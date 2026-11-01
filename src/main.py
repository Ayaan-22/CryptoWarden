"""CryptoWarden 3.1: managed collection, durable incidents and explicit response policy."""

import argparse
import asyncio
import json
import logging
import os
import signal
import sys
import time
from collections import OrderedDict, deque
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from logging.handlers import RotatingFileHandler
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src import __version__
from src.analysis.entropy import sample_file_entropy
from src.analysis.process_tracker import ProcessTracker
from src.config import ConfigError, Settings, normalize_path
from src.control import CONTROL_COMMANDS, MonitoringControl
from src.detection.engine import DetectionEngine
from src.models import ActionResult, Incident, ProcessIdentity
from src.monitoring.honey_pot import safe_root
from src.monitoring.process_monitor import ProcessMonitor
from src.response.responder import Responder
from src.storage import IncidentStore
from src.utils.dashboard_bridge import DashboardBridge
from src.utils.process_tools import executable_digest, inspect_process
from src.utils.runtime import InstanceLock, secure_directory

log = logging.getLogger("cryptowarden")


class CryptoWarden:
    def __init__(self, settings=None, demo=False, reset_policy=False):
        self.settings = deepcopy(
            settings.data if isinstance(settings, Settings) else settings or Settings.load().data
        )
        cfg = self.settings
        self.demo = demo
        self.reset_policy = reset_policy
        self.tracker = ProcessTracker(window=cfg["detection"]["window_seconds"])
        self.behavior = ProcessTracker(window=cfg["detection"]["window_seconds"])
        self.detector = DetectionEngine(cfg["detection"])
        self.responder = Responder(cfg["response"])
        self.process_monitor = ProcessMonitor(self.tracker, cfg["monitoring"]["poll_interval"])
        token = os.environ.get("CRYPTOWARDEN_DASHBOARD_TOKEN", cfg["dashboard"]["auth_token"])
        if token and (len(token) < 32 or not token.isascii()):
            raise ConfigError("CRYPTOWARDEN_DASHBOARD_TOKEN must be at least 32 characters")
        self.bridge = DashboardBridge(
            cfg["dashboard"]["host"],
            cfg["dashboard"]["port"],
            token,
            cfg["dashboard"]["session_seconds"],
            self.snapshot,
            self.execute_command,
        )
        self.bridge.export_provider = self.export_incidents
        self.queue = asyncio.PriorityQueue(maxsize=cfg["monitoring"]["queue_capacity"])
        self.file_monitor = self.canaries = self.store = self.lock = None
        self.running = False
        self.shutting_down = False
        self.health = "stopped"
        self.started_at = None
        self.tasks = []
        self.stop_requested = asyncio.Event()
        self.command_lock = asyncio.Lock()
        self.event_lock = asyncio.Lock()
        self.stats = {
            "scanned": 0,
            "detections": 0,
            "blocked": 0,
            "failed_actions": 0,
            "dropped": 0,
            "analysis_errors": 0,
            "coalesced": 0,
            "analysis_skipped": 0,
            "discarded": 0,
        }
        self.activity = deque(maxlen=200)
        self.series = deque(maxlen=60)
        self.suppressed = OrderedDict()
        self.command_results = OrderedDict()
        self.baselines = OrderedDict()
        self.recent_paths = {}
        self.entropy_pool = ThreadPoolExecutor(max_workers=2, thread_name_prefix="entropy")
        self.entropy_pending = set()
        self.queue_age_ms = 0
        self.canary_status = []
        self.issues = []
        self.rules = []
        self._sequence = 0
        self.controls = MonitoringControl(self)

    def event_offer(self, event):
        self._sequence += 1
        self.queue.put_nowait((0 if event.get("is_canary") else 1, self._sequence, event))

    def record_loss(self, count):
        self.stats["dropped"] += count
        if "Event overflow: coverage incomplete" not in self.issues:
            self.issues.append("Event overflow: coverage incomplete")

    def record_discard(self, count):
        self.stats["discarded"] += count

    async def initialize(self):
        runtime = self.settings["storage"]["directory"]
        await asyncio.to_thread(secure_directory, runtime)
        self.lock = InstanceLock(runtime)
        self.lock.acquire()
        storage = self.settings["storage"]
        self.store = await asyncio.to_thread(
            IncidentStore, runtime, storage["retention_days"], storage["max_incidents"]
        )
        await asyncio.to_thread(self.store.claim_workspace, "demo" if self.demo else "live")
        await self.controls.load(self.reset_policy)
        self.rules = await asyncio.to_thread(self.store.rules)
        handler = RotatingFileHandler(
            Path(runtime) / "engine.log", maxBytes=5 * 1024 * 1024, backupCount=3, encoding="utf-8"
        )
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
        log.setLevel(logging.INFO)
        log.addHandler(handler)
        self.log_handler = handler
        if self.demo:
            await self.seed_demo()

    async def _entropy(self, path):
        # Timeout cannot cancel an OS read. Keep timed-out futures in a bounded set
        # so repeated locked/unresponsive paths cannot build an unbounded executor queue.
        self.entropy_pending = {future for future in self.entropy_pending if not future.done()}
        if len(self.entropy_pending) >= 2:
            self.stats["analysis_skipped"] += 1
            return None, "capacity", None
        cfg = self.settings["detection"]
        future = asyncio.get_running_loop().run_in_executor(
            self.entropy_pool,
            sample_file_entropy,
            path,
            cfg["entropy_check_samples"],
            cfg["min_file_size_for_entropy"],
        )
        self.entropy_pending.add(future)
        try:
            sample = await asyncio.wait_for(asyncio.shield(future), timeout=cfg["entropy_timeout"])
            previous = self.baselines.get(path)
            if sample.value is not None:
                self.baselines[path] = sample.value
                self.baselines.move_to_end(path)
                if len(self.baselines) > 4096:
                    self.baselines.popitem(last=False)
            return (
                sample.value,
                sample.status,
                sample.value - previous
                if sample.value is not None and previous is not None
                else None,
            )
        except asyncio.TimeoutError:
            self.stats["analysis_errors"] += 1
            return None, "timeout", None

    async def process_event(self, event):
        async with self.event_lock:
            if "_collector_generation" in event and (
                event["_collector_generation"] != self.controls.generation
                or self.controls.status != "running"
            ):
                self.stats["discarded"] += 1
                return
            return await self._process_event(event)

    async def _process_event(self, event):
        self.stats["scanned"] += 1
        self.queue_age_ms = max(
            0, (time.monotonic() - event.get("received_monotonic", time.monotonic())) * 1000
        )
        path = event.get("dest_path") or event["src_path"]
        is_canary = event.get("is_canary", False)
        if self.canaries:
            is_canary = (
                is_canary
                or normalize_path(event["src_path"]) in self.canaries.paths
                or normalize_path(path) in self.canaries.paths
            )
        # Watchdog has no actor identity. External event dictionaries cannot assert verified provenance.
        event = {
            **event,
            "process": None,
            "pid": None,
            "process_name": None,
            "attribution_confidence": "unknown",
        }
        group = normalize_path(Path(path).parent)
        state = self.behavior.update_access(
            f"unattributed:{group}", "Unresolved actor", event["type"], path=path
        )
        entropy, status, delta = None, "not_applicable", None
        if (
            event["type"] in {"created", "modified", "moved"}
            and not event.get("is_directory")
            and not is_canary
        ):
            entropy, status, delta = await self._entropy(path)
        result = self.detector.evaluate(state, entropy, is_canary, path, delta)
        public = {**event, "entropy": entropy, "analysis_status": status}
        self.activity.appendleft(public)
        self.bridge.publish("activity", public)
        if result.detected:
            key = (
                normalize_path(path) if is_canary else group,
                "canary" if is_canary else result.reason,
            )
            now = time.monotonic()
            previous = self.suppressed.get(key)
            if previous is None or now - previous >= self.settings["response"]["cooldown_seconds"]:
                self.suppressed[key] = now
                self.suppressed.move_to_end(key)
                while len(self.suppressed) > 2048:
                    self.suppressed.popitem(last=False)
                action = ActionResult(
                    "alert_only",
                    "Actor unresolved: filesystem notifications cannot authorize termination",
                )
                incident = Incident(
                    result.reason,
                    result.severity,
                    path,
                    list(result.signals),
                    action=action.to_dict(),
                    evidence={
                        "source": "watchdog",
                        "score": result.score,
                        "event_type": event["type"],
                        "unique_modifications": state.unique_modifications(),
                        "unique_renames": state.unique_renames(),
                        "entropy": entropy,
                        "entropy_status": status,
                        "queue_age_ms": round(self.queue_age_ms, 2),
                    },
                )
                # Persist before publication. UI failures have no authority over response decisions.
                await asyncio.to_thread(self.store.save, incident)
                self.stats["detections"] += 1
                self.bridge.publish("incident", incident.to_dict())
                log.warning("Incident %s: %s; actor unresolved", incident.id, incident.reason)
        if event.get("is_directory") and event["type"] in {"moved", "deleted"}:
            if "Directory change: inspect protected scope" not in self.issues:
                self.issues.append("Directory change: inspect protected scope")

    async def process_events(self):
        while self.running:
            _, _, event = await self.queue.get()
            try:
                now = time.monotonic()
                key = (event["type"], event["src_path"], event.get("dest_path"))
                last = self.recent_paths.get(key, 0)
                if not event.get("is_canary") and now - last < 0.1:
                    self.stats["coalesced"] += 1
                    continue
                self.recent_paths[key] = now
                if len(self.recent_paths) > 4096:
                    self.recent_paths = {
                        key: value for key, value in self.recent_paths.items() if now - value < 2
                    }
                    while len(self.recent_paths) > 4096:
                        self.recent_paths.pop(next(iter(self.recent_paths)))
                await self.process_event(event)
            except Exception:
                self.stats["analysis_errors"] += 1
                if "Event analysis failed" not in self.issues:
                    self.issues.append("Event analysis failed")
                log.exception("Event analysis failed")
            finally:
                self.queue.task_done()

    async def snapshot(self):
        if not self.store:
            return {"health": "starting", "incidents": [], "stats": dict(self.stats)}
        incidents, counts, audit = await asyncio.gather(
            asyncio.to_thread(self.store.list),
            asyncio.to_thread(self.store.counts),
            asyncio.to_thread(self.store.audit_events),
        )
        degraded = bool(self.issues) or any(
            row["status"] != "healthy" for row in self.canary_status
        )
        phase = "degraded" if self.health == "running" and degraded else self.health
        if self.health == "running":
            if self.controls.status == "paused":
                phase = "paused"
            elif self.controls.status in {"starting", "stopping"}:
                phase = "updating"
            elif self.controls.status == "faulted":
                phase = "degraded"
            elif self.demo:
                phase = "demo"
        return {
            "version": __version__,
            "demo": self.demo,
            "health": phase,
            "issues": list(self.issues),
            "mode": self.settings["response"]["mode"],
            "automatic_termination": False,
            "attribution": "filesystem notifications; writer identity unavailable",
            "started_at": self.started_at,
            "timestamp": time.time(),
            "stats": {**self.stats, **counts},
            "incidents": incidents,
            "activity": list(self.activity),
            "rules": self.rules,
            "directories": list(self.settings["monitoring"]["directories"]),
            "canaries": self.canary_status,
            "processes": self.process_monitor.instances,
            "series": list(self.series),
            "runtime": {
                "queue_depth": self.queue.qsize(),
                "queue_capacity": self.queue.maxsize,
                "queue_age_ms": round(self.queue_age_ms, 2),
                "clients": len(self.bridge.active_connections),
                "ui_dropped": self.bridge.dropped,
                "file_monitor": self.file_monitor.health
                if self.file_monitor
                else "demo"
                if self.demo
                else "stopped",
                "process_monitor": self.process_monitor.health,
                "last_process_sample": self.process_monitor.last_sample,
            },
            "management": self.controls.snapshot(),
            "audit": audit,
        }

    async def export_incidents(self):
        return await asyncio.to_thread(self.store.export) if self.store else []

    async def execute_command(self, command):
        if self.shutting_down:
            return {
                "status": "refused",
                "reason": "Engine is shutting down; no new commands are accepted",
            }
        async with self.command_lock:
            if self.shutting_down:
                return {
                    "status": "refused",
                    "reason": "Engine is shutting down; no new commands are accepted",
                }
            request_id = command["request_id"]
            reservation, previous = await asyncio.to_thread(self.store.reserve_command, command)
            if reservation != "new":
                return previous
            action = command["command"]
            result = {"status": "refused", "reason": "No matching record"}
            incident = await asyncio.to_thread(self.store.get, command.get("incident_id"))
            await asyncio.to_thread(
                self.store.audit,
                {
                    "request_id": request_id,
                    "command": action,
                    "status": "pending",
                    "incident_id": command.get("incident_id"),
                    "process": incident.get("process") if incident else None,
                },
            )
            if action in CONTROL_COMMANDS:
                result = await self.controls.execute(command)
            elif action == "resolve" and incident:
                incident["status"] = "resolved"
                await asyncio.to_thread(self.store.save, incident)
                self.bridge.publish("incident", incident)
                result = {
                    "status": "resolved",
                    "reason": "Incident acknowledged; this does not assert remediation",
                }
            elif action == "remove_rule":
                removed = await asyncio.to_thread(self.store.remove_rule, command["rule_id"])
                result = {
                    "status": "removed" if removed else "refused",
                    "reason": "Rule removed" if removed else "Rule not found",
                }
            elif action == "select_actor" and incident:
                if self.demo:
                    result = {
                        "status": "refused",
                        "reason": "Demonstration records cannot select live processes",
                    }
                else:
                    candidate = next(
                        (
                            row
                            for row in self.process_monitor.instances
                            if ProcessIdentity(
                                row["pid"], row["create_time"], row["name"], row["executable"]
                            ).key
                            == command["process_key"]
                        ),
                        None,
                    )
                    current = (
                        await asyncio.to_thread(inspect_process, candidate["pid"])
                        if candidate
                        else None
                    )
                    if (
                        not current
                        or current.key != command["process_key"]
                        or not current.executable
                        or current.executable != candidate["executable"]
                        or current.name != candidate["name"]
                    ):
                        result = {
                            "status": "refused",
                            "reason": "Selected process instance is no longer available",
                        }
                    else:
                        incident["process"] = current.to_dict()
                        incident["attribution"] = "operator_selected"
                        incident["evidence"]["actor_note"] = (
                            "Explicit operator selection; not proof of a file write"
                        )
                        await asyncio.to_thread(self.store.save, incident)
                        self.bridge.publish("incident", incident)
                        result = {
                            "status": "selected",
                            "reason": "Process selected for review; writer causality remains unverified",
                        }
            elif action in {"terminate", "allow"} and incident:
                captured = incident.get("process")
                if not captured:
                    result = {
                        "status": "refused",
                        "reason": "Actor unresolved; no process can be safely selected",
                    }
                elif self.demo:
                    result = {
                        "status": "refused",
                        "reason": "Demonstration records cannot authorize live actions",
                    }
                else:
                    identity = ProcessIdentity(**captured)
                    current = await asyncio.to_thread(inspect_process, identity.pid)
                    if not current or current != identity:
                        result = {
                            "status": "refused",
                            "reason": "Process instance changed or unavailable",
                        }
                    elif action == "allow":
                        digest = await asyncio.to_thread(executable_digest, identity.executable)
                        await asyncio.to_thread(
                            self.store.add_rule, identity.executable, digest, command["reason"]
                        )
                        result = {
                            "status": "allowed",
                            "reason": "Executable fingerprint saved; canary detections remain visible",
                        }
                    else:
                        outcome = await asyncio.to_thread(
                            self.responder.take_action, identity, incident["reason"], True
                        )
                        result = outcome.to_dict()
                        incident["action"] = result
                        await asyncio.to_thread(self.store.save, incident)
                        self.stats["blocked"] += sum(
                            row["status"] == "terminated" for row in outcome.targets
                        )
                        if outcome.status in {"failed", "partial"}:
                            self.stats["failed_actions"] += 1
                        self.bridge.publish("incident", incident)
            self.rules = await asyncio.to_thread(self.store.rules)
            await asyncio.to_thread(
                self.store.audit,
                {
                    "request_id": request_id,
                    "command": action,
                    "incident_id": command.get("incident_id"),
                    "result": result,
                },
            )
            await asyncio.to_thread(self.store.finish_command, request_id, result)
            self.command_results[request_id] = result
            while len(self.command_results) > 512:
                self.command_results.popitem(last=False)
            self.bridge.publish("command_result", {"request_id": request_id, **result})
            return result

    async def maintenance(self):
        previous, stamp = self.stats["scanned"], time.monotonic()
        ticks = 0
        while self.running:
            await asyncio.sleep(1)
            now = time.monotonic()
            self.series.append(
                {
                    "timestamp": time.time(),
                    "rate": round((self.stats["scanned"] - previous) / max(0.001, now - stamp), 2),
                }
            )
            previous, stamp = self.stats["scanned"], now
            self.behavior.expire()
            await self.controls.tick()
            ticks += 1
            if self.canaries and ticks % 10 == 0 and self.controls.status == "running":
                generation = self.controls.generation
                manager = self.canaries
                checks = await asyncio.to_thread(manager.health)
                if generation == self.controls.generation and self.controls.status == "running":
                    self.canary_status = checks
                    self.controls.last_canary_check = time.time()
                    for row in checks:
                        if row["status"] != "healthy":
                            await self.process_event(
                                {
                                    "type": "integrity",
                                    "src_path": row["path"],
                                    "is_canary": True,
                                    "received_monotonic": time.monotonic(),
                                    "_collector_generation": generation,
                                }
                            )
            if ticks % 60 == 0:
                await asyncio.to_thread(self.store.prune)
            self.bridge.publish("snapshot", await self.snapshot())

    async def start(self):
        self.health = "starting"
        try:
            await self.initialize()
            self.started_at = time.time()
            self.running = True
            await self.controls.start_initial()
            await self.bridge.start()
            self.health = "running"
            self.tasks = [
                asyncio.create_task(self.process_events(), name="file-events"),
                asyncio.create_task(self.maintenance(), name="maintenance"),
            ]
            loop = asyncio.get_running_loop()
            for sig in (signal.SIGINT, signal.SIGTERM):
                try:
                    loop.add_signal_handler(sig, self.stop_requested.set)
                except (NotImplementedError, RuntimeError):
                    pass
            print(
                f"CryptoWarden {__version__} {'DEMO' if self.demo else 'endpoint console'}: http://{self.bridge.host}:{self.bridge.port}/",
                flush=True,
            )
            print(
                f"Console access key: {self.bridge.auth_token}", flush=True
            )  # Console only, never logged or placed in URLs.
            while not self.stop_requested.is_set():
                supervised = [*self.tasks, self.bridge.server_task]
                if self.process_monitor.task and self.controls.status == "running":
                    supervised.append(self.process_monitor.task)
                for task in supervised:
                    if task.done():
                        failure = task.exception() if not task.cancelled() else None
                        raise RuntimeError(
                            f"Required service stopped: {task.get_name()}"
                        ) from failure
                if (
                    self.file_monitor
                    and self.controls.status == "running"
                    and not self.file_monitor.observer.is_alive()
                ):
                    raise RuntimeError("Filesystem observer stopped")
                await asyncio.sleep(0.2)
        except BaseException:
            self.health = "failed"
            raise
        finally:
            await self.stop()

    async def stop(self):
        failed = self.health == "failed"
        self.shutting_down = True
        self.running = False
        async with self.command_lock:
            async with self.event_lock:
                if self.file_monitor:
                    await asyncio.to_thread(self.file_monitor.stop)
                await self.process_monitor.stop()
                self.controls.status = "stopped"
        for task in self.tasks:
            task.cancel()
        await asyncio.gather(*self.tasks, return_exceptions=True)
        await self.bridge.stop()
        self.entropy_pool.shutdown(wait=False, cancel_futures=True)
        if self.lock:
            self.lock.release()
        if hasattr(self, "log_handler"):
            log.removeHandler(self.log_handler)
            self.log_handler.close()
        self.health = "failed" if failed else "stopped"

    async def seed_demo(self):
        if await asyncio.to_thread(self.store.list, 1):
            return
        examples = [
            ("Canary integrity event", "critical", "Quarterly forecast.txt", "open", "alert_only"),
            (
                "Renaming across 12 files · Suspicious extension",
                "high",
                "Client agreements.enc",
                "open",
                "alert_only",
            ),
            (
                "Rapid modification across 64 files · High entropy sequence",
                "high",
                "Finance archive",
                "resolved",
                "alert_only",
            ),
        ]
        for index, (reason, severity, path, status, action) in enumerate(examples):
            item = Incident(
                reason,
                severity,
                f"Demonstration workspace / {path}",
                reason.split(" · "),
                status=status,
                action=ActionResult(
                    action, "Demonstration evidence — no real process action"
                ).to_dict(),
                timestamp=time.time() - index * 960,
                evidence={"source": "demo", "score": 100 - index * 15},
            )
            await asyncio.to_thread(self.store.save, item)


def main():
    parser = argparse.ArgumentParser(description="CryptoWarden endpoint console")
    parser.add_argument("command", choices=["start", "check", "demo"], nargs="?", default="check")
    parser.add_argument("--config")
    parser.add_argument(
        "--reset-policy",
        action="store_true",
        help="Reset saved console policy to this startup configuration",
    )
    args = parser.parse_args()
    try:
        settings = Settings.load(args.config)
        if args.command == "demo" and not args.config:
            settings.data["storage"]["directory"] = str(
                Path(settings.data["storage"]["directory"]).with_name(".cryptowarden-demo")
            )
        if args.command == "check":
            print(
                json.dumps(
                    {
                        "configuration": "valid",
                        "scope": "startup configuration; saved console policy overrides managed settings unless --reset-policy is used",
                        "mode": settings.data["response"]["mode"],
                        "automatic_termination": False,
                        "directories": [
                            {"path": path, "available": safe_root(path)}
                            for path in settings.data["monitoring"]["directories"]
                        ],
                    },
                    indent=2,
                )
            )
            return
        asyncio.run(
            CryptoWarden(
                settings, demo=args.command == "demo", reset_policy=args.reset_policy
            ).start()
        )
    except KeyboardInterrupt:
        pass
    except (ValueError, RuntimeError, OSError) as error:
        parser.exit(1, f"CryptoWarden: {error}\n")


if __name__ == "__main__":
    main()
