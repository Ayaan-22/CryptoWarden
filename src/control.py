"""Persistent operator controls with revision checks and recoverable collector transitions."""

import asyncio
import hmac
import time
from copy import deepcopy
from uuid import uuid4

from src.analysis.process_tracker import ProcessTracker
from src.config import validate_config
from src.detection.engine import DetectionEngine
from src.management import preview_policy, public_policy
from src.monitoring.file_monitor import FileMonitor
from src.monitoring.honey_pot import CanaryManager
from src.monitoring.process_monitor import ProcessMonitor
from src.response.responder import Responder

CONTROL_COMMANDS = {
    "policy_preview",
    "policy_apply",
    "monitoring_pause",
    "monitoring_resume",
    "monitoring_restart",
}


class MonitoringControl:
    def __init__(self, app):
        self.app = app
        self.state = None
        self.status = "stopped"
        self.generation = 0
        self.interrupted = False
        self.last_error = None
        self.retry_at = 0
        self.last_canary_check = None
        self.pause_deadline = None

    async def load(self, reset=False):
        self.state, self.interrupted = await asyncio.to_thread(
            self.app.store.management_load, public_policy(self.app.settings), reset
        )
        candidate = deepcopy(self.app.settings)
        for section, values in self.state["policy"].items():
            candidate[section].update(values)
        self.install_settings(validate_config(candidate))
        if self.state.get("pause_until"):
            self.pause_deadline = time.monotonic() + max(0, self.state["pause_until"] - time.time())
        if self.interrupted:
            self.status = "paused"
            self.last_error = "An interrupted management operation was found. Review policy and resume explicitly."
        elif self.state["desired"] == "paused":
            self.status = "paused"

    def install_settings(self, candidate):
        app = self.app
        app.settings = deepcopy(candidate)
        app.detector = DetectionEngine(app.settings["detection"])
        app.responder = Responder(app.settings["response"])
        app.behavior = ProcessTracker(window=app.settings["detection"]["window_seconds"])
        app.tracker = ProcessTracker(window=app.settings["detection"]["window_seconds"])
        app.process_monitor = ProcessMonitor(
            app.tracker, app.settings["monitoring"]["poll_interval"]
        )
        app.baselines.clear()
        app.recent_paths.clear()
        app.suppressed.clear()

    def snapshot(self):
        return {
            "revision": self.state["revision"] if self.state else 0,
            "policy": public_policy(self.app.settings),
            "monitoring_status": self.status,
            "desired": self.state["desired"] if self.state else "running",
            "pause_until": self.state.get("pause_until") if self.state else None,
            "updated_at": self.state.get("updated_at") if self.state else None,
            "reason": self.state.get("reason") if self.state else None,
            "interrupted": self.interrupted,
            "last_error": self.last_error,
            "last_canary_check": self.last_canary_check,
            "automatic_termination_available": False,
            "commands_available": not self.app.shutting_down,
        }

    async def start_collectors(self):
        app = self.app
        self.status = "starting"
        self.generation += 1
        generation = self.generation
        if app.demo:
            self.status = "running"
            return
        manager = CanaryManager(
            app.settings["monitoring"]["directories"], app.settings["storage"]["directory"]
        )
        await asyncio.to_thread(manager.setup)
        app.canaries = manager
        app.canary_status = await asyncio.to_thread(manager.health)
        self.last_canary_check = time.time()

        class Intake:
            def put_nowait(_, event):
                app.event_offer({**event, "_collector_generation": generation})

        loop = asyncio.get_running_loop()
        app.file_monitor = FileMonitor(
            Intake(),
            loop,
            app.settings,
            manager.paths,
            lambda count: loop.call_soon_threadsafe(app.record_loss, count),
            on_discard=lambda count: loop.call_soon_threadsafe(app.record_discard, count),
        )
        try:
            await asyncio.to_thread(app.file_monitor.start)
            await app.process_monitor.start()
            deadline = time.monotonic() + 10
            while app.process_monitor.health != "running":
                if app.process_monitor.task.done():
                    await app.process_monitor.task
                    raise RuntimeError("Process collector stopped during readiness")
                if time.monotonic() > deadline:
                    raise RuntimeError("Process collector readiness timed out")
                await asyncio.sleep(0.02)
        except BaseException:
            await self.stop_collectors()
            raise
        self.status = "running"

    async def stop_collectors(self):
        self.status = "stopping"
        self.generation += 1
        app = self.app
        if app.file_monitor:
            await asyncio.wait_for(asyncio.to_thread(app.file_monitor.stop), timeout=10)
            if app.file_monitor.health != "stopped":
                self.status = "faulted"
                raise RuntimeError("The file collector did not stop cleanly")
        await app.process_monitor.stop()
        app.process_monitor.instances = []
        app.file_monitor = None
        while not app.queue.empty():
            app.queue.get_nowait()
            app.queue.task_done()
            app.stats["discarded"] += 1
        self.status = "paused"

    async def start_initial(self):
        if self.interrupted or self.state["desired"] == "paused":
            self.status = "paused"
            return
        try:
            await self.start_collectors()
        except (OSError, ValueError, RuntimeError) as error:
            self.status = "faulted"
            self.last_error = f"Monitoring could not start: {error}"

    async def execute(self, command):
        if not self.state:
            await self.load()
        revision = self.state["revision"]
        if command["expected_revision"] != revision:
            return {
                "status": "conflict",
                "reason": "Policy changed in another session. Refresh and review again.",
                "revision": revision,
            }
        operation = command["command"]
        reason = command["reason"].strip()
        candidate = self.app.settings
        preview = None
        if operation.startswith("policy_"):
            try:
                candidate, preview = await asyncio.to_thread(
                    preview_policy, self.app.settings, command["patch"], revision, reason
                )
            except (ValueError, OSError) as error:
                return {"status": "refused", "reason": str(error), "revision": revision}
            if operation == "policy_preview":
                return {
                    "status": "preview",
                    "reason": "Review these changes before applying.",
                    **preview,
                }
            digest = command.get("preview_id", "")
            if (
                not isinstance(digest, str)
                or not digest.isascii()
                or not hmac.compare_digest(digest, preview["preview_id"])
            ):
                return {
                    "status": "refused",
                    "reason": "Policy review is stale or does not match this change. Preview again.",
                }
            if (
                preview["requires_termination_confirmation"]
                and command.get("confirmation") != "ENABLE MANUAL TERMINATION"
            ):
                return {
                    "status": "refused",
                    "reason": "Explicit confirmation is required to enable manual termination mode.",
                }
        if (
            operation in {"policy_apply", "monitoring_pause", "monitoring_restart"}
            and command.get("acknowledge_gap") is not True
        ):
            return {
                "status": "refused",
                "reason": "Acknowledge the coverage gap before changing active collection.",
            }

        old_state = deepcopy(self.state)
        old_settings = deepcopy(self.app.settings)
        was_running = self.status == "running"
        started = time.time()
        desired = old_state["desired"]
        pause_until = old_state.get("pause_until")
        if operation == "monitoring_pause":
            desired = "paused"
            duration = command["duration_seconds"]
            pause_until = time.time() + duration if duration else None
        elif operation in {"monitoring_resume", "monitoring_restart"}:
            desired = "running"
            pause_until = None
        if self.interrupted and operation == "policy_apply":
            desired = "paused"  # Editing policy must not silently resume an interrupted transition.
        await asyncio.to_thread(
            self.app.store.management_transition,
            revision,
            {
                "request_id": command["request_id"],
                "command": operation,
                "reason": reason,
                "started_at": started,
            },
        )
        try:
            async with self.app.event_lock:
                await self.stop_collectors()
                self.install_settings(candidate)
                if desired == "running":
                    await self.start_collectors()
                self.state = await asyncio.to_thread(
                    self.app.store.management_commit,
                    revision,
                    {
                        **old_state,
                        "policy": public_policy(candidate),
                        "desired": desired,
                        "pause_until": pause_until,
                        "paused_since": (
                            old_state.get("paused_since") or old_state.get("updated_at")
                        )
                        if desired == "paused" and old_state["desired"] == "paused"
                        else started
                        if desired == "paused"
                        else None,
                        "reason": reason,
                    },
                )
                self.interrupted = False
                self.last_error = None
                if operation == "monitoring_pause":
                    self.pause_deadline = (
                        time.monotonic() + command["duration_seconds"] if pause_until else None
                    )
                elif desired == "running":
                    self.pause_deadline = None
        except Exception as error:
            restored = False
            try:
                async with self.app.event_lock:
                    await self.stop_collectors()
                    self.install_settings(old_settings)
                    if was_running:
                        await self.start_collectors()
                    if not self.interrupted:
                        await asyncio.to_thread(self.app.store.management_rollback)
                    restored = True
            except Exception:
                self.status = "faulted"
                self.interrupted = True
            self.last_error = f"Change failed: {error}. " + (
                "Previous policy restored." if restored else "Monitoring needs operator recovery."
            )
            result = {
                "status": "failed",
                "reason": self.last_error,
                "revision": self.state["revision"],
                "monitoring_status": self.status,
            }
        else:
            result = {
                "status": "applied",
                "reason": (
                    "Demo policy updated; no live collectors or actions were enabled."
                    if self.app.demo
                    else "Policy saved and collectors restarted."
                    if operation == "policy_apply" and desired == "running"
                    else "Monitoring paused; the console remains available."
                    if desired == "paused"
                    else "Monitoring is running."
                ),
                "revision": self.state["revision"],
                "monitoring_status": self.status,
            }
        await asyncio.to_thread(
            self.app.store.audit,
            {
                "command": "coverage_gap",
                "request_id": command["request_id"],
                "started_at": started,
                "ended_at": time.time(),
                "duration_seconds": round(time.time() - started, 3),
                "reason": reason,
                "result": result,
                "changes": preview["changes"] if preview else [],
                "pause_started_at": old_state.get("paused_since")
                if old_state["desired"] == "paused"
                else None,
                "resumed_after_pause_seconds": round(
                    max(
                        0, time.time() - (old_state.get("paused_since") or old_state["updated_at"])
                    ),
                    3,
                )
                if old_state["desired"] == "paused" and self.status == "running"
                else None,
            },
        )
        self.app.bridge.publish("snapshot", await self.app.snapshot())
        return result

    async def tick(self):
        if self.state and self.status == "paused" and not self.interrupted:
            deadline = self.state.get("pause_until")
            if (
                deadline
                and self.pause_deadline is not None
                and time.monotonic() >= self.pause_deadline
                and time.monotonic() >= self.retry_at
            ):
                self.retry_at = time.monotonic() + 30
                await self.app.execute_command(
                    {
                        "request_id": str(uuid4()),
                        "command": "monitoring_resume",
                        "expected_revision": self.state["revision"],
                        "reason": "Automatic resume after the operator's timed pause",
                    }
                )
