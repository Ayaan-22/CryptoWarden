import asyncio
import time
from pathlib import Path
from unittest.mock import AsyncMock, Mock
from uuid import uuid4

import pytest

from src.analysis.process_tracker import ProcessTracker
from src.main import CryptoWarden
from src.models import Incident
from src.monitoring.process_monitor import ProcessMonitor
from src.storage import IncidentStore
from src.utils.runtime import InstanceLock


def app_with_store(cfg):
    app = CryptoWarden(cfg)
    app.store = IncidentStore(cfg["storage"]["directory"])
    return app


def event(path, kind="modified", **kwargs):
    return {
        "type": kind,
        "src_path": str(path),
        "received_monotonic": time.monotonic(),
        "timestamp": time.time(),
        **kwargs,
    }


def test_unattributed_event_cannot_select_high_io_actor(cfg, tmp_path):
    async def check():
        app = app_with_store(cfg)
        app.tracker.get_or_create(12345, "benign.exe", 100).update_io_stats(999)
        app.responder.take_action = Mock()
        app._entropy = AsyncMock(return_value=(7.9, "sampled", None))
        await app.process_event(
            event(
                tmp_path / "canary.txt",
                is_canary=True,
                pid=12345,
                process={"pid": 12345},
                attribution_confidence="verified",
            )
        )
        assert app.stats["detections"] == 1 and app.stats["blocked"] == 0
        assert app.store.list()[0]["process"] is None
        app.responder.take_action.assert_not_called()
        await app.stop()

    asyncio.run(check())


def test_ui_publish_failure_does_not_erase_persisted_incident(cfg, tmp_path):
    async def check():
        app = app_with_store(cfg)

        def publish(kind, data):
            if kind == "incident":
                raise RuntimeError("injected transport failure")

        app.bridge.publish = publish
        with pytest.raises(RuntimeError):
            await app.process_event(event(tmp_path / "canary", is_canary=True))
        assert len(app.store.list()) == 1 and app.stats["blocked"] == 0
        await app.stop()

    asyncio.run(check())


def test_independent_unknown_incidents_are_not_permanently_suppressed(cfg, tmp_path):
    async def check():
        app = app_with_store(cfg)
        await app.process_event(event(tmp_path / "one" / "canary", is_canary=True))
        await app.process_event(event(tmp_path / "two" / "canary", is_canary=True))
        assert len(app.store.list()) == 2
        await app.stop()

    asyncio.run(check())


def test_resolve_acknowledges_without_claiming_remediation_and_is_idempotent(cfg):
    async def check():
        app = app_with_store(cfg)
        item = Incident("reason", "high", "path", ["reason"])
        app.store.save(item)
        cmd = {"request_id": str(uuid4()), "command": "resolve", "incident_id": item.id}
        result = await app.execute_command(cmd)
        assert result["status"] == "resolved" and "does not assert remediation" in result["reason"]
        assert await app.execute_command(cmd) == result
        assert app.store.get(item.id)["status"] == "resolved"
        assert app.stats["blocked"] == 0
        await app.stop()

    asyncio.run(check())


def test_unknown_process_manual_command_is_refused(cfg):
    async def check():
        app = app_with_store(cfg)
        item = Incident("reason", "high", "path", ["reason"])
        app.store.save(item)
        result = await app.execute_command(
            {"request_id": str(uuid4()), "command": "terminate", "incident_id": item.id}
        )
        assert result["status"] == "refused" and app.stats["blocked"] == 0
        await app.stop()

    asyncio.run(check())


def test_queue_task_done_even_on_analysis_error(cfg):
    async def check():
        app = app_with_store(cfg)
        app.running = True

        async def fail(event):
            app.running = False
            raise ValueError("malformed event")

        app.process_event = fail
        app.event_offer(event("path"))
        await app.process_events()
        await asyncio.wait_for(app.queue.join(), timeout=1)
        assert app.stats["analysis_errors"] == 1
        await app.stop()

    asyncio.run(check())


def test_priority_queue_puts_canary_first(cfg):
    app = app_with_store(cfg)
    app.event_offer(event("normal"))
    app.event_offer(event("canary", is_canary=True))
    assert app.queue.get_nowait()[2]["is_canary"]
    app.entropy_pool.shutdown()


def test_retention_and_rules_are_persistent(cfg):
    storage = IncidentStore(cfg["storage"]["directory"], max_incidents=2)
    old = Incident("old", "high", "old", ["old"], timestamp=time.time() - 31 * 86400)
    storage.save(old)
    for index in range(4):
        storage.save(Incident(str(index), "high", "p", []))
    storage.prune()
    assert len(storage.list()) == 2 and storage.get(old.id) is None
    rule = storage.add_rule("C:/app.exe", "a" * 64, "reviewed")
    assert IncidentStore(cfg["storage"]["directory"]).rules()[0]["sha256"] == "a" * 64
    assert storage.remove_rule(rule["id"])


def test_single_instance_lock_is_os_held(cfg):
    Path(cfg["storage"]["directory"]).mkdir(parents=True)
    first = InstanceLock(cfg["storage"]["directory"])
    second = InstanceLock(cfg["storage"]["directory"])
    first.acquire()
    try:
        with pytest.raises(RuntimeError):
            second.acquire()
    finally:
        first.release()
    second.acquire()
    second.release()


def test_process_monitor_resets_io_and_replaces_pid_instance(monkeypatch):
    from types import SimpleNamespace

    import src.monitoring.process_monitor as module

    clock = [100.0]
    info = {
        "pid": 12345,
        "name": "app.exe",
        "create_time": 10,
        "exe": "C:/app.exe",
        "io_counters": SimpleNamespace(write_count=0, write_bytes=0),
    }
    monkeypatch.setattr(
        module.psutil, "process_iter", lambda attrs: [SimpleNamespace(info=info.copy())]
    )
    monkeypatch.setattr(module.time, "monotonic", lambda: clock[0])
    monitor = ProcessMonitor(ProcessTracker())
    monitor.sample()
    clock[0] += 1
    info["io_counters"] = SimpleNamespace(write_count=100, write_bytes=4096)
    rows, _, _ = monitor.sample()
    assert rows[0][1] == (100, 4096)
    clock[0] += 1
    assert monitor.sample()[0][0][1] == (0, 0)
    info["create_time"] = 20
    clock[0] += 1
    assert monitor.sample()[0][0][1] == (0, 0)


def test_initialization_failure_releases_lock_and_services(cfg, monkeypatch):
    async def check():
        import src.main as module

        def denied(directory):
            raise OSError("Injected runtime access failure")

        monkeypatch.setattr(module, "secure_directory", denied)
        app = CryptoWarden(cfg)
        with pytest.raises(OSError, match="runtime access"):
            await app.start()
        assert app.health == "failed" and app.lock is None
        assert app.bridge.server_task is None

    asyncio.run(check())


def test_snapshot_reports_degraded_coverage(cfg):
    async def check():
        app = app_with_store(cfg)
        app.health = "running"
        app.record_loss(12)
        snapshot = await app.snapshot()
        assert snapshot["health"] == "degraded" and snapshot["stats"]["dropped"] == 12
        assert snapshot["automatic_termination"] is False
        await app.stop()

    asyncio.run(check())


def test_operator_selection_is_explicit_and_partial_exits_are_counted(cfg, monkeypatch, tmp_path):
    async def check():
        import src.main as module
        from src.models import ActionResult, ProcessIdentity

        app = app_with_store(cfg)
        executable = tmp_path / "fixture.exe"
        executable.write_bytes(b"review fixture, never executed")
        captured = ProcessIdentity(12345, 100, "fixture.exe", str(executable))
        app.process_monitor.instances = [captured.to_dict()]
        monkeypatch.setattr(module, "inspect_process", lambda pid: captured)
        item = Incident("Canary", "critical", "canary", ["Canary"])
        app.store.save(item)
        choice = await app.execute_command(
            {
                "request_id": str(uuid4()),
                "command": "select_actor",
                "incident_id": item.id,
                "process_key": captured.key,
            }
        )
        assert choice["status"] == "selected"
        assert app.store.get(item.id)["attribution"] == "operator_selected"
        app.responder.take_action = Mock(
            return_value=ActionResult(
                "partial",
                "One target failed",
                ({"pid": 12345, "status": "terminated"}, {"pid": 12346, "status": "failed"}),
            )
        )
        result = await app.execute_command(
            {"request_id": str(uuid4()), "command": "terminate", "incident_id": item.id}
        )
        assert result["status"] == "partial"
        assert app.stats["blocked"] == 1 and app.stats["failed_actions"] == 1
        reviewed = await app.execute_command(
            {
                "request_id": str(uuid4()),
                "command": "allow",
                "incident_id": item.id,
                "reason": "Reviewed fixture",
            }
        )
        assert reviewed["status"] == "allowed" and len(app.store.rules()) == 1
        assert app.store.get(item.id)["status"] == "open"
        await app.stop()

    asyncio.run(check())


def test_workspace_kinds_cannot_mix_and_export_is_not_limited_to_ui(cfg):
    store = IncidentStore(cfg["storage"]["directory"])
    store.claim_workspace("live")
    with pytest.raises(ValueError):
        store.claim_workspace("demo")
    for index in range(205):
        store.save(Incident(str(index), "high", "path", []))
    assert len(store.list()) == 200
    assert len(store.export()) == 205


def test_simulator_never_modifies_preexisting_files(tmp_path):
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "safe_simulator", Path(__file__).parent / "ransomware_simulator.py"
    )
    simulator = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(simulator)
    existing = tmp_path / "keep.txt"
    existing.write_text("USER CONTENT")
    result = simulator.run_simulation(tmp_path, files=6, delay=0)
    assert result["prevention_claim"] is False
    assert existing.read_text() == "USER CONTENT"
    assert list(tmp_path.iterdir()) == [existing]
