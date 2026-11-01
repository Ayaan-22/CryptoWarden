"""Controlled Windows-capable runtime checks. All files are temporary; kills are forbidden."""

import asyncio
import socket
import time
from pathlib import Path

import httpx
import pytest

from src.main import CryptoWarden
from src.storage import IncidentStore


async def until(predicate, timeout=12):
    deadline = time.monotonic() + timeout
    while not predicate():
        if time.monotonic() > deadline:
            raise AssertionError("Runtime readiness deadline exceeded")
        await asyncio.sleep(0.05)


def test_live_fixture_canary_to_authenticated_console_and_shutdown(cfg):
    async def check():
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            cfg["dashboard"]["port"] = listener.getsockname()[1]
        app = CryptoWarden(cfg)
        task = asyncio.create_task(app.start())
        try:
            await until(lambda: app.health == "running" or task.done())
            assert not task.done(), task.exception() if task.done() else ""
            origin = f"http://127.0.0.1:{cfg['dashboard']['port']}"
            async with httpx.AsyncClient(base_url=origin, timeout=5) as client:
                assert (await client.get("/api/snapshot")).status_code == 401
                result = await client.post(
                    "/api/session",
                    json={"token": app.bridge.auth_token},
                    headers={"Origin": origin},
                )
                assert result.status_code == 200
                canary = Path(next(iter(app.canaries.paths)))
                canary.write_text("Controlled integration fixture changed")
                await until(lambda: app.stats["detections"] > 0)
                snapshot = (await client.get("/api/snapshot")).json()
                assert snapshot["stats"]["blocked"] == 0
                assert snapshot["incidents"][0]["process"] is None
                assert snapshot["runtime"]["file_monitor"] == "running"
                assert all(item["attribution"] == "unknown" for item in snapshot["incidents"])
                assert len(app.canaries.paths) == 4
        finally:
            app.stop_requested.set()
            await asyncio.wait_for(task, timeout=10)
        assert not app.file_monitor.observer.is_alive()
        assert app.lock.stream is None and app.health == "stopped"

    asyncio.run(check())


def test_failure_after_observer_start_cleans_every_acquired_service(cfg, monkeypatch):
    async def check():
        app = CryptoWarden(cfg)

        async def fail():
            raise RuntimeError("Injected dashboard bind failure")

        monkeypatch.setattr(app.bridge, "start", fail)
        with pytest.raises(RuntimeError, match="bind failure"):
            await app.start()
        assert not app.file_monitor.observer.is_alive()
        assert app.process_monitor.task.done()
        assert app.lock.stream is None and app.health == "failed"

    asyncio.run(check())


def test_persisted_command_replay_and_pending_outcome_are_fail_closed(cfg):
    store = IncidentStore(cfg["storage"]["directory"])
    command = {"request_id": "1", "command": "resolve", "incident_id": "x"}
    assert store.reserve_command(command)[0] == "new"
    restarted = IncidentStore(cfg["storage"]["directory"])
    status, result = restarted.reserve_command(command)
    assert status == "replay" and result["status"] == "refused"
    store.finish_command("1", {"status": "resolved"})
    assert restarted.reserve_command(command)[1] == {"status": "resolved"}
    assert restarted.reserve_command({**command, "incident_id": "other"})[1]["status"] == "refused"


def test_entropy_timeout_does_not_build_unbounded_executor_work(cfg, monkeypatch):
    async def check():
        import threading

        import src.main as module
        from src.analysis.entropy import EntropyResult

        release = threading.Event()

        def blocked(*args):
            release.wait(3)
            return EntropyResult(1, "sampled", 4096)

        monkeypatch.setattr(module, "sample_file_entropy", blocked)
        cfg["detection"]["entropy_timeout"] = 0.02
        app = CryptoWarden(cfg)
        try:
            assert (await app._entropy("one"))[1] == "timeout"
            assert (await app._entropy("two"))[1] == "timeout"
            assert (await app._entropy("three"))[1] == "capacity"
            assert len(app.entropy_pending) == 2
        finally:
            release.set()
            await app.stop()

    asyncio.run(check())
