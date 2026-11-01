"""Real collector management against disposable roots; no personal paths or response kills."""

import asyncio
import socket
import time
from pathlib import Path
from uuid import uuid4

import httpx

from src.main import CryptoWarden


async def wait_for(predicate, timeout=12):
    deadline = time.monotonic() + timeout
    while not predicate():
        if time.monotonic() > deadline:
            raise AssertionError("Management integration deadline exceeded")
        await asyncio.sleep(0.05)


def test_authenticated_pause_scope_update_resume_and_restart(cfg, tmp_path):
    async def check():
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            cfg["dashboard"]["port"] = sock.getsockname()[1]
        app = CryptoWarden(cfg)
        task = asyncio.create_task(app.start())
        try:
            await wait_for(lambda: app.health == "running" or task.done())
            assert not task.done()
            origin = f"http://127.0.0.1:{cfg['dashboard']['port']}"
            async with httpx.AsyncClient(base_url=origin, timeout=20) as client:
                response = await client.post(
                    "/api/session",
                    json={"token": app.bridge.auth_token},
                    headers={"Origin": origin},
                )
                csrf = response.json()["csrf"]

                async def command(name, revision, **fields):
                    result = await client.post(
                        "/api/commands",
                        json={
                            "request_id": str(uuid4()),
                            "command": name,
                            "expected_revision": revision,
                            "reason": "Controlled fixture management integration",
                            **fields,
                        },
                        headers={"Origin": origin, "X-CSRF-Token": csrf},
                    )
                    assert result.status_code == 200, result.text
                    return result.json()

                old_observer = app.file_monitor.observer
                paused = await command(
                    "monitoring_pause", 1, duration_seconds=0, acknowledge_gap=True
                )
                assert paused["status"] == "applied"
                assert app.controls.status == "paused" and not old_observer.is_alive()
                assert (await client.get("/api/snapshot")).json()["health"] == "paused"
                scanned = app.stats["scanned"]
                (Path(cfg["monitoring"]["directories"][0]) / "during-pause.txt").write_text(
                    "Not collected during the declared gap"
                )
                await asyncio.sleep(0.2)
                assert app.stats["scanned"] == scanned
                second_root = tmp_path / "new-protected-root"
                second_root.mkdir()
                patch = {
                    "monitoring": {"directories": [str(second_root)]},
                    "detection": {"min_unique_files": 8},
                }
                preview = await command("policy_preview", 2, patch=patch)
                assert preview["status"] == "preview"
                applied = await command(
                    "policy_apply",
                    2,
                    patch=patch,
                    preview_id=preview["preview_id"],
                    acknowledge_gap=True,
                    confirmation="",
                )
                assert applied["status"] == "applied" and app.controls.status == "paused"
                assert not list(second_root.glob(".cw-canary-*"))
                resumed = await command("monitoring_resume", 3)
                assert resumed["status"] == "applied" and app.file_monitor.observer.is_alive()
                assert len(list(second_root.glob(".cw-canary-*"))) == 4
                assert app.settings["detection"]["min_unique_files"] == 8
                canary = Path(next(iter(app.canaries.paths)))
                canary.write_text("Controlled post-resume integrity change")
                await wait_for(lambda: app.stats["detections"] > 0)
                assert app.store.list()[0]["path"] == str(canary)
                assert app.stats["blocked"] == 0
                previous = app.file_monitor.observer
                restarted = await command("monitoring_restart", 4, acknowledge_gap=True)
                assert restarted["status"] == "applied" and not previous.is_alive()
                assert app.file_monitor.observer.is_alive()
                stale = await command(
                    "monitoring_pause", 4, duration_seconds=0, acknowledge_gap=True
                )
                assert stale["status"] == "conflict" and app.controls.status == "running"
                gaps = [
                    row for row in app.store.audit_events(100) if row["command"] == "coverage_gap"
                ]
                assert len(gaps) == 4
        finally:
            app.stop_requested.set()
            await asyncio.wait_for(task, timeout=12)
        assert app.lock.stream is None

    asyncio.run(check())
