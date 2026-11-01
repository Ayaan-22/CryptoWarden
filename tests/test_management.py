import asyncio
from copy import deepcopy
from pathlib import Path
from uuid import uuid4

import pytest

from src.config import ConfigError
from src.main import CryptoWarden
from src.management import candidate_policy, preview_policy, public_policy
from src.storage import IncidentStore
from src.utils.dashboard_bridge import DashboardBridge


def operation(name, revision=1, **fields):
    return {
        "request_id": str(uuid4()),
        "command": name,
        "expected_revision": revision,
        "reason": "Controlled management test",
        **fields,
    }


async def demo_app(cfg):
    app = CryptoWarden(cfg, demo=True)
    app.store = IncidentStore(cfg["storage"]["directory"])
    await app.controls.load()
    await app.controls.start_initial()
    return app


@pytest.mark.parametrize(
    "patch",
    [
        {"dashboard": {"auth_token": "attacker"}},
        {"response": {"protected_processes": []}},
        {"monitoring": {"queue_capacity": 100000}},
        {"detection": {"max_entropy_threshold": 9}},
        {"monitoring": {"directories": []}},
        {"storage": {"directory": "somewhere"}},
    ],
)
def test_only_scoped_valid_policy_is_accepted(cfg, patch):
    with pytest.raises(ConfigError):
        candidate_policy(cfg, patch)


def test_invalid_directory_and_overlapping_scope_are_refused(cfg, tmp_path):
    with pytest.raises(ConfigError):
        candidate_policy(cfg, {"monitoring": {"directories": [str(tmp_path / "missing")]}})
    root = cfg["monitoring"]["directories"][0]
    with pytest.raises(ConfigError):
        candidate_policy(cfg, {"monitoring": {"directories": [root, str(Path(root) / "sub")]}})
    with pytest.raises(ConfigError, match="entire protected root"):
        candidate_policy(cfg, {"monitoring": {"ignored_directories": [Path(root).name]}})


def test_policy_preview_is_pure_and_bound_to_revision_and_reason(cfg):
    old = deepcopy(cfg)
    patch = {"detection": {"min_unique_files": 8}}
    _, preview = preview_policy(cfg, patch, 1, "Approved test change")
    assert cfg == old and len(preview["changes"]) == 1
    assert (
        preview["preview_id"]
        != preview_policy(cfg, patch, 2, "Approved test change")[1]["preview_id"]
    )
    assert (
        preview["preview_id"] != preview_policy(cfg, patch, 1, "Different reason")[1]["preview_id"]
    )


def test_preview_apply_is_persistent_and_conflicts_do_not_overwrite(cfg):
    async def check():
        app = await demo_app(cfg)
        patch = {"detection": {"min_unique_files": 9}}
        preview = await app.execute_command(operation("policy_preview", patch=patch))
        assert preview["status"] == "preview" and app.settings["detection"]["min_unique_files"] == 6
        result = await app.execute_command(
            operation(
                "policy_apply",
                patch=patch,
                preview_id=preview["preview_id"],
                acknowledge_gap=True,
                confirmation="",
            )
        )
        assert result["status"] == "applied" and result["revision"] == 2
        assert app.settings["detection"]["min_unique_files"] == 9
        conflict = await app.execute_command(
            operation("monitoring_pause", duration_seconds=0, acknowledge_gap=True)
        )
        assert conflict["status"] == "conflict" and app.controls.status == "running"
        second = CryptoWarden(cfg, demo=True)
        second.store = IncidentStore(cfg["storage"]["directory"])
        await second.controls.load()
        assert second.settings["detection"]["min_unique_files"] == 9
        assert second.controls.state["revision"] == 2
        assert any(item["command"] == "coverage_gap" for item in app.store.audit_events())
        await app.stop()
        await second.stop()

    asyncio.run(check())


def test_risky_mode_requires_exact_confirmation_and_never_enables_automatic_response(cfg):
    async def check():
        app = await demo_app(cfg)
        patch = {"response": {"mode": "terminate"}}
        preview = await app.execute_command(operation("policy_preview", patch=patch))
        assert preview["requires_termination_confirmation"]
        refused = await app.execute_command(
            operation(
                "policy_apply",
                patch=patch,
                preview_id=preview["preview_id"],
                acknowledge_gap=True,
                confirmation="yes",
            )
        )
        assert refused["status"] == "refused" and app.settings["response"]["mode"] == "alert_only"
        result = await app.execute_command(
            operation(
                "policy_apply",
                patch=patch,
                preview_id=preview["preview_id"],
                acknowledge_gap=True,
                confirmation="ENABLE MANUAL TERMINATION",
            )
        )
        assert result["status"] == "applied"
        assert (await app.snapshot())["automatic_termination"] is False
        await app.stop()

    asyncio.run(check())


def test_pause_resume_and_restart_are_explicit_and_revisioned(cfg):
    async def check():
        app = await demo_app(cfg)
        denied = await app.execute_command(
            operation("monitoring_pause", duration_seconds=300, acknowledge_gap=False)
        )
        assert denied["status"] == "refused"
        paused = await app.execute_command(
            operation("monitoring_pause", duration_seconds=0, acknowledge_gap=True)
        )
        assert paused["status"] == "applied" and app.controls.status == "paused"
        assert app.controls.state["pause_until"] is None
        restarted = CryptoWarden(cfg, demo=True)
        restarted.store = app.store
        await restarted.controls.load()
        await restarted.controls.start_initial()
        assert restarted.controls.status == "paused"
        resumed = await app.execute_command(operation("monitoring_resume", revision=2))
        assert resumed["status"] == "applied" and app.controls.status == "running"
        result = await app.execute_command(
            operation("monitoring_restart", revision=3, acknowledge_gap=True)
        )
        assert result["status"] == "applied" and app.controls.state["revision"] == 4
        await app.stop()
        await restarted.stop()

    asyncio.run(check())


def test_expired_timed_pause_resumes_and_is_audited(cfg):
    async def check():
        app = await demo_app(cfg)
        await app.execute_command(
            operation("monitoring_pause", duration_seconds=60, acknowledge_gap=True)
        )
        app.controls.state["pause_until"] = 1
        app.controls.pause_deadline = 0
        await app.controls.tick()
        assert app.controls.status == "running" and app.controls.state["revision"] == 3
        assert any(row["command"] == "monitoring_resume" for row in app.store.audit_events())
        await app.stop()

    asyncio.run(check())


def test_failed_restart_rolls_back_policy_and_collectors(cfg, monkeypatch):
    async def check():
        app = await demo_app(cfg)
        patch = {"detection": {"min_unique_files": 12}}
        preview = await app.execute_command(operation("policy_preview", patch=patch))
        original = app.controls.start_collectors
        calls = []

        async def fail_once():
            calls.append(1)
            if len(calls) == 1:
                raise RuntimeError("Injected collector startup failure")
            await original()

        monkeypatch.setattr(app.controls, "start_collectors", fail_once)
        result = await app.execute_command(
            operation(
                "policy_apply",
                patch=patch,
                preview_id=preview["preview_id"],
                acknowledge_gap=True,
                confirmation="",
            )
        )
        assert result["status"] == "failed" and "restored" in result["reason"]
        assert app.settings["detection"]["min_unique_files"] == 6
        assert app.controls.state["revision"] == 1 and app.controls.status == "running"
        assert app.store.management_load(public_policy(cfg))[1] is False
        await app.stop()

    asyncio.run(check())


def test_interrupted_transition_starts_paused_and_edit_does_not_resume(cfg):
    async def check():
        app = await demo_app(cfg)
        app.store.management_transition(1, {"command": "policy_apply"})
        other = CryptoWarden(cfg, demo=True)
        other.store = app.store
        await other.controls.load()
        await other.controls.start_initial()
        assert other.controls.status == "paused" and other.controls.interrupted
        patch = {"detection": {"min_unique_files": 7}}
        preview = await other.execute_command(operation("policy_preview", patch=patch))
        result = await other.execute_command(
            operation(
                "policy_apply",
                patch=patch,
                preview_id=preview["preview_id"],
                acknowledge_gap=True,
                confirmation="",
            )
        )
        assert result["status"] == "applied" and other.controls.status == "paused"
        await app.stop()
        await other.stop()

    asyncio.run(check())


def test_old_generation_is_discarded_and_demo_controls_never_watch_files(cfg):
    async def check():
        app = await demo_app(cfg)
        app.stats["discarded"] = 0
        await app.process_event(
            {
                "_collector_generation": app.controls.generation - 1,
                "type": "modified",
                "src_path": "old",
            }
        )
        assert app.stats["discarded"] == 1 and app.stats["scanned"] == 0
        assert app.file_monitor is None and app.canaries is None
        await app.stop()

    asyncio.run(check())


def test_unrecoverable_transition_leaves_durable_recovery_marker(cfg, monkeypatch):
    async def check():
        app = await demo_app(cfg)
        patch = {"detection": {"min_unique_files": 11}}
        preview = await app.execute_command(operation("policy_preview", patch=patch))

        async def fail():
            raise RuntimeError("Collector cannot start")

        monkeypatch.setattr(app.controls, "start_collectors", fail)
        result = await app.execute_command(
            operation(
                "policy_apply",
                patch=patch,
                preview_id=preview["preview_id"],
                acknowledge_gap=True,
                confirmation="",
            )
        )
        assert result["status"] == "failed" and app.controls.status == "faulted"
        assert app.store.management_load(public_policy(cfg))[1] is True
        assert app.controls.interrupted
        await app.stop()

    asyncio.run(check())


def test_failed_edit_cannot_clear_prior_interruption_marker(cfg, monkeypatch):
    async def check():
        app = await demo_app(cfg)
        app.store.management_transition(1, {"command": "policy_apply"})
        await app.controls.load()
        assert app.controls.interrupted
        patch = {"detection": {"min_unique_files": 10}}
        preview = await app.execute_command(operation("policy_preview", patch=patch))

        def failed_commit(*args):
            raise OSError("Injected commit failure")

        monkeypatch.setattr(app.store, "management_commit", failed_commit)
        result = await app.execute_command(
            operation(
                "policy_apply",
                patch=patch,
                preview_id=preview["preview_id"],
                acknowledge_gap=True,
                confirmation="",
            )
        )
        assert result["status"] == "failed"
        assert app.store.management_load(public_policy(cfg))[1] is True
        assert app.controls.status == "paused"
        await app.stop()

    asyncio.run(check())


def test_unreviewed_or_modified_policy_cannot_apply(cfg):
    async def check():
        app = await demo_app(cfg)
        patch = {"detection": {"min_unique_files": 9}}
        preview = await app.execute_command(operation("policy_preview", patch=patch))
        result = await app.execute_command(
            operation(
                "policy_apply",
                patch={"detection": {"min_unique_files": 10}},
                preview_id=preview["preview_id"],
                acknowledge_gap=True,
                confirmation="",
            )
        )
        assert result["status"] == "refused"
        assert app.settings["detection"]["min_unique_files"] == 6
        assert app.controls.state["revision"] == 1
        await app.stop()

    asyncio.run(check())


def test_shutdown_waits_for_admitted_control_and_rejects_new_commands(cfg, monkeypatch):
    async def check():
        app = await demo_app(cfg)
        entered, release = asyncio.Event(), asyncio.Event()
        original = app.controls.stop_collectors

        async def delayed_stop():
            entered.set()
            await release.wait()
            await original()

        monkeypatch.setattr(app.controls, "stop_collectors", delayed_stop)
        pending = asyncio.create_task(
            app.execute_command(
                operation("monitoring_pause", duration_seconds=0, acknowledge_gap=True)
            )
        )
        await entered.wait()
        shutdown = asyncio.create_task(app.stop())
        await asyncio.sleep(0)
        assert not shutdown.done()
        denied = await app.execute_command(operation("monitoring_resume"))
        assert denied["status"] == "refused" and "shutting down" in denied["reason"]
        release.set()
        assert (await pending)["status"] == "applied"
        await shutdown
        assert app.controls.status == "stopped"

    asyncio.run(check())


def test_missing_directory_keeps_recovery_console_possible(cfg):
    async def check():
        cfg["monitoring"]["directories"] = [str(Path(cfg["storage"]["directory"]) / "missing")]
        app = CryptoWarden(cfg)
        app.store = IncidentStore(cfg["storage"]["directory"])
        await app.controls.load()
        await app.controls.start_initial()
        assert app.controls.status == "faulted" and app.controls.last_error
        app.health = "running"
        assert (await app.snapshot())["health"] == "degraded"
        await app.stop()

    asyncio.run(check())


@pytest.mark.parametrize(
    "fields",
    [
        {"expected_revision": True},
        {"reason": "x"},
        {"duration_seconds": -1},
        {"duration_seconds": True},
        {"acknowledge_gap": "yes"},
    ],
)
def test_management_http_schema_rejects_wrong_types(fields):
    command = operation("monitoring_pause", duration_seconds=300, acknowledge_gap=True)
    command.update(fields)
    assert DashboardBridge()._validate_command(command)[0] is False
