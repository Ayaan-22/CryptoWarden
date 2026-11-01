from unittest.mock import Mock

import psutil
import pytest

from src.models import ProcessIdentity
from src.response.responder import Responder


def fake_process(pid=12345, created=100, name="app.exe", exe="C:/app.exe"):
    process = Mock(pid=pid)
    process.create_time.return_value = created
    process.name.return_value = name
    process.exe.return_value = exe
    process.is_running.return_value = True
    process.children.return_value = []
    return process


def identity(process):
    return ProcessIdentity(process.pid, 100, "app.exe", "C:/app.exe")


def responder(cfg, process):
    cfg["response"]["mode"] = "terminate"
    return Responder(cfg["response"], lambda pid: process, critical_check=lambda pid: False)


def test_alert_only_does_not_inspect_or_kill(cfg):
    factory = Mock()
    response = Responder(cfg["response"], factory).take_action(None, "reason", manual=True)
    assert response.status == "alert_only" and not factory.called


def test_invalid_mode_refuses(cfg):
    cfg["response"]["mode"] = "typo"
    assert Responder(cfg["response"]).take_action(None, "reason", True).status == "refused"


def test_automatic_response_is_unavailable(cfg):
    process = fake_process()
    assert responder(cfg, process).take_action(identity(process), "canary").status == "refused"
    process.kill.assert_not_called()


def test_pid_only_input_is_refused(cfg):
    process = fake_process()
    assert responder(cfg, process).take_action(12345, "reason", True).status == "refused"


@pytest.mark.parametrize("name", ["System", "lsass.exe", "CSRSS.EXE"])
def test_protected_name_refused(cfg, name):
    process = fake_process(name=name)
    assert (
        responder(cfg, process).take_action(identity(process), "reason", True).status == "refused"
    )
    process.kill.assert_not_called()


def test_reused_pid_refused(cfg):
    process = fake_process(created=200)
    assert (
        responder(cfg, process).take_action(identity(process), "reason", True).status == "refused"
    )
    process.kill.assert_not_called()


def test_verified_manual_exit_is_confirmed(cfg):
    process = fake_process()
    result = responder(cfg, process).take_action(identity(process), "reason", True)
    assert result.status == "terminated"
    process.kill.assert_called_once()
    process.wait.assert_called_once_with(timeout=3)


def test_permission_denied_is_failed_not_blocked(cfg):
    process = fake_process()
    process.kill.side_effect = psutil.AccessDenied(process.pid)
    assert responder(cfg, process).take_action(identity(process), "reason", True).status == "failed"


def test_already_exited_not_counted_as_termination(cfg):
    process = fake_process()
    process.is_running.return_value = False
    assert (
        responder(cfg, process).take_action(identity(process), "reason", True).status
        == "already_exited"
    )


def test_protected_child_stops_tree_preflight(cfg):
    process = fake_process()
    child = fake_process(pid=12346, name="lsass.exe")
    process.children.return_value = [child]
    cfg["response"]["terminate_tree"] = True
    assert (
        responder(cfg, process).take_action(identity(process), "reason", True).status == "refused"
    )
    process.kill.assert_not_called()
    child.kill.assert_not_called()


def test_process_changes_before_final_action(cfg):
    process = fake_process()
    process.create_time.side_effect = [100, 100, 200]
    assert responder(cfg, process).take_action(identity(process), "reason", True).status == "failed"
    process.kill.assert_not_called()


def test_kill_timeout_is_failed(cfg):
    process = fake_process()
    process.wait.side_effect = psutil.TimeoutExpired(3)
    assert responder(cfg, process).take_action(identity(process), "reason", True).status == "failed"


def test_critical_query_failure_refuses_response(cfg):
    process = fake_process()
    cfg["response"]["mode"] = "terminate"
    response = Responder(cfg["response"], lambda pid: process, critical_check=lambda pid: True)
    assert response.take_action(identity(process), "reason", True).status == "refused"
    process.kill.assert_not_called()


def test_native_critical_query_fails_closed_on_invalid_windows_pid():
    import os

    from src.response.responder import is_critical_process

    if os.name == "nt":
        assert is_critical_process(0) is True
