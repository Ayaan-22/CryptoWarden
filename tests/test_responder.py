from src.response import responder
from src.response.responder import Responder


def test_alert_only_mode_does_not_kill(monkeypatch):
    killed = []
    alerted = []
    instance = Responder()

    monkeypatch.setattr(responder, "RESPONSE_MODE", "alert_only")
    monkeypatch.setattr(responder, "kill_process", lambda pid: killed.append(pid))
    monkeypatch.setattr(instance, "_resolve_process_name", lambda pid, fallback: fallback)
    monkeypatch.setattr(instance, "_show_alert_once", lambda name, reason: alerted.append((name, reason)))

    instance.take_action(99, "locker.exe", "test detection")

    assert killed == []
    assert alerted == [("locker.exe", "test detection")]


def test_protected_process_is_not_killed(monkeypatch):
    killed = []
    alerted = []
    instance = Responder()

    monkeypatch.setattr(responder, "RESPONSE_MODE", "terminate")
    monkeypatch.setattr(responder, "PROTECTED_PROCESS_NAMES", {"system"})
    monkeypatch.setattr(responder, "kill_process", lambda pid: killed.append(pid))
    monkeypatch.setattr(instance, "_resolve_process_name", lambda pid, fallback: "System")
    monkeypatch.setattr(instance, "_show_alert_once", lambda name, reason: alerted.append((name, reason)))

    instance.take_action(4, "unknown", "test detection")

    assert killed == []
    assert alerted == [("System", "test detection")]
