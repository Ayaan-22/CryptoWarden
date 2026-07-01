from src.utils.dashboard_bridge import DashboardBridge


def test_kill_command_requires_positive_integer_pid():
    bridge = DashboardBridge()

    is_valid, reason = bridge._validate_command({"command": "kill", "pid": "42"})
    assert is_valid is True
    assert reason is None

    is_valid, reason = bridge._validate_command({"command": "kill", "pid": "abc"})
    assert is_valid is False
    assert "integer pid" in reason

    is_valid, reason = bridge._validate_command({"command": "kill", "pid": 0})
    assert is_valid is False
    assert "positive" in reason


def test_whitelist_command_trims_process_name():
    bridge = DashboardBridge()
    command = {"command": "whitelist", "process_name": "  app.exe  "}

    is_valid, reason = bridge._validate_command(command)

    assert is_valid is True
    assert reason is None
    assert command["process_name"] == "app.exe"


def test_unknown_dashboard_command_is_rejected():
    bridge = DashboardBridge()

    is_valid, reason = bridge._validate_command({"command": "format_disk"})

    assert is_valid is False
    assert "Unknown dashboard command" in reason
