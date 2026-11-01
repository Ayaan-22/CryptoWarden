import asyncio
from unittest.mock import Mock
from uuid import uuid4

import pytest
from starlette.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from src.utils.dashboard_bridge import DashboardBridge

TOKEN = "a" * 40
ORIGIN = "http://127.0.0.1:8001"


def setup_bridge():
    async def snapshot():
        return {"incidents": [], "health": "running"}

    async def command(cmd):
        return {"status": "refused", "reason": "test policy"}

    return DashboardBridge(auth_token=TOKEN, snapshot_provider=snapshot, command_handler=command)


def login(client):
    response = client.post("/api/session", json={"token": TOKEN}, headers={"Origin": ORIGIN})
    assert response.status_code == 200
    return response.json()["csrf"]


def test_anonymous_snapshot_and_export_rejected():
    with TestClient(setup_bridge().app, base_url=ORIGIN) as client:
        assert client.get("/api/snapshot").status_code == 401
        assert client.get("/api/export").status_code == 401


def test_foreign_origin_and_host_rejected():
    with TestClient(setup_bridge().app, base_url=ORIGIN) as client:
        assert (
            client.post(
                "/api/session", json={"token": TOKEN}, headers={"Origin": "https://evil.invalid"}
            ).status_code
            == 403
        )
        assert client.get("/", headers={"Host": "evil.invalid"}).status_code == 400


def test_login_session_security_and_logout():
    with TestClient(setup_bridge().app, base_url=ORIGIN) as client:
        response = client.post("/api/session", json={"token": TOKEN}, headers={"Origin": ORIGIN})
        assert (
            "HttpOnly" in response.headers["set-cookie"]
            and "SameSite=strict" in response.headers["set-cookie"]
        )
        assert client.get("/api/snapshot").status_code == 200
        assert (
            client.delete(
                "/api/session", headers={"Origin": ORIGIN, "X-CSRF-Token": response.json()["csrf"]}
            ).status_code
            == 200
        )
        assert client.get("/api/snapshot").status_code == 401


def test_csrf_and_origin_are_required_for_actions():
    with TestClient(setup_bridge().app, base_url=ORIGIN) as client:
        csrf = login(client)
        command = {"command": "resolve", "request_id": str(uuid4()), "incident_id": "x"}
        assert client.post("/api/commands", json=command).status_code == 403
        assert (
            client.post(
                "/api/commands",
                json=command,
                headers={"X-CSRF-Token": csrf, "Origin": "https://evil.invalid"},
            ).status_code
            == 403
        )
        result = client.post(
            "/api/commands", json=command, headers={"X-CSRF-Token": csrf, "Origin": ORIGIN}
        )
        assert result.status_code == 200 and result.json()["status"] == "refused"


@pytest.mark.parametrize(
    "command",
    [
        {"command": "kill", "pid": 42},
        {"command": "terminate", "pid": True},
        {"command": "whitelist", "process_name": "chrome.exe"},
        {"command": "resolve", "incident_id": 1},
        {"command": "resolve", "incident_id": "x", "pid": 123},
    ],
)
def test_arbitrary_process_control_payloads_rejected(command):
    command["request_id"] = str(uuid4())
    assert not setup_bridge()._validate_command(command)[0]


def test_websocket_requires_session_and_exact_origin():
    with TestClient(setup_bridge().app, base_url=ORIGIN) as client:
        with pytest.raises(WebSocketDisconnect):
            with client.websocket_connect(
                ORIGIN.replace("http:", "ws:") + "/ws", headers={"Origin": ORIGIN}
            ):
                pass
        login(client)
        with pytest.raises(WebSocketDisconnect):
            with client.websocket_connect(
                ORIGIN.replace("http:", "ws:") + "/ws", headers={"Origin": "https://evil.invalid"}
            ):
                pass
        with client.websocket_connect(
            ORIGIN.replace("http:", "ws:") + "/ws", headers={"Origin": ORIGIN}
        ) as ws:
            assert ws.receive_json()["type"] == "snapshot"
            ws.send_text("ping")


def test_socket_cannot_submit_commands():
    with TestClient(setup_bridge().app, base_url=ORIGIN) as client:
        login(client)
        with client.websocket_connect(
            ORIGIN.replace("http:", "ws:") + "/ws", headers={"Origin": ORIGIN}
        ) as ws:
            ws.receive_json()
            ws.send_text('{"command":"kill","pid":42}')
            with pytest.raises(WebSocketDisconnect):
                ws.receive_text()


def test_login_rate_limit():
    with TestClient(setup_bridge().app, base_url=ORIGIN) as client:
        for _ in range(5):
            assert client.post("/api/session", json={"token": "bad"}).status_code == 401
        assert client.post("/api/session", json={"token": TOKEN}).status_code == 429


def test_request_size_bound_and_security_headers():
    with TestClient(setup_bridge().app, base_url=ORIGIN) as client:
        response = client.get("/")
        assert "frame-ancestors 'none'" in response.headers["content-security-policy"]
        assert response.headers["x-content-type-options"] == "nosniff"
        assert client.post("/api/session", content="x" * 9000).status_code == 400


def test_non_ascii_access_key_is_rejected_without_server_error():
    with TestClient(setup_bridge().app, base_url=ORIGIN) as client:
        assert client.post("/api/session", json={"token": "非ASCII"}).status_code == 401


def test_expired_session_is_rejected():
    bridge = setup_bridge()
    with TestClient(bridge.app, base_url=ORIGIN) as client:
        login(client)
        for session in bridge.sessions.values():
            session["expires"] = 0
        assert client.get("/api/snapshot").status_code == 401


def test_unlisted_paths_never_reach_filesystem():
    with TestClient(setup_bridge().app, base_url=ORIGIN) as client:
        assert client.get("/%5C%5Cuntrusted.invalid%5Cshare").status_code == 404
        assert client.get("/config.yaml").status_code == 404
        assert client.get("/dashboard.js").status_code == 200


def test_broadcast_is_nonblocking_and_bounded():
    async def check():
        bridge = setup_bridge()
        socket = Mock()
        queue = asyncio.Queue(maxsize=1)
        bridge.active_connections[socket] = queue
        await bridge.broadcast({"type": "activity", "data": {"x": 1}})
        await bridge.broadcast({"type": "activity", "data": {"x": 2}})
        assert bridge.dropped == 1 and socket not in bridge.active_connections
        socket.send_json.assert_not_called()

    asyncio.run(check())
