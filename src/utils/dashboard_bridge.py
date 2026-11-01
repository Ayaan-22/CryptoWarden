"""Loopback-only console: authenticated HTTP actions and bounded push-only WebSockets."""

import asyncio
import hmac
import json
import secrets
import time
from pathlib import Path
from uuid import UUID

import uvicorn
from starlette.applications import Starlette
from starlette.responses import JSONResponse, Response
from starlette.routing import Route, WebSocketRoute
from starlette.websockets import WebSocketDisconnect

HEADERS = {
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "X-Frame-Options": "DENY",
    "Content-Security-Policy": "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; font-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
}


class DashboardBridge:
    def __init__(
        self,
        host="127.0.0.1",
        port=8001,
        auth_token="",
        session_seconds=3600,
        snapshot_provider=None,
        command_handler=None,
    ):
        self.host, self.port = host, port
        self.auth_token = auth_token or secrets.token_urlsafe(32)
        self.session_seconds = session_seconds
        self.snapshot_provider = snapshot_provider
        self.export_provider = None
        self.command_handler = command_handler
        self.sessions = {}
        self.login_attempts = {}
        self.active_connections = {}
        self.sender_tasks = {}
        self.server_task = self.server = None
        self.health = "stopped"
        self.published = self.dropped = 0
        self.allowed_hosts = {f"{host}:{port}", f"localhost:{port}"}
        if ":" in host:
            self.allowed_hosts = {f"[{host}]:{port}", f"localhost:{port}"}
        self.allowed_origins = {f"http://{host}" for host in self.allowed_hosts}
        self.dashboard_dir = Path(__file__).resolve().parents[2] / "dashboard"
        self.assets = {}
        for filename, media in (
            ("index.html", "text/html"),
            ("dashboard.js", "text/javascript"),
            ("dashboard.css", "text/css"),
        ):
            self.assets["/" if filename == "index.html" else "/" + filename] = (
                self.dashboard_dir.joinpath(filename).read_bytes(),
                media,
            )
        routes = [
            Route("/", self.asset),
            Route("/dashboard.js", self.asset),
            Route("/dashboard.css", self.asset),
            Route("/api/session", self.login, methods=["POST"]),
            Route("/api/session", self.logout, methods=["DELETE"]),
            Route("/api/snapshot", self.snapshot),
            Route("/api/export", self.export),
            Route("/api/commands", self.command, methods=["POST"]),
            WebSocketRoute("/ws", self.websocket),
        ]
        self.app = Starlette(routes=routes)
        original = self.app

        async def secured(scope, receive, send):
            if scope["type"] not in {"http", "websocket"}:
                return await original(scope, receive, send)
            headers = dict(scope.get("headers", []))
            if headers.get(b"host", b"").decode().lower() not in self.allowed_hosts:
                if scope["type"] == "websocket":
                    return await send({"type": "websocket.close", "code": 1008})
                return await JSONResponse(
                    {"error": "Invalid Host"}, status_code=400, headers=HEADERS
                )(scope, receive, send)

            async def guarded_send(message):
                if message["type"] == "http.response.start":
                    message["headers"] = list(message.get("headers", [])) + [
                        (key.lower().encode(), value.encode()) for key, value in HEADERS.items()
                    ]
                await send(message)

            await original(scope, receive, guarded_send)

        self.app = secured

    def _origin_ok(self, request, required=False):
        origin = request.headers.get("origin")
        return origin in self.allowed_origins if origin else not required

    def _session(self, request):
        now = time.monotonic()
        self.sessions = {
            key: value for key, value in self.sessions.items() if value["expires"] > now
        }
        return self.sessions.get(request.cookies.get("cw_session", ""))

    async def _body(self, request):
        data = bytearray()
        async for chunk in request.stream():
            data.extend(chunk)
            if len(data) > 8192:
                raise ValueError("Request too large")
        result = json.loads(data)
        if not isinstance(result, dict):
            raise ValueError("JSON object required")
        return result

    async def asset(self, request):
        # Exact allowlist loaded once: no untrusted path ever reaches a filesystem resolver.
        content, media = self.assets[request.url.path]
        return Response(content, media_type=media)

    async def login(self, request):
        if not self._origin_ok(request):
            return JSONResponse({"error": "Origin rejected"}, status_code=403)
        now = time.monotonic()
        ip = request.client.host if request.client else "local"
        attempts = [value for value in self.login_attempts.get(ip, []) if now - value < 60]
        self.login_attempts = {
            key: value
            for key, value in self.login_attempts.items()
            if value and now - value[-1] < 60
        }
        if len(attempts) >= 5:
            return JSONResponse(
                {"error": "Too many attempts. Try again in a minute."}, status_code=429
            )
        if ip not in self.login_attempts and len(self.login_attempts) >= 64:
            return JSONResponse({"error": "Login capacity reached"}, status_code=429)
        try:
            body = await asyncio.wait_for(self._body(request), timeout=3)
            token = body.get("token")
            if (
                not isinstance(token, str)
                or not token.isascii()
                or not hmac.compare_digest(token, self.auth_token)
            ):
                self.login_attempts[ip] = [*attempts, now]
                return JSONResponse({"error": "Invalid access key"}, status_code=401)
        except (ValueError, asyncio.TimeoutError):
            return JSONResponse({"error": "Invalid login request"}, status_code=400)
        if len(self.sessions) >= 16:
            self.sessions.pop(next(iter(self.sessions)))
        session, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        self.sessions[session] = {
            "csrf": csrf,
            "expires": now + self.session_seconds,
            "commands": [],
        }
        response = JSONResponse({"csrf": csrf, "expires_in": self.session_seconds})
        response.set_cookie(
            "cw_session", session, httponly=True, samesite="strict", max_age=self.session_seconds
        )
        return response

    def _authorized_write(self, request):
        session = self._session(request)
        if not session or not self._origin_ok(request, required=True):
            return None
        csrf = request.headers.get("x-csrf-token", "")
        return session if csrf.isascii() and hmac.compare_digest(csrf, session["csrf"]) else None

    async def logout(self, request):
        if not self._authorized_write(request):
            return JSONResponse({"error": "Session or CSRF check failed"}, status_code=403)
        self.sessions.pop(request.cookies.get("cw_session"), None)
        for socket in list(self.active_connections):
            if not self._session(socket):
                await socket.close(code=1008)
        response = JSONResponse({"ok": True})
        response.delete_cookie("cw_session")
        return response

    async def snapshot(self, request):
        if not self._session(request):
            return JSONResponse({"error": "Authentication required"}, status_code=401)
        data = await self.snapshot_provider() if self.snapshot_provider else {}
        return JSONResponse(data)

    async def export(self, request):
        if not self._session(request):
            return JSONResponse({"error": "Authentication required"}, status_code=401)
        data = await self.snapshot_provider() if self.snapshot_provider else {}
        records = (
            await self.export_provider() if self.export_provider else data.get("incidents", [])
        )
        return Response(
            json.dumps({"exported_at": time.time(), "incidents": records}, indent=2),
            media_type="application/json",
            headers={"Content-Disposition": 'attachment; filename="cryptowarden-incidents.json"'},
        )

    def _validate_command(self, cmd):
        if not isinstance(cmd, dict):
            return False, "Command must be an object"
        try:
            UUID(cmd.get("request_id", ""))
        except (ValueError, TypeError, AttributeError):
            return False, "A UUID request_id is required"
        command = cmd.get("command")
        if not isinstance(command, str):
            return False, "Command name must be a string"
        fields = {
            "terminate": {"incident_id"},
            "allow": {"incident_id", "reason"},
            "select_actor": {"incident_id", "process_key"},
            "remove_rule": {"rule_id"},
            "resolve": {"incident_id"},
        }
        controls = {
            "policy_preview": {"expected_revision", "patch", "reason"},
            "policy_apply": {
                "expected_revision",
                "patch",
                "reason",
                "preview_id",
                "acknowledge_gap",
                "confirmation",
            },
            "monitoring_pause": {
                "expected_revision",
                "reason",
                "duration_seconds",
                "acknowledge_gap",
            },
            "monitoring_resume": {"expected_revision", "reason"},
            "monitoring_restart": {"expected_revision", "reason", "acknowledge_gap"},
        }
        if command in controls:
            if set(cmd) != {"request_id", "command"} | controls[command]:
                return False, "Missing or unexpected management fields"
            if type(cmd["expected_revision"]) is not int or cmd["expected_revision"] < 1:
                return False, "A positive policy revision is required"
            if not isinstance(cmd["reason"], str) or not 5 <= len(cmd["reason"].strip()) <= 512:
                return False, "A reason of 5–512 characters is required"
            if "patch" in cmd and not isinstance(cmd["patch"], dict):
                return False, "Policy patch must be an object"
            if "acknowledge_gap" in cmd and type(cmd["acknowledge_gap"]) is not bool:
                return False, "Coverage acknowledgment must be boolean"
            if "duration_seconds" in cmd and (
                type(cmd["duration_seconds"]) is not int
                or cmd["duration_seconds"] not in {0, 60, 300, 900, 3600}
            ):
                return False, "Pause duration must be 0, 60, 300, 900 or 3600 seconds"
            if command == "policy_apply" and (
                not isinstance(cmd["preview_id"], str)
                or len(cmd["preview_id"]) != 64
                or not isinstance(cmd["confirmation"], str)
                or len(cmd["confirmation"]) > 64
            ):
                return False, "A valid review fingerprint and confirmation are required"
            return True, None
        if command not in fields:
            return False, "Unknown command"
        if set(cmd) - {"request_id", "command"} - fields[command]:
            return False, "Unexpected command fields"
        for field in fields[command]:
            if not isinstance(cmd.get(field), str) or not 1 <= len(cmd[field]) <= 512:
                return False, f"{field} is required"
        return True, None

    async def command(self, request):
        session = self._authorized_write(request)
        if not session:
            return JSONResponse({"error": "Session, Origin or CSRF check failed"}, status_code=403)
        now = time.monotonic()
        session["commands"] = [stamp for stamp in session["commands"] if now - stamp < 60]
        if len(session["commands"]) >= 30:
            return JSONResponse({"error": "Command rate limit"}, status_code=429)
        session["commands"].append(now)
        try:
            command = await asyncio.wait_for(self._body(request), timeout=3)
            valid, reason = self._validate_command(command)
            if not valid:
                return JSONResponse({"error": reason}, status_code=400)
            result = (
                await self.command_handler(command)
                if self.command_handler
                else {"status": "refused", "reason": "Engine unavailable"}
            )
            return JSONResponse({"request_id": command["request_id"], **result})
        except (ValueError, asyncio.TimeoutError):
            return JSONResponse({"error": "Invalid command request"}, status_code=400)
        except Exception:
            return JSONResponse(
                {
                    "error": "Command outcome unavailable. Refresh the incident before attempting another action."
                },
                status_code=500,
            )

    async def _sender(self, socket, queue):
        while True:
            message = await queue.get()
            try:
                await asyncio.wait_for(socket.send_json(message), timeout=2)
            finally:
                queue.task_done()

    async def websocket(self, socket):
        if (
            not self._origin_ok(socket, required=True)
            or not self._session(socket)
            or len(self.active_connections) >= 8
        ):
            await socket.close(code=1008)
            return
        await socket.accept()
        queue = asyncio.Queue(maxsize=64)
        self.active_connections[socket] = queue
        sender = asyncio.create_task(self._sender(socket, queue))
        self.sender_tasks[socket] = sender
        if self.snapshot_provider:
            queue.put_nowait({"type": "snapshot", "data": await self.snapshot_provider()})
        try:
            received = []
            while self._session(socket):
                try:
                    text = await asyncio.wait_for(socket.receive_text(), timeout=5)
                    now = time.monotonic()
                    received = [stamp for stamp in received if now - stamp < 60]
                    received.append(now)
                    if len(received) > 60:
                        await socket.close(code=1008)
                        break
                    # Push-only stream: all state-changing commands use authenticated HTTP + CSRF.
                    if text != "ping":
                        await socket.close(code=1008)
                        break
                except asyncio.TimeoutError:
                    if sender.done():
                        break
            if not self._session(socket):
                await socket.close(code=1008)
        except (WebSocketDisconnect, RuntimeError):
            pass
        finally:
            self.active_connections.pop(socket, None)
            self.sender_tasks.pop(socket, None)
            sender.cancel()
            await asyncio.gather(sender, return_exceptions=True)
            try:
                await asyncio.wait_for(socket.close(code=1001), timeout=1)
            except (RuntimeError, WebSocketDisconnect, asyncio.TimeoutError):
                pass

    def publish(self, kind, data):
        self.published += 1
        for socket, queue in list(self.active_connections.items()):
            try:
                queue.put_nowait({"type": kind, "data": data})
            except asyncio.QueueFull:
                self.dropped += 1
                self.active_connections.pop(socket, None)
                task = self.sender_tasks.get(socket)
                if task:
                    task.cancel()
                # The receiver observes the stopped sender within five seconds.

    async def broadcast(self, data):
        self.publish(data["type"], data["data"])

    async def send_activity(self, event):
        self.publish("activity", event)

    async def send_stats(self, stats):
        self.publish("stats", stats)

    async def start(self):
        self.server = uvicorn.Server(
            uvicorn.Config(
                self.app,
                host=self.host,
                port=self.port,
                log_level="warning",
                ws_max_size=1024,
                ws_max_queue=8,
                timeout_graceful_shutdown=3,
                limit_concurrency=32,
                backlog=64,
                h11_max_incomplete_event_size=16384,
            )
        )

        async def serve():
            try:
                await self.server.serve()
            except SystemExit as error:
                raise RuntimeError("Dashboard could not bind its listener") from error

        self.server_task = asyncio.create_task(serve(), name="dashboard-server")
        deadline = time.monotonic() + 10
        while not self.server.started:
            if self.server_task.done():
                await self.server_task
                raise RuntimeError("Dashboard stopped during startup")
            if time.monotonic() > deadline:
                raise RuntimeError("Dashboard readiness timed out")
            await asyncio.sleep(0.02)
        self.health = "running"

    async def stop(self):
        for socket in list(self.active_connections):
            try:
                await asyncio.wait_for(socket.close(code=1001), timeout=1)
            except (RuntimeError, asyncio.TimeoutError):
                pass
        for task in self.sender_tasks.values():
            task.cancel()
        if self.sender_tasks:
            await asyncio.gather(*self.sender_tasks.values(), return_exceptions=True)
        self.active_connections.clear()
        if self.server:
            self.server.should_exit = True
        if self.server_task:
            try:
                await asyncio.wait_for(self.server_task, timeout=5)
            except asyncio.TimeoutError:
                self.server_task.cancel()
                await asyncio.gather(self.server_task, return_exceptions=True)
        self.health = "stopped"
