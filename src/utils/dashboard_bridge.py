import asyncio
import json
from pathlib import Path
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
import uvicorn
from src.utils.logger import logger

class DashboardBridge:
    def __init__(self, host="127.0.0.1", port=8001, auth_token=""):
        self.app = FastAPI()
        self.host = host
        self.port = port
        self.auth_token = auth_token
        self.dashboard_dir = Path(__file__).resolve().parents[2] / "dashboard"
        self.active_connections = set()
        self.server_task = None
        self.command_queue = asyncio.Queue()

        # Define routes
        @self.app.get("/", response_class=HTMLResponse)
        async def dashboard_home():
            index_path = self.dashboard_dir / "index.html"
            if not index_path.exists():
                return HTMLResponse("<h1>CryptoWarden dashboard files were not found.</h1>", status_code=404)
            return HTMLResponse(
                index_path.read_text(encoding="utf-8"),
                headers={"Cache-Control": "no-store"}
            )

        @self.app.get("/ws")
        async def websocket_help():
            return PlainTextResponse(f"CryptoWarden dashboard WebSocket endpoint. Open http://{self.host}:{self.port}/ in your browser.")

        @self.app.websocket("/ws")
        async def websocket_endpoint(websocket: WebSocket):
            if self.auth_token and websocket.query_params.get("token") != self.auth_token:
                await websocket.close(code=1008)
                logger.warning("Rejected dashboard WebSocket connection with invalid token")
                return

            await websocket.accept()
            self.active_connections.add(websocket)
            logger.info(f"Dashboard connected. Active sessions: {len(self.active_connections)}")
            try:
                while True:
                    # Receive commands from dashboard
                    data = await websocket.receive_text()
                    try:
                        cmd = json.loads(data)
                        is_valid, reason = self._validate_command(cmd)
                        if is_valid:
                            await self.command_queue.put(cmd)
                            logger.info(f"Received command from dashboard: {cmd.get('command')}")
                        else:
                            await websocket.send_text(json.dumps({
                                "type": "command_error",
                                "data": {"reason": reason}
                            }))
                            logger.warning(f"Rejected dashboard command: {reason}")
                    except json.JSONDecodeError:
                        logger.warning("Received invalid JSON from dashboard")
            except WebSocketDisconnect:
                self.active_connections.discard(websocket)
                logger.info(f"Dashboard disconnected. Active sessions: {len(self.active_connections)}")
            except Exception as e:
                logger.error(f"WebSocket error: {e}")
                self.active_connections.discard(websocket)

        if self.dashboard_dir.exists():
            self.app.mount("/", StaticFiles(directory=self.dashboard_dir), name="dashboard")
        else:
            logger.warning(f"Dashboard directory not found: {self.dashboard_dir}")

    def _validate_command(self, cmd):
        if not isinstance(cmd, dict):
            return False, "Command payload must be an object"

        command = cmd.get("command")
        if command == "kill":
            try:
                pid = int(cmd.get("pid"))
            except (TypeError, ValueError):
                return False, "Kill command requires an integer pid"
            if pid <= 0:
                return False, "Kill command pid must be positive"
            cmd["pid"] = pid
            return True, None

        if command == "whitelist":
            process_name = str(cmd.get("process_name") or "").strip()
            if not process_name:
                return False, "Whitelist command requires process_name"
            cmd["process_name"] = process_name
            return True, None

        return False, f"Unknown dashboard command: {command}"

    async def start(self):
        """Starts the FastAPI server in the background."""
        config = uvicorn.Config(self.app, host=self.host, port=self.port, log_level="info")
        server = uvicorn.Server(config)
        self.server_task = asyncio.create_task(server.serve())
        logger.info(f"Dashboard Bridge started at ws://{self.host}:{self.port}/ws")

    async def stop(self):
        if self.server_task:
            self.server_task.cancel()
            try:
                await self.server_task
            except asyncio.CancelledError:
                pass

    async def broadcast(self, data: dict):
        """Sends data to all connected dashboard clients."""
        if not self.active_connections:
            return

        message = json.dumps(data)
        # Copy list for iteration to avoid race conditions
        targets = list(self.active_connections)
        disconnected = []
        
        for connection in targets:
            try:
                await connection.send_text(message)
            except Exception:
                disconnected.append(connection)

        for conn in disconnected:
            self.active_connections.discard(conn)

    async def send_activity(self, event):
        await self.broadcast({
            "type": "activity",
            "data": event
        })

    async def send_alert(self, pid, name, reason):
        await self.broadcast({
            "type": "alert",
            "data": {
                "pid": pid,
                "name": name,
                "reason": reason,
                "timestamp": asyncio.get_event_loop().time()
            }
        })

    async def send_stats(self, stats):
        await self.broadcast({
            "type": "stats",
            "data": stats
        })
