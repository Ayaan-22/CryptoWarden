import asyncio
import json
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
import uvicorn
from src.utils.logger import logger

class DashboardBridge:
    def __init__(self, host="127.0.0.1", port=8000):
        self.app = FastAPI()
        self.host = host
        self.port = port
        self.active_connections = []
        self.server_task = None
        self.command_queue = asyncio.Queue()

        # Define routes
        @self.app.websocket("/ws")
        async def websocket_endpoint(websocket: WebSocket):
            await websocket.accept()
            self.active_connections.append(websocket)
            logger.info(f"Dashboard connected. Active sessions: {len(self.active_connections)}")
            try:
                while True:
                    # Receive commands from dashboard
                    data = await websocket.receive_text()
                    try:
                        cmd = json.loads(data)
                        await self.command_queue.put(cmd)
                        logger.info(f"Received command from dashboard: {cmd.get('command')}")
                    except json.JSONDecodeError:
                        logger.warning("Received invalid JSON from dashboard")
            except WebSocketDisconnect:
                self.active_connections.remove(websocket)
                logger.info(f"Dashboard disconnected. Active sessions: {len(self.active_connections)}")

    async def start(self):
        """Starts the FastAPI server in the background."""
        config = uvicorn.Config(self.app, host=self.host, port=self.port, log_level="error")
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
        disconnected = []
        for connection in self.active_connections:
            try:
                await connection.send_text(message)
            except Exception:
                disconnected.append(connection)

        for conn in disconnected:
            self.active_connections.remove(conn)

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
