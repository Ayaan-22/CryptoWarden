import asyncio
import websockets
import json
import sys

async def send_kill_command(pid):
    uri = "ws://127.0.0.1:8000/ws"
    print(f"Connecting to {uri} to kill PID {pid}...")
    try:
        async with websockets.connect(uri) as websocket:
            cmd = {
                "command": "kill",
                "pid": int(pid)
            }
            await websocket.send(json.dumps(cmd))
            print(f"Sent kill command for PID {pid}")
            # Wait a bit for response
            await asyncio.sleep(2)
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python tests/test_interactive.py <PID>")
    else:
        asyncio.run(send_kill_command(sys.argv[1]))
