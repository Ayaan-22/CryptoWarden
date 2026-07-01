import asyncio
import websockets
import json
import os

async def mock_dashboard():
    token = os.environ.get("CRYPTOWARDEN_DASHBOARD_TOKEN", "")
    suffix = f"?token={token}" if token else ""
    uri = f"ws://127.0.0.1:8001/ws{suffix}"
    print(f"Connecting to {uri}...")
    try:
        async with websockets.connect(uri) as websocket:
            print("Connected to Dashboard Bridge.")
            while True:
                message = await websocket.recv()
                data = json.loads(message)
                print(f"\n[DASHBOARD RECEIVE] Type: {data['type']}")
                print(json.dumps(data['data'], indent=2))
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    asyncio.run(mock_dashboard())
