from fastapi import FastAPI, WebSocket, WebSocketDisconnect
import uvicorn

app = FastAPI()
rooms: dict[str, set[WebSocket]] = {}

@app.websocket("/ws/{room_id}")
async def websocket_endpoint(websocket: WebSocket, room_id: str):
    await websocket.accept()
    print(f"✅ Client joined room: {room_id}")

    if room_id not in rooms:
        rooms[room_id] = set()
    rooms[room_id].add(websocket)

    try:
        while True:
            msg = await websocket.receive()

            # Handle binary or text messages
            if "bytes" in msg and msg["bytes"] is not None:
                data = msg["bytes"]
                kind = "binary"
            elif "text" in msg and msg["text"] is not None:
                data = msg["text"].encode()
                kind = "text"
            else:
                continue

            print(f"📩 {len(data)} bytes received ({kind}) in room {room_id}")

            # Broadcast to all peers in the same room (except sender)
            for peer in list(rooms[room_id]):
                if peer != websocket:
                    try:
                        await peer.send_bytes(data)
                    except Exception:
                        rooms[room_id].remove(peer)
    except WebSocketDisconnect:
        print(f"❌ Client disconnected from {room_id}")
        rooms[room_id].remove(websocket)
        if not rooms[room_id]:
            del rooms[room_id]

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
