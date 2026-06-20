# (●°u°●)​ 」 WebSocket Router
# Real-time scan progress via WebSocket~ >_<

import json
from fastapi import APIRouter, WebSocket, WebSocketDisconnect

router = APIRouter()


class WebSocketManager:
    """Manage WebSocket connections per scan"""

    def __init__(self):
        self._connections: dict[int, list[WebSocket]] = {}

    async def connect(self, scan_id: int, ws: WebSocket):
        await ws.accept()
        if scan_id not in self._connections:
            self._connections[scan_id] = []
        self._connections[scan_id].append(ws)

    def disconnect(self, scan_id: int, ws: WebSocket):
        if scan_id in self._connections:
            self._connections[scan_id].remove(ws)
            if not self._connections[scan_id]:
                del self._connections[scan_id]

    async def send(self, scan_id: int, data: dict):
        """Send message to all watchers of a scan"""
        if scan_id in self._connections:
            message = json.dumps(data)
            dead = []
            for ws in self._connections[scan_id]:
                try:
                    await ws.send_text(message)
                except Exception:
                    dead.append(ws)
            for ws in dead:
                self.disconnect(scan_id, ws)


@router.websocket("/ws/scan/{scan_id}")
async def scan_websocket(ws: WebSocket, scan_id: int):
    """WebSocket endpoint for real-time scan progress"""
    manager = ws.app.state.ws_manager

    # Send initial greeting
    await ws.accept()
    await ws.send_text(json.dumps({
        "type": "connected",
        "message": "(●°u°●)​ 」 Xiao Qi is connected! Watching scan...",
        "scan_id": scan_id,
    }))

    manager._connections.setdefault(scan_id, []).append(ws)

    try:
        while True:
            # Keep connection alive, receive pings
            data = await ws.receive_text()
            if data == "ping":
                await ws.send_text(json.dumps({"type": "pong", "message": "^ - ^"}))
    except WebSocketDisconnect:
        manager.disconnect(scan_id, ws)
    except Exception:
        manager.disconnect(scan_id, ws)
