"""WebSocket connection manager for broadcasting events and risk scores."""

import asyncio
import json
from datetime import datetime
from typing import Any
from fastapi import WebSocket


class ConnectionManager:
    """Manages active WebSocket connections and broadcasts messages to all clients."""

    def __init__(self) -> None:
        self._event_connections: list[WebSocket] = []
        self._risk_connections: list[WebSocket] = []
        self._lock = asyncio.Lock()

    async def connect_events(self, websocket: WebSocket) -> None:
        """Accept and register a new event-stream WebSocket connection."""
        await websocket.accept()
        async with self._lock:
            self._event_connections.append(websocket)

    async def connect_risk(self, websocket: WebSocket) -> None:
        """Accept and register a new risk-score WebSocket connection."""
        await websocket.accept()
        async with self._lock:
            self._risk_connections.append(websocket)

    def disconnect_events(self, websocket: WebSocket) -> None:
        """Remove a disconnected event-stream WebSocket."""
        if websocket in self._event_connections:
            self._event_connections.remove(websocket)

    def disconnect_risk(self, websocket: WebSocket) -> None:
        """Remove a disconnected risk-score WebSocket."""
        if websocket in self._risk_connections:
            self._risk_connections.remove(websocket)

    async def broadcast_event(self, payload: dict[str, Any]) -> None:
        """Broadcast an audit log event to all connected event-stream clients."""
        message = json.dumps({"type": "audit_event", "data": payload, "ts": datetime.utcnow().isoformat()})
        await self._broadcast(self._event_connections, message, self.disconnect_events)

    async def broadcast_alert(self, payload: dict[str, Any]) -> None:
        """Broadcast a new security alert to all connected event-stream clients."""
        message = json.dumps({"type": "alert", "data": payload, "ts": datetime.utcnow().isoformat()})
        await self._broadcast(self._event_connections, message, self.disconnect_events)

    async def broadcast_risk(self, score: float) -> None:
        """Broadcast a risk score update to all connected risk WebSocket clients."""
        message = json.dumps({"type": "risk_update", "score": score, "ts": datetime.utcnow().isoformat()})
        await self._broadcast(self._risk_connections, message, self.disconnect_risk)

    async def _broadcast(
        self,
        connections: list[WebSocket],
        message: str,
        disconnect_fn,
    ) -> None:
        """Send a message to all connections, silently dropping stale ones."""
        dead: list[WebSocket] = []
        for ws in list(connections):
            try:
                await ws.send_text(message)
            except Exception:
                dead.append(ws)
        for ws in dead:
            disconnect_fn(ws)


# Singleton used across the application
manager = ConnectionManager()
