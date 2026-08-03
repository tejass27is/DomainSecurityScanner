from fastapi import WebSocket
from collections import defaultdict
from typing import List
import logging

logger = logging.getLogger(__name__)


class WebSocketManager:
    """Manages WebSocket connections for real-time updates"""
    
    def __init__(self):
        # org_id → list of WebSocket connections
        self.connections: dict[str, List[WebSocket]] = defaultdict(list)

    async def connect(self, org_id: str, websocket: WebSocket):
        """Accept and register a WebSocket connection"""
        try:
            await websocket.accept()
            self.connections[org_id].append(websocket)
            logger.info(f"WebSocket connected: org_id={org_id}, total={len(self.connections[org_id])}")
        except Exception as e:
            logger.error(f"Error accepting WebSocket: {str(e)}")

    def disconnect(self, org_id: str, websocket: WebSocket):
        """Remove a WebSocket connection"""
        try:
            if org_id in self.connections:
                if websocket in self.connections[org_id]:
                    self.connections[org_id].remove(websocket)
                    logger.info(f"WebSocket disconnected: org_id={org_id}, remaining={len(self.connections[org_id])}")

                # Clean up empty lists
                if not self.connections[org_id]:
                    self.connections.pop(org_id, None)
        except Exception as e:
            logger.error(f"Error disconnecting WebSocket: {str(e)}")

    async def send(self, org_id: str, payload: dict):
        """Send a message to all connections for an org_id"""
        if org_id not in self.connections:
            logger.warning(f"No WebSocket connections for org_id={org_id}")
            return

        dead_connections = []

        for ws in self.connections[org_id]:
            try:
                await ws.send_json(payload)
            except Exception as e:
                logger.error(f"Error sending WebSocket message: {str(e)}")
                dead_connections.append(ws)

        # Cleanup broken sockets
        for ws in dead_connections:
            try:
                self.connections[org_id].remove(ws)
            except:
                pass


# ✅ IMPORTANT: Create the instance here, at module level
# This should be the ONLY thing exported from this module
ws_manager = WebSocketManager()
