import hashlib
import os

from fastapi import HTTPException, Request, WebSocket

from app.core.redis_queue import redis_client


def _client_identifier(request_or_websocket: Request | WebSocket) -> str:
    client = request_or_websocket.client
    return client.host if client else "unknown"


async def check_rate_limit(scope: str, identifier: str, limit: int, window_seconds: int) -> None:
    """Apply a Redis-backed fixed-window limit shared by all backend replicas."""
    digest = hashlib.sha256(identifier.encode("utf-8")).hexdigest()[:32]
    key = f"rate_limit:{scope}:{digest}"
    try:
        count = await redis_client.redis.incr(key)
        if count == 1:
            await redis_client.redis.expire(key, window_seconds)
    except Exception as exc:
        raise HTTPException(status_code=503, detail="Rate limiting service is unavailable") from exc

    if count > limit:
        raise HTTPException(status_code=429, detail="Too many requests. Please try again later.")


async def enforce_http_rate_limit(request: Request, scope: str, limit: int, window_seconds: int) -> None:
    await check_rate_limit(scope, _client_identifier(request), limit, window_seconds)


async def enforce_websocket_rate_limit(websocket: WebSocket, scope: str, limit: int, window_seconds: int) -> None:
    try:
        await check_rate_limit(scope, _client_identifier(websocket), limit, window_seconds)
    except HTTPException:
        await websocket.close(code=1013, reason="Too many connection attempts")
        raise


def allowed_websocket_origins() -> set[str]:
    raw = os.getenv("CORS_ORIGINS", "")
    return {origin.strip().rstrip("/") for origin in raw.split(",") if origin.strip()}
