import os
import json
import redis.asyncio as redis


class RedisClient:
    def __init__(
        self,
        host: str | None = None,
        port: int | None = None,
        db: int = 0,
        decode_responses: bool = True,
    ):
        configured_host = host or os.getenv("REDIS_HOST")
        if not configured_host:
            raise ValueError(
                "REDIS_HOST environment variable is not set. "
                "Set it to your Redis server address (e.g. redis, localhost:6379)."
            )
        self.host = configured_host
        port = port if port is not None else int(os.getenv("REDIS_PORT", "6379"))
        password = os.getenv("REDIS_PASSWORD") or None

        self.redis = redis.Redis(
            host=self.host,
            port=port,
            password=password,
            db=db,
            decode_responses=decode_responses,
            socket_connect_timeout=2,
            socket_timeout=2,
        )
        self.port = port
        self.db = db
        self.decode_responses = decode_responses

    def _build_client(self, host: str):
        return redis.Redis(
            host=host,
            port=self.port,
            password=os.getenv("REDIS_PASSWORD") or None,
            db=self.db,
            decode_responses=self.decode_responses,
        )

    async def _execute_with_fallback(self, operation, *args, **kwargs):
        try:
            return await operation(self.redis, *args, **kwargs)
        except Exception:
            raise

    async def PushToQueue(self, queue_name: str = "scan_queue", data: dict = {}):
        await self._execute_with_fallback(lambda client, *_args, **_kwargs: client.lpush(queue_name, json.dumps(data)))

    async def PopFromQueue(self, queue_name: str = "scan_queue"):
        return await self._execute_with_fallback(lambda client, *_args, **_kwargs: client.brpop(queue_name))


redis_client = RedisClient()