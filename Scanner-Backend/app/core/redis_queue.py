import os
import json
import redis.asyncio as redis

redis_client = redis.Redis(
    host="redis",
    port=6379,
    decode_responses=True,
)

class RedisClient:
    def __init__(
        self,
        host: str | None = None,
        port: int | None = None,
        db: int = 0,
        decode_responses: bool = True,
    ):
        host = host or os.getenv("REDIS_HOST", "redis")
        port = port if port is not None else int(os.getenv("REDIS_PORT", "6379"))

        self.redis = redis.Redis(
            host=host,
            port=port,
            db=db,
            decode_responses=decode_responses,
        )

    async def PushToQueue(self, queue_name: str = "scan_queue", data: dict = {}):
        await self.redis.lpush(queue_name, json.dumps(data))

    async def PopFromQueue(self, queue_name: str = "scan_queue"):
        return await self.redis.brpop(queue_name)