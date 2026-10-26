import json
import time

from guard_core.protocols.redis_protocol import RedisHandlerProtocol


class InMemoryCloudIpStore:
    def __init__(self) -> None:
        self._data: dict[str, set[str]] = {}
        self._expires_at: dict[str, float] = {}

    async def get(self, provider: str) -> set[str] | None:
        expires_at = self._expires_at.get(provider)
        if expires_at is not None and time.monotonic() >= expires_at:
            self._data.pop(provider, None)
            self._expires_at.pop(provider, None)
            return None
        ranges = self._data.get(provider)
        if ranges is None:
            return None
        return set(ranges)

    async def set(
        self, provider: str, ranges: set[str], ttl: int | None = None
    ) -> None:
        self._data[provider] = set(ranges)
        if ttl is None:
            self._expires_at.pop(provider, None)
        else:
            self._expires_at[provider] = time.monotonic() + ttl

    async def clear(self) -> None:
        self._data.clear()
        self._expires_at.clear()


class RedisCloudIpStore:
    def __init__(
        self,
        redis_handler: RedisHandlerProtocol,
        key_prefix: str = "cloud_ip_v2",
    ) -> None:
        self._redis = redis_handler
        self._prefix = key_prefix

    async def get(self, provider: str) -> set[str] | None:
        raw: str | bytes | None = await self._redis.get_key(self._prefix, provider)
        if raw is None:
            return None
        try:
            decoded = json.loads(raw)
        except (TypeError, json.JSONDecodeError):
            return None
        if not isinstance(decoded, list):
            return None
        return {str(item) for item in decoded}

    async def set(
        self, provider: str, ranges: set[str], ttl: int | None = None
    ) -> None:
        payload = json.dumps(sorted(ranges))
        await self._redis.set_key(self._prefix, provider, payload, ttl=ttl)

    async def clear(self) -> None:
        keys: list[str] | None = await self._redis.keys(f"{self._prefix}:*")
        if not keys:
            return
        for key in keys:
            _, _, provider = key.partition(f"{self._prefix}:")
            if provider:
                await self._redis.delete(self._prefix, provider)
