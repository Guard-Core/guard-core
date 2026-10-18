from typing import Any
from unittest.mock import AsyncMock, MagicMock


def fake_ban_redis(ban_value: str | None = None, version: str | None = None) -> Any:
    async def scan_iter(*_args: Any, **_kwargs: Any) -> Any:
        keys: list[str] = []
        if keys:
            yield keys[0]

    connection = MagicMock()
    connection.scan_iter = scan_iter
    connection.mget = AsyncMock(return_value=[])
    redis = AsyncMock()
    redis.config = MagicMock(redis_prefix="guard:")
    redis.get_key = AsyncMock(return_value=version)
    redis.get_many = AsyncMock(
        side_effect=lambda pairs: [ban_value] * (len(pairs) - 1) + [version]
    )
    redis.get_connection = MagicMock(
        return_value=AsyncMock(
            __aenter__=AsyncMock(return_value=connection),
            __aexit__=AsyncMock(return_value=None),
        )
    )
    return redis
