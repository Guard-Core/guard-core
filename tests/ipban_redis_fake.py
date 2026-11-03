from collections.abc import AsyncIterator, Callable
from unittest.mock import AsyncMock, MagicMock


def fake_ban_redis(
    ban_value: str | None = None, version: str | None = None
) -> AsyncMock:
    async def scan_iter(*_args: object, **_kwargs: object) -> AsyncIterator[str]:
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


def scanning(*keys: str) -> Callable[..., AsyncIterator[str]]:
    async def scan_iter(*_args: object, **_kwargs: object) -> AsyncIterator[str]:
        position = 0
        while position < len(keys):
            yield keys[position]
            position += 1

    return scan_iter


def pipeline_of(pipe: object) -> MagicMock:
    return MagicMock(
        return_value=AsyncMock(
            __aenter__=AsyncMock(return_value=pipe),
            __aexit__=AsyncMock(return_value=None),
        )
    )


def redis_with_connection(connection: object) -> AsyncMock:
    redis = AsyncMock()
    redis.config = MagicMock(redis_prefix="guard:")
    redis.get_connection = MagicMock(
        return_value=AsyncMock(
            __aenter__=AsyncMock(return_value=connection),
            __aexit__=AsyncMock(return_value=None),
        )
    )
    return redis
