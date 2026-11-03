from collections.abc import Callable, Iterator
from unittest.mock import MagicMock


def fake_ban_redis(
    ban_value: str | None = None, version: str | None = None
) -> MagicMock:
    def scan_iter(*_args: object, **_kwargs: object) -> Iterator[str]:
        keys: list[str] = []
        if keys:
            yield keys[0]

    connection = MagicMock()
    connection.scan_iter = scan_iter
    connection.mget = MagicMock(return_value=[])
    redis = MagicMock()
    redis.config = MagicMock(redis_prefix="guard:")
    redis.get_key = MagicMock(return_value=version)
    redis.get_many = MagicMock(
        side_effect=lambda pairs: [ban_value] * (len(pairs) - 1) + [version]
    )
    redis.get_connection = MagicMock(
        return_value=MagicMock(
            __enter__=MagicMock(return_value=connection),
            __exit__=MagicMock(return_value=None),
        )
    )
    return redis


def scanning(*keys: str) -> Callable[..., Iterator[str]]:
    def scan_iter(*_args: object, **_kwargs: object) -> Iterator[str]:
        position = 0
        while position < len(keys):
            yield keys[position]
            position += 1

    return scan_iter


def pipeline_of(pipe: object) -> MagicMock:
    return MagicMock(
        return_value=MagicMock(
            __enter__=MagicMock(return_value=pipe),
            __exit__=MagicMock(return_value=None),
        )
    )


def redis_with_connection(connection: object) -> MagicMock:
    redis = MagicMock()
    redis.config = MagicMock(redis_prefix="guard:")
    redis.get_connection = MagicMock(
        return_value=MagicMock(
            __enter__=MagicMock(return_value=connection),
            __exit__=MagicMock(return_value=None),
        )
    )
    return redis
