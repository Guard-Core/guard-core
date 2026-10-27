from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING, Concatenate, ParamSpec, Protocol, TypeAlias, TypeVar
from urllib.parse import urlsplit, urlunsplit

if TYPE_CHECKING:
    from redis.asyncio import Redis

OperationParams = ParamSpec("OperationParams")
OperationResult = TypeVar("OperationResult")

RedisValue: TypeAlias = str | bytes | int | float

RedisOperation: TypeAlias = Callable[
    Concatenate["Redis", OperationParams], Awaitable[OperationResult]
]

NO_OPERATION_RESULT = "the Redis operation returned no result"


class EventSink(Protocol):
    async def send_event(self, event: object) -> None: ...


def _unparseable_redis_url(url: str, scheme: str = "") -> str:
    scheme = scheme or url.partition("://")[0]
    return f"{scheme}://<unparseable>" if scheme and "://" in url else "<unparseable>"


def _redact_redis_url(url: str | None) -> str | None:
    if url is None:
        return None
    try:
        parts = urlsplit(url)
    except ValueError:
        return _unparseable_redis_url(url)
    if not parts.netloc:
        return url
    try:
        host = parts.hostname or ""
        port = parts.port
    except ValueError:
        return _unparseable_redis_url(url, parts.scheme)
    netloc = f"[{host}]" if ":" in host else host
    if port is not None:
        netloc = f"{netloc}:{port}"
    return urlunsplit((parts.scheme, netloc, parts.path, parts.query, parts.fragment))
