from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING, Concatenate, ParamSpec, Protocol, TypeAlias, TypeVar
from urllib.parse import urlsplit, urlunsplit

if TYPE_CHECKING:
    from redis import Redis

OperationParams = ParamSpec("OperationParams")
OperationResult = TypeVar("OperationResult")

RedisValue: TypeAlias = str | bytes | int | float

RedisOperation: TypeAlias = Callable[
    Concatenate["Redis", OperationParams], OperationResult
]

NO_OPERATION_RESULT = "the Redis operation returned no result"


def as_stored_value(value: str | None) -> str | bytes | None:
    """A ``get_key`` reply as the backend stored it: a client that does not
    decode replies hands back bytes although the protocol declares text."""
    return value


class EventSink(Protocol):
    def send_event(self, event: object) -> None: ...


def _unparseable_redis_url(url: str, scheme: str = "") -> str:
    scheme = scheme or url.partition("://")[0]
    return f"{scheme}://<unparseable>" if scheme and "://" in url else "<unparseable>"


_CREDENTIAL_QUERY_KEYS = frozenset({"password", "username"})


def _without_credential_params(query: str) -> str:
    """redis-py reads ``?password=`` and ``?username=`` like userinfo, so they go
    with it; every other parameter stays as written."""
    kept = [
        part
        for part in query.split("&")
        if part.partition("=")[0].lower() not in _CREDENTIAL_QUERY_KEYS
    ]
    return "&".join(kept)


def _redact_redis_url(url: str | None) -> str | None:
    if url is None:
        return None
    try:
        parts = urlsplit(url)
    except ValueError:
        return _unparseable_redis_url(url)
    if not parts.netloc:
        # a socket URL (unix:///path) has no netloc; its query can carry the password
        if not parts.query:
            return url
        kept = _without_credential_params(parts.query)
        return url.replace(f"?{parts.query}", f"?{kept}" if kept else "", 1)
    try:
        host = parts.hostname or ""
        port = parts.port
    except ValueError:
        return _unparseable_redis_url(url, parts.scheme)
    netloc = f"[{host}]" if ":" in host else host
    if port is not None:
        netloc = f"{netloc}:{port}"
    return urlunsplit(
        (
            parts.scheme,
            netloc,
            parts.path,
            _without_credential_params(parts.query),
            parts.fragment,
        )
    )
