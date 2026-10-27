import asyncio
import logging
import re
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from typing import TYPE_CHECKING, Protocol, runtime_checkable
from weakref import WeakKeyDictionary

from guard_core._utils.capability import has_callable, serves_attributes_dynamically
from guard_core.exceptions import (
    BodyReadFailedError,
    BodyReadSlotsExhaustedError,
    BodyReadStalledError,
)
from guard_core.protocols.request_protocol import GuardRequest, GuardRequestHeaders

if TYPE_CHECKING:
    from guard_core.decorators.base import RouteConfig
    from guard_core.handlers.suspatterns_handler import SusPatternsManager
    from guard_core.models import SecurityConfig

logger = logging.getLogger("guard_core")

_CONTENT_LENGTH_RE = re.compile(r"[0-9]+")


def _parse_content_length(value: str) -> int | None:
    return parse_declared_length(value) or None


def parse_declared_length(value: str) -> int | None:
    stripped = value.strip()
    return int(stripped) if _CONTENT_LENGTH_RE.fullmatch(stripped) else None


def request_declares_body(headers: GuardRequestHeaders) -> bool:
    if headers.get("transfer-encoding"):
        return True
    content_length = headers.get("content-length")
    if content_length is None:
        return False
    return parse_declared_length(content_length) != 0


@runtime_checkable
class _BoundedBodyReader(Protocol):
    async def read_body_prefix(self, max_bytes: int) -> bytes: ...


@runtime_checkable
class _IdleBoundedBodyReader(Protocol):
    async def read_body_prefix_until_idle(
        self, max_bytes: int, idle_timeout: float
    ) -> bytes: ...


_DEFAULT_BODY_READ_TIMEOUT = 3.0
_DEFAULT_BODY_READ_MAX_CONCURRENT = 64
_MAX_STRADDLE_OVERLAP_BYTES = 256


_BODY_READ_SLOT_POLL_SECONDS = 0.005
_NO_CONFIG_MAX_CONCURRENT: int | None = None
_body_read_slots: dict[int, list[None]] = {}


@asynccontextmanager
async def _body_read_slot(
    max_concurrent: int | None, timeout: float
) -> AsyncIterator[None]:
    if max_concurrent is None:
        yield
        return
    deadline = asyncio.get_running_loop().time() + timeout
    slots = _body_read_slots.setdefault(max_concurrent, [])
    while len(slots) >= max_concurrent:
        if asyncio.get_running_loop().time() >= deadline:
            logger.warning(
                "Body read concurrency limit reached (max_concurrent=%d); "
                "treating the body as unavailable for detection",
                max_concurrent,
            )
            raise BodyReadSlotsExhaustedError(max_concurrent)
        await asyncio.sleep(_BODY_READ_SLOT_POLL_SECONDS)
    slots.append(None)
    try:
        yield
    finally:
        slots.pop()


async def _safe_read(
    reader: Callable[[], Awaitable[bytes]],
    timeout: float,
    max_concurrent: int | None = None,
) -> bytes | None:
    deadline = asyncio.get_running_loop().time() + timeout
    try:
        async with _body_read_slot(max_concurrent, timeout):
            remaining = max(deadline - asyncio.get_running_loop().time(), 0.0)
            return await asyncio.wait_for(reader(), timeout=remaining)
    except Exception:
        return None


_PREFIX_UNTIL_IDLE = "read_body_prefix_until_idle"
_PREFIX = "read_body_prefix"
_FULL_BODY = "body"

_reader_kind_by_class: WeakKeyDictionary[type, str] = WeakKeyDictionary()
_fallback_warned_kinds: WeakKeyDictionary[type, set[str]] = WeakKeyDictionary()


def _first_fallback_of_kind(request: GuardRequest, kind: str) -> bool:
    warned = _fallback_warned_kinds.setdefault(type(request), set())
    first = kind not in warned
    warned.add(kind)
    return first


def _resolve_body_reader_kind(request: GuardRequest) -> str:
    adapter = type(request).__name__
    if has_callable(request, _PREFIX_UNTIL_IDLE):
        return _PREFIX_UNTIL_IDLE
    if has_callable(request, _PREFIX):
        if _first_fallback_of_kind(request, _PREFIX):
            logger.warning(
                "%s has no read_body_prefix_until_idle; its read_body_prefix is "
                "read in full with no idle deadline, so a client that stops "
                "sending holds the request until the server's own timeout",
                adapter,
            )
        return _PREFIX
    if _first_fallback_of_kind(request, _FULL_BODY):
        logger.warning(
            "%s has neither read_body_prefix_until_idle nor read_body_prefix; "
            "body() is read in full with no idle deadline, so a client that "
            "stops sending holds the request until the server's own timeout",
            adapter,
        )
    return _FULL_BODY


def _body_reader_kind(request: GuardRequest) -> str:
    cls = type(request)
    kind = _reader_kind_by_class.get(cls)
    if kind is None:
        kind = _resolve_body_reader_kind(request)
        if not serves_attributes_dynamically(cls):
            _reader_kind_by_class[cls] = kind
    return kind


def _body_reader_call(
    request: GuardRequest, kind: str, max_bytes: int, idle_timeout: float
) -> Callable[[], Awaitable[bytes]]:
    if kind == _PREFIX_UNTIL_IDLE:
        idle_reader: Callable[[int, float], Awaitable[bytes]] = getattr(
            request, _PREFIX_UNTIL_IDLE
        )
        return lambda: idle_reader(max_bytes, idle_timeout)
    if kind == _PREFIX:
        prefix_reader: Callable[[int], Awaitable[bytes]] = getattr(request, _PREFIX)
        return lambda: prefix_reader(max_bytes)
    return request.body


async def _read_under_slot(
    reader: Callable[[], Awaitable[bytes]],
    timeout: float,
    max_concurrent: int | None,
) -> object:
    async with _body_read_slot(max_concurrent, timeout):
        try:
            return await reader()
        except (BodyReadStalledError, BodyReadFailedError):
            raise
        except Exception as exc:
            raise BodyReadFailedError(
                f"the adapter's body read raised {type(exc).__name__}"
            ) from exc


async def _straddle_overlap_bytes(
    *, patterns: "SusPatternsManager | None" = None
) -> int:
    from guard_core.handlers.suspatterns_handler import active_sus_patterns

    try:
        compiled = await (
            patterns if patterns is not None else active_sus_patterns()
        ).get_all_compiled_patterns()
    except Exception:
        return 0

    if not compiled:
        return 0

    longest = max(len(pattern.pattern) for pattern, _contexts, _category in compiled)
    return min(longest, _MAX_STRADDLE_OVERLAP_BYTES)


_CAPPED_BODY_PREFIX_STATE_ATTR = "_guard_capped_body_prefix_cache"
_FAILED_LIMIT_READ_STATE_ATTR = "_guard_failed_limit_read"


async def _read_and_cache_body(
    request: GuardRequest,
    max_bytes: int,
    timeout: float,
    reader: Callable[[], Awaitable[bytes]],
    accessor: str,
    max_concurrent: int | None,
) -> bytes | None:
    cached = getattr(request.state, _CAPPED_BODY_PREFIX_STATE_ATTR, None)
    if cached is not None and cached[0] is request and cached[1] >= max_bytes:
        cached_bytes: bytes = cached[2]
        return cached_bytes[:max_bytes]

    prefix = await _read_under_slot(reader, timeout, max_concurrent)

    if not isinstance(prefix, bytes):
        logger.warning(
            "%s.%s returned %s, not bytes; treating the body as unavailable "
            "for detection",
            type(request).__name__,
            accessor,
            type(prefix).__name__,
        )
        raise BodyReadFailedError(
            f"the adapter's body read returned {type(prefix).__name__}, not bytes"
        )

    capped = prefix[:max_bytes]
    setattr(request.state, _CAPPED_BODY_PREFIX_STATE_ATTR, (request, max_bytes, capped))
    return capped


async def _capped_body_fetch_size(
    max_bytes: int, *, patterns: "SusPatternsManager | None" = None
) -> int:
    return max_bytes + max(await _straddle_overlap_bytes(patterns=patterns), 1)


async def _read_bounded_prefix(
    request: GuardRequest,
    kind: str,
    max_bytes: int,
    timeout: float,
    max_concurrent: int | None,
    *,
    patterns: "SusPatternsManager | None" = None,
) -> bytes | None:
    fetch_bytes = await _capped_body_fetch_size(max_bytes, patterns=patterns)
    return await _read_and_cache_body(
        request,
        fetch_bytes,
        timeout,
        _body_reader_call(request, kind, fetch_bytes, timeout),
        kind,
        max_concurrent,
    )


async def _read_capped_body_prefix(
    request: GuardRequest,
    max_bytes: int,
    timeout: float,
    max_concurrent: int | None,
    *,
    patterns: "SusPatternsManager | None" = None,
) -> bytes | None:
    kind = _body_reader_kind(request)
    if kind == _FULL_BODY:
        return None

    return await _read_bounded_prefix(
        request, kind, max_bytes, timeout, max_concurrent, patterns=patterns
    )


def inspect_limit_fix_hint(content_type: str | None) -> str:
    field = (
        "detection_max_file_inspect_bytes"
        if _is_multipart(content_type)
        else "detection_max_body_inspect_bytes"
    )
    return f"raise {field}, or max_request_size on the route"


def _warn_body_inspect_bytes_cap_reached(
    max_bytes: int, client_ip: str, content_type: str | None
) -> None:
    logger.warning(
        "detection_max_body_inspect_bytes (%d) reached for client %s; only the "
        "first %d bytes of the request body are scanned and the request gets "
        "the body-read failure outcome (%s)",
        max_bytes,
        client_ip,
        max_bytes,
        inspect_limit_fix_hint(content_type),
    )


def _warn_body_inspect_bytes_cap_reached_no_bounded_reader(
    max_bytes: int, client_ip: str, content_type: str | None
) -> None:
    logger.warning(
        "detection_max_body_inspect_bytes (%d) reached for client %s; the "
        "request body is not read because the adapter does not implement a "
        "bounded reader (read_body_prefix) (%s)",
        max_bytes,
        client_ip,
        inspect_limit_fix_hint(content_type),
    )


async def _read_oversized_declared_body(
    request: GuardRequest,
    max_bytes: int,
    timeout: float,
    max_concurrent: int | None,
    client_ip: str,
    *,
    patterns: "SusPatternsManager | None" = None,
) -> bytes | None:
    kind = _body_reader_kind(request)
    content_type = request.headers.get("content-type")
    if kind == _FULL_BODY:
        _warn_body_inspect_bytes_cap_reached_no_bounded_reader(
            max_bytes, client_ip, content_type
        )
        raise BodyReadFailedError(
            f"the body is past detection_max_body_inspect_bytes ({max_bytes}) "
            "and the adapter has no bounded reader, so it cannot be scanned "
            f"({inspect_limit_fix_hint(content_type)})"
        )

    _warn_body_inspect_bytes_cap_reached(max_bytes, client_ip, content_type)
    return await _read_bounded_prefix(
        request, kind, max_bytes, timeout, max_concurrent, patterns=patterns
    )


async def _read_declared_body(
    request: GuardRequest,
    max_bytes: int,
    timeout: float,
    max_concurrent: int | None,
) -> bytes | None:
    kind = _body_reader_kind(request)
    return await _read_and_cache_body(
        request,
        max_bytes,
        timeout,
        _body_reader_call(request, kind, max_bytes, timeout),
        kind,
        max_concurrent,
    )


def _is_multipart(content_type: str | None) -> bool:
    media_type = (content_type or "").split(";", 1)[0]
    return media_type.strip().lower() == "multipart/form-data"


def resolve_inspect_cap(
    config: "SecurityConfig",
    route_config: "RouteConfig | None",
    content_type: str | None = None,
) -> int:
    cap = (
        config.detection_max_file_inspect_bytes
        if _is_multipart(content_type)
        else config.detection_max_body_inspect_bytes
    )
    if route_config is None or route_config.max_request_size is None:
        return cap
    return max(cap, route_config.max_request_size)


async def read_body_for_inspection(
    request: GuardRequest,
    config: "SecurityConfig",
    client_ip: str,
    max_bytes: int,
    *,
    patterns: "SusPatternsManager | None" = None,
) -> tuple[bytes | None, bool]:
    timeout = config.body_read_timeout
    max_concurrent = config.async_body_read_max_concurrent
    content_length = request.headers.get("content-length")

    if content_length is not None:
        parsed = _parse_content_length(content_length)
        if parsed is not None:
            if parsed > max_bytes:
                return (
                    await _read_oversized_declared_body(
                        request,
                        max_bytes,
                        timeout,
                        max_concurrent,
                        client_ip,
                        patterns=patterns,
                    ),
                    True,
                )
            return (
                await _read_declared_body(request, max_bytes, timeout, max_concurrent),
                False,
            )

    prefix = await _read_capped_body_prefix(
        request, max_bytes, timeout, max_concurrent, patterns=patterns
    )
    return prefix, prefix is not None and len(prefix) > max_bytes


async def _read_capped_body_or_raise(
    request: GuardRequest,
    config: "SecurityConfig | None",
    client_ip: str = "",
    *,
    patterns: "SusPatternsManager | None" = None,
) -> bytes | None:
    if config is None:
        prefix = await _read_under_slot(
            request.body, _DEFAULT_BODY_READ_TIMEOUT, _NO_CONFIG_MAX_CONCURRENT
        )
        return prefix if isinstance(prefix, bytes) else None

    body, _past_cap = await read_body_for_inspection(
        request,
        config,
        client_ip,
        config.detection_max_body_inspect_bytes,
        patterns=patterns,
    )
    return body


async def _read_capped_body(
    request: GuardRequest,
    config: "SecurityConfig | None",
    client_ip: str = "",
    *,
    patterns: "SusPatternsManager | None" = None,
) -> bytes | None:
    try:
        return await _read_capped_body_or_raise(
            request, config, client_ip, patterns=patterns
        )
    except (BodyReadStalledError, BodyReadFailedError) as exc:
        logger.warning("%s; the body is treated as unavailable", exc)
        return None


async def read_prefix_beyond_limit(
    request: GuardRequest, config: "SecurityConfig", limit: int
) -> bytes | None:
    failed = getattr(request.state, _FAILED_LIMIT_READ_STATE_ATTR, None)
    if failed is not None and failed[0] is request:
        raise failed[1]
    kind = _body_reader_kind(request)
    fetch_bytes = limit + 1
    try:
        return await _read_and_cache_body(
            request,
            fetch_bytes,
            config.body_read_timeout,
            _body_reader_call(request, kind, fetch_bytes, config.body_read_timeout),
            kind,
            config.async_body_read_max_concurrent,
        )
    except (BodyReadStalledError, BodyReadFailedError) as error:
        setattr(request.state, _FAILED_LIMIT_READ_STATE_ATTR, (request, error))
        raise
