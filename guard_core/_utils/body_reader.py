import asyncio
import logging
import re
from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING, Protocol, runtime_checkable

from guard_core.protocols.request_protocol import GuardRequest

if TYPE_CHECKING:
    from guard_core.models import SecurityConfig

logger = logging.getLogger("guard_core")

_CONTENT_LENGTH_RE = re.compile(r"[0-9]+")


def _parse_content_length(value: str) -> int | None:
    stripped = value.strip()
    if not _CONTENT_LENGTH_RE.fullmatch(stripped):
        return None
    parsed = int(stripped)
    return parsed if parsed > 0 else None


@runtime_checkable
class _BoundedBodyReader(Protocol):
    async def read_body_prefix(self, max_bytes: int) -> bytes: ...


_DEFAULT_BODY_READ_TIMEOUT = 3.0
_DEFAULT_BODY_READ_MAX_CONCURRENT = 64
_MAX_STRADDLE_OVERLAP_BYTES = 256


_BODY_READ_SLOT_POLL_SECONDS = 0.005
_body_read_slots: dict[int, list[None]] = {}


async def _safe_read(
    reader: Callable[[], Awaitable[bytes]],
    timeout: float,
    max_concurrent: int = _DEFAULT_BODY_READ_MAX_CONCURRENT,
) -> bytes | None:
    deadline = asyncio.get_running_loop().time() + timeout
    slots = _body_read_slots.setdefault(max_concurrent, [])
    while len(slots) >= max_concurrent:
        if asyncio.get_running_loop().time() >= deadline:
            logger.warning(
                "Body read concurrency limit reached (max_concurrent=%d); "
                "treating the body as unavailable for detection",
                max_concurrent,
            )
            return None
        await asyncio.sleep(_BODY_READ_SLOT_POLL_SECONDS)
    slots.append(None)
    try:
        remaining = max(deadline - asyncio.get_running_loop().time(), 0.0)
        return await asyncio.wait_for(reader(), timeout=remaining)
    except Exception:
        return None
    finally:
        slots.pop()


async def _straddle_overlap_bytes() -> int:
    from guard_core.handlers.suspatterns_handler import sus_patterns_handler

    try:
        patterns = await sus_patterns_handler.get_all_compiled_patterns()
    except Exception:
        return 0

    if not patterns:
        return 0

    longest = max(len(pattern.pattern) for pattern, _contexts, _category in patterns)
    return min(longest, _MAX_STRADDLE_OVERLAP_BYTES)


_CAPPED_BODY_PREFIX_STATE_ATTR = "_guard_capped_body_prefix_cache"


async def _read_and_cache_body(
    request: GuardRequest,
    max_bytes: int,
    timeout: float,
    reader: Callable[[], Awaitable[bytes]],
    accessor: str,
    max_concurrent: int,
) -> bytes | None:
    cached = getattr(request.state, _CAPPED_BODY_PREFIX_STATE_ATTR, None)
    if cached is not None and cached[0] is request and cached[1] >= max_bytes:
        cached_bytes: bytes = cached[2]
        return cached_bytes[:max_bytes]

    prefix: object = await _safe_read(reader, timeout, max_concurrent)
    if prefix is None:
        return None

    if not isinstance(prefix, bytes):
        logger.warning(
            "%s.%s returned %s, not bytes; treating the "
            "body as unavailable for detection",
            type(request).__name__,
            accessor,
            type(prefix).__name__,
        )
        return None

    capped = prefix[:max_bytes]
    setattr(request.state, _CAPPED_BODY_PREFIX_STATE_ATTR, (request, max_bytes, capped))
    return capped


async def _capped_body_fetch_size(max_bytes: int) -> int:
    return max_bytes + await _straddle_overlap_bytes()


async def _read_capped_body_prefix(
    request: GuardRequest, max_bytes: int, timeout: float, max_concurrent: int
) -> bytes | None:
    if not isinstance(request, _BoundedBodyReader):
        return None

    fetch_bytes = await _capped_body_fetch_size(max_bytes)
    return await _read_and_cache_body(
        request,
        fetch_bytes,
        timeout,
        lambda: request.read_body_prefix(fetch_bytes),
        "read_body_prefix",
        max_concurrent,
    )


def _warn_body_inspect_bytes_cap_reached(max_bytes: int, client_ip: str) -> None:
    logger.warning(
        "detection_max_body_inspect_bytes (%d) reached for client %s; only the "
        "first %d bytes of the request body are scanned",
        max_bytes,
        client_ip,
        max_bytes,
    )


def _warn_body_inspect_bytes_cap_reached_no_bounded_reader(
    max_bytes: int, client_ip: str
) -> None:
    logger.warning(
        "detection_max_body_inspect_bytes (%d) reached for client %s; the "
        "request body is not read because the adapter does not implement a "
        "bounded reader (read_body_prefix)",
        max_bytes,
        client_ip,
    )


async def _read_oversized_declared_body(
    request: GuardRequest,
    max_bytes: int,
    timeout: float,
    max_concurrent: int,
    client_ip: str,
) -> bytes | None:
    if not isinstance(request, _BoundedBodyReader):
        _warn_body_inspect_bytes_cap_reached_no_bounded_reader(max_bytes, client_ip)
        return None

    _warn_body_inspect_bytes_cap_reached(max_bytes, client_ip)
    fetch_bytes = await _capped_body_fetch_size(max_bytes)
    return await _read_and_cache_body(
        request,
        fetch_bytes,
        timeout,
        lambda: request.read_body_prefix(fetch_bytes),
        "read_body_prefix",
        max_concurrent,
    )


async def _read_capped_body(
    request: GuardRequest, config: "SecurityConfig | None", client_ip: str = ""
) -> bytes | None:
    if config is None:
        return await _safe_read(
            request.body, _DEFAULT_BODY_READ_TIMEOUT, _DEFAULT_BODY_READ_MAX_CONCURRENT
        )

    max_bytes = config.detection_max_body_inspect_bytes
    timeout = config.body_read_timeout
    max_concurrent = config.sync_body_read_max_concurrent
    content_length = request.headers.get("content-length")

    if content_length is not None:
        parsed = _parse_content_length(content_length)
        if parsed is not None:
            if parsed > max_bytes:
                return await _read_oversized_declared_body(
                    request, max_bytes, timeout, max_concurrent, client_ip
                )
            return await _read_and_cache_body(
                request, max_bytes, timeout, request.body, "body", max_concurrent
            )

    return await _read_capped_body_prefix(request, max_bytes, timeout, max_concurrent)
