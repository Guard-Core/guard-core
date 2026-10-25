import logging
import re
import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from typing import TYPE_CHECKING, Protocol, runtime_checkable
from weakref import WeakKeyDictionary

from guard_core.exceptions import (
    BodyReadFailedError,
    BodyReadSlotsExhaustedError,
    BodyReadStalledError,
)
from guard_core.protocols.request_protocol import GuardRequestHeaders
from guard_core.sync._utils.capability import (
    has_callable,
    serves_attributes_dynamically,
)
from guard_core.sync.protocols.request_protocol import SyncGuardRequest

if TYPE_CHECKING:
    from guard_core.models import SyncSecurityConfig
    from guard_core.sync.decorators.base import RouteConfig
    from guard_core.sync.handlers.suspatterns_handler import SusPatternsManager

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
    def read_body_prefix(self, max_bytes: int) -> bytes: ...


@runtime_checkable
class _IdleBoundedBodyReader(Protocol):
    def read_body_prefix_until_idle(
        self, max_bytes: int, idle_timeout: float
    ) -> bytes: ...


_DEFAULT_BODY_READ_TIMEOUT = 3.0
_DEFAULT_BODY_READ_MAX_CONCURRENT = 64
_MAX_STRADDLE_OVERLAP_BYTES = 256


_sync_body_read_semaphores: dict[int, threading.Semaphore] = {}
_sync_body_read_semaphores_lock = threading.Lock()
_NO_CONFIG_MAX_CONCURRENT: int | None = _DEFAULT_BODY_READ_MAX_CONCURRENT


def _sync_body_read_semaphore(max_concurrent: int) -> threading.Semaphore:
    with _sync_body_read_semaphores_lock:
        semaphore = _sync_body_read_semaphores.get(max_concurrent)
        if semaphore is None:
            semaphore = threading.Semaphore(max_concurrent)
            _sync_body_read_semaphores[max_concurrent] = semaphore
        return semaphore


@contextmanager
def _body_read_slot(max_concurrent: int | None, timeout: float) -> Iterator[None]:
    if max_concurrent is None:
        yield
        return
    semaphore = _sync_body_read_semaphore(max_concurrent)
    if not semaphore.acquire(timeout=max(timeout, 0.0)):
        logger.warning(
            "Sync body read concurrency limit reached (max_concurrent=%d); "
            "treating the body as unavailable for detection",
            max_concurrent,
        )
        raise BodyReadSlotsExhaustedError(max_concurrent)
    try:
        yield
    finally:
        semaphore.release()


def _safe_read(
    reader: Callable[[], bytes],
    timeout: float,
    max_concurrent: int | None = None,
) -> bytes | None:
    try:
        with _body_read_slot(max_concurrent, timeout):
            return reader()
    except Exception:
        return None


_PREFIX_UNTIL_IDLE = "read_body_prefix_until_idle"
_PREFIX = "read_body_prefix"
_FULL_BODY = "body"

_reader_kind_by_class: WeakKeyDictionary[type, str] = WeakKeyDictionary()
_fallback_warned_kinds: WeakKeyDictionary[type, set[str]] = WeakKeyDictionary()


def _first_fallback_of_kind(request: SyncGuardRequest, kind: str) -> bool:
    warned = _fallback_warned_kinds.setdefault(type(request), set())
    first = kind not in warned
    warned.add(kind)
    return first


def _resolve_body_reader_kind(request: SyncGuardRequest) -> str:
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


def _body_reader_kind(request: SyncGuardRequest) -> str:
    cls = type(request)
    kind = _reader_kind_by_class.get(cls)
    if kind is None:
        kind = _resolve_body_reader_kind(request)
        if not serves_attributes_dynamically(cls):
            _reader_kind_by_class[cls] = kind
    return kind


def _body_reader_call(
    request: SyncGuardRequest, kind: str, max_bytes: int, idle_timeout: float
) -> Callable[[], bytes]:
    if kind == _PREFIX_UNTIL_IDLE:
        idle_reader: Callable[[int, float], bytes] = getattr(
            request, _PREFIX_UNTIL_IDLE
        )
        return lambda: idle_reader(max_bytes, idle_timeout)
    if kind == _PREFIX:
        prefix_reader: Callable[[int], bytes] = getattr(request, _PREFIX)
        return lambda: prefix_reader(max_bytes)
    return request.body


def _read_under_slot(
    reader: Callable[[], bytes],
    timeout: float,
    max_concurrent: int | None,
) -> object:
    with _body_read_slot(max_concurrent, timeout):
        try:
            return reader()
        except (BodyReadStalledError, BodyReadFailedError):
            raise
        except Exception as exc:
            raise BodyReadFailedError(
                f"the adapter's body read raised {type(exc).__name__}"
            ) from exc


def _straddle_overlap_bytes(*, patterns: "SusPatternsManager | None" = None) -> int:
    from guard_core.sync.handlers.suspatterns_handler import active_sus_patterns

    try:
        compiled = (
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


def _read_and_cache_body(
    request: SyncGuardRequest,
    max_bytes: int,
    timeout: float,
    reader: Callable[[], bytes],
    accessor: str,
    max_concurrent: int | None,
) -> bytes | None:
    cached = getattr(request.state, _CAPPED_BODY_PREFIX_STATE_ATTR, None)
    if cached is not None and cached[0] is request and cached[1] >= max_bytes:
        cached_bytes: bytes = cached[2]
        return cached_bytes[:max_bytes]

    prefix = _read_under_slot(reader, timeout, max_concurrent)

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


def _capped_body_fetch_size(
    max_bytes: int, *, patterns: "SusPatternsManager | None" = None
) -> int:
    return max_bytes + max(_straddle_overlap_bytes(patterns=patterns), 1)


def _read_bounded_prefix(
    request: SyncGuardRequest,
    kind: str,
    max_bytes: int,
    timeout: float,
    max_concurrent: int | None,
    *,
    patterns: "SusPatternsManager | None" = None,
) -> bytes | None:
    fetch_bytes = _capped_body_fetch_size(max_bytes, patterns=patterns)
    return _read_and_cache_body(
        request,
        fetch_bytes,
        timeout,
        _body_reader_call(request, kind, fetch_bytes, timeout),
        kind,
        max_concurrent,
    )


def _read_capped_body_prefix(
    request: SyncGuardRequest,
    max_bytes: int,
    timeout: float,
    max_concurrent: int | None,
    *,
    patterns: "SusPatternsManager | None" = None,
) -> bytes | None:
    kind = _body_reader_kind(request)
    if kind == _FULL_BODY:
        return None

    return _read_bounded_prefix(
        request, kind, max_bytes, timeout, max_concurrent, patterns=patterns
    )


def _warn_body_inspect_bytes_cap_reached(max_bytes: int, client_ip: str) -> None:
    logger.warning(
        "detection_max_body_inspect_bytes (%d) reached for client %s; only the "
        "first %d bytes of the request body are scanned and the request gets "
        "the body-read failure outcome",
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


def _read_oversized_declared_body(
    request: SyncGuardRequest,
    max_bytes: int,
    timeout: float,
    max_concurrent: int | None,
    client_ip: str,
    *,
    patterns: "SusPatternsManager | None" = None,
) -> bytes | None:
    kind = _body_reader_kind(request)
    if kind == _FULL_BODY:
        _warn_body_inspect_bytes_cap_reached_no_bounded_reader(max_bytes, client_ip)
        raise BodyReadFailedError(
            f"the body is past detection_max_body_inspect_bytes ({max_bytes}) "
            "and the adapter has no bounded reader, so it cannot be scanned"
        )

    _warn_body_inspect_bytes_cap_reached(max_bytes, client_ip)
    return _read_bounded_prefix(
        request, kind, max_bytes, timeout, max_concurrent, patterns=patterns
    )


def _read_declared_body(
    request: SyncGuardRequest,
    max_bytes: int,
    timeout: float,
    max_concurrent: int | None,
) -> bytes | None:
    kind = _body_reader_kind(request)
    return _read_and_cache_body(
        request,
        max_bytes,
        timeout,
        _body_reader_call(request, kind, max_bytes, timeout),
        kind,
        max_concurrent,
    )


def resolve_inspect_cap(
    config: "SyncSecurityConfig", route_config: "RouteConfig | None"
) -> int:
    cap = config.detection_max_body_inspect_bytes
    if route_config is None or route_config.max_request_size is None:
        return cap
    return max(cap, route_config.max_request_size)


def read_body_for_inspection(
    request: SyncGuardRequest,
    config: "SyncSecurityConfig",
    client_ip: str,
    max_bytes: int,
    *,
    patterns: "SusPatternsManager | None" = None,
) -> tuple[bytes | None, bool]:
    timeout = config.body_read_timeout
    max_concurrent = config.sync_body_read_max_concurrent
    content_length = request.headers.get("content-length")

    if content_length is not None:
        parsed = _parse_content_length(content_length)
        if parsed is not None:
            if parsed > max_bytes:
                return (
                    _read_oversized_declared_body(
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
                _read_declared_body(request, max_bytes, timeout, max_concurrent),
                False,
            )

    prefix = _read_capped_body_prefix(
        request, max_bytes, timeout, max_concurrent, patterns=patterns
    )
    return prefix, prefix is not None and len(prefix) > max_bytes


def _read_capped_body_or_raise(
    request: SyncGuardRequest,
    config: "SyncSecurityConfig | None",
    client_ip: str = "",
    *,
    patterns: "SusPatternsManager | None" = None,
) -> bytes | None:
    if config is None:
        prefix = _read_under_slot(
            request.body, _DEFAULT_BODY_READ_TIMEOUT, _NO_CONFIG_MAX_CONCURRENT
        )
        return prefix if isinstance(prefix, bytes) else None

    body, _past_cap = read_body_for_inspection(
        request,
        config,
        client_ip,
        config.detection_max_body_inspect_bytes,
        patterns=patterns,
    )
    return body


def _read_capped_body(
    request: SyncGuardRequest,
    config: "SyncSecurityConfig | None",
    client_ip: str = "",
    *,
    patterns: "SusPatternsManager | None" = None,
) -> bytes | None:
    try:
        return _read_capped_body_or_raise(request, config, client_ip, patterns=patterns)
    except (BodyReadStalledError, BodyReadFailedError) as exc:
        logger.warning("%s; the body is treated as unavailable", exc)
        return None


def read_prefix_beyond_limit(
    request: SyncGuardRequest, config: "SyncSecurityConfig", limit: int
) -> bytes | None:
    failed = getattr(request.state, _FAILED_LIMIT_READ_STATE_ATTR, None)
    if failed is not None and failed[0] is request:
        raise failed[1]
    kind = _body_reader_kind(request)
    fetch_bytes = limit + 1
    try:
        return _read_and_cache_body(
            request,
            fetch_bytes,
            config.body_read_timeout,
            _body_reader_call(request, kind, fetch_bytes, config.body_read_timeout),
            kind,
            config.sync_body_read_max_concurrent,
        )
    except (BodyReadStalledError, BodyReadFailedError) as error:
        setattr(request.state, _FAILED_LIMIT_READ_STATE_ATTR, (request, error))
        raise
