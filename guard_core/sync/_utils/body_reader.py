import logging
import re
import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from typing import TYPE_CHECKING, Protocol, cast, runtime_checkable
from weakref import WeakKeyDictionary

from guard_core.exceptions import (
    BodyReadFailedError,
    BodyReadSlotsExhaustedError,
    BodyReadStalledError,
)
from guard_core.sync.protocols.request_protocol import SyncGuardRequest

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


def _resolve_body_reader_kind(request: SyncGuardRequest) -> str:
    adapter = type(request).__name__
    if isinstance(request, _IdleBoundedBodyReader):
        return _PREFIX_UNTIL_IDLE
    if isinstance(request, _BoundedBodyReader):
        logger.warning(
            "%s has no read_body_prefix_until_idle; its read_body_prefix is "
            "read in full with no idle deadline, so a client that stops sending "
            "holds the request until the server's own timeout",
            adapter,
        )
        return _PREFIX
    logger.warning(
        "%s has neither read_body_prefix_until_idle nor read_body_prefix; "
        "body() is read in full with no idle deadline, so a client that "
        "stops sending holds the request until the server's own timeout",
        adapter,
    )
    return _FULL_BODY


def _body_reader_kind(request: SyncGuardRequest) -> str:
    kind = _reader_kind_by_class.get(type(request))
    if kind is None:
        kind = _resolve_body_reader_kind(request)
        _reader_kind_by_class[type(request)] = kind
    return kind


def _body_reader_call(
    request: SyncGuardRequest, kind: str, max_bytes: int, idle_timeout: float
) -> Callable[[], bytes]:
    if kind == _PREFIX_UNTIL_IDLE:
        idle_reader = cast(_IdleBoundedBodyReader, request)
        return lambda: idle_reader.read_body_prefix_until_idle(max_bytes, idle_timeout)
    if kind == _PREFIX:
        prefix_reader = cast(_BoundedBodyReader, request)
        return lambda: prefix_reader.read_body_prefix(max_bytes)
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


def _straddle_overlap_bytes() -> int:
    from guard_core.sync.handlers.suspatterns_handler import sus_patterns_handler

    try:
        patterns = sus_patterns_handler.get_all_compiled_patterns()
    except Exception:
        return 0

    if not patterns:
        return 0

    longest = max(len(pattern.pattern) for pattern, _contexts, _category in patterns)
    return min(longest, _MAX_STRADDLE_OVERLAP_BYTES)


_CAPPED_BODY_PREFIX_STATE_ATTR = "_guard_capped_body_prefix_cache"


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


def _capped_body_fetch_size(max_bytes: int) -> int:
    return max_bytes + _straddle_overlap_bytes()


def _read_bounded_prefix(
    request: SyncGuardRequest,
    kind: str,
    max_bytes: int,
    timeout: float,
    max_concurrent: int | None,
) -> bytes | None:
    fetch_bytes = _capped_body_fetch_size(max_bytes)
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
) -> bytes | None:
    kind = _body_reader_kind(request)
    if kind == _FULL_BODY:
        return None

    return _read_bounded_prefix(request, kind, max_bytes, timeout, max_concurrent)


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


def _read_oversized_declared_body(
    request: SyncGuardRequest,
    max_bytes: int,
    timeout: float,
    max_concurrent: int | None,
    client_ip: str,
) -> bytes | None:
    kind = _body_reader_kind(request)
    if kind == _FULL_BODY:
        _warn_body_inspect_bytes_cap_reached_no_bounded_reader(max_bytes, client_ip)
        raise BodyReadFailedError(
            f"the body is past detection_max_body_inspect_bytes ({max_bytes}) "
            "and the adapter has no bounded reader, so it cannot be scanned"
        )

    _warn_body_inspect_bytes_cap_reached(max_bytes, client_ip)
    return _read_bounded_prefix(request, kind, max_bytes, timeout, max_concurrent)


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


def _read_capped_body_or_raise(
    request: SyncGuardRequest, config: "SecurityConfig | None", client_ip: str = ""
) -> bytes | None:
    if config is None:
        prefix = _read_under_slot(
            request.body, _DEFAULT_BODY_READ_TIMEOUT, _NO_CONFIG_MAX_CONCURRENT
        )
        return prefix if isinstance(prefix, bytes) else None

    max_bytes = config.detection_max_body_inspect_bytes
    timeout = config.body_read_timeout
    max_concurrent = config.sync_body_read_max_concurrent
    content_length = request.headers.get("content-length")

    if content_length is not None:
        parsed = _parse_content_length(content_length)
        if parsed is not None:
            if parsed > max_bytes:
                return _read_oversized_declared_body(
                    request, max_bytes, timeout, max_concurrent, client_ip
                )
            return _read_declared_body(request, max_bytes, timeout, max_concurrent)

    return _read_capped_body_prefix(request, max_bytes, timeout, max_concurrent)


def _read_capped_body(
    request: SyncGuardRequest, config: "SecurityConfig | None", client_ip: str = ""
) -> bytes | None:
    try:
        return _read_capped_body_or_raise(request, config, client_ip)
    except (BodyReadStalledError, BodyReadFailedError) as exc:
        logger.warning("%s; the body is treated as unavailable", exc)
        return None
