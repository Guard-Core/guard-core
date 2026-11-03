import logging
import re
import time
from collections.abc import Callable, Iterable, Iterator, MutableMapping
from enum import Enum
from typing import Final, ParamSpec, Protocol, TypeGuard, TypeVar

from guard_core._utils.agent_events import send_agent_event
from guard_core._utils.sampling import PerApp, RefusalReports
from guard_core.core.events.event_types import EVENT_RESPONSE_BODY_UNAVAILABLE
from guard_core.exceptions import ResponseBodyUnavailableError
from guard_core.models import SecurityConfig
from guard_core.protocols.agent_protocol import AgentHandlerProtocol
from guard_core.protocols.request_protocol import GuardRequest
from guard_core.protocols.response_protocol import (
    GuardResponse,
    GuardResponseHeaders,
)
from guard_core.utils import extract_client_ip

_ModifierArguments = ParamSpec("_ModifierArguments")
_ModifierResult = TypeVar("_ModifierResult")

READS_BODY_MARKER = "__guard_core_reads_response_body__"
_BODY_NOT_YET_AVAILABLE = "the first call of a modifier that is replayed with the body"
_BODYLESS_STATUSES = frozenset({204, 304})
# not str.isdigit(), which is also true for superscripts and digits int() rejects
_ASCII_DIGITS = re.compile(r"[0-9]+")
_REFUSAL_REPORT_SECONDS = 60
_REFUSAL_REPORT_MAX_REASONS = 64
_reported_refusals: PerApp[RefusalReports] = PerApp("refusals", RefusalReports)


def reads_response_body(
    modifier: Callable[_ModifierArguments, _ModifierResult],
) -> Callable[_ModifierArguments, _ModifierResult]:
    """Mark a ``custom_response_modifier`` that has side effects and reads ``.body``.

    A marked modifier is called once, with the bounded body already read, instead
    of once without it and again with it.
    """
    setattr(modifier, READS_BODY_MARKER, True)
    return modifier


def modifier_reads_response_body(
    modifier: Callable[_ModifierArguments, object],
) -> bool:
    return getattr(modifier, READS_BODY_MARKER, False) is True


class _AppendableHeaders(Protocol):
    def items(self) -> Iterable[tuple[str, str]]: ...

    def append(self, key: str, value: str) -> None: ...


class _IterableHeaders(Protocol):
    def __iter__(self) -> Iterator[str]: ...


class _SizedHeaders(Protocol):
    def __len__(self) -> int: ...


def _is_appendable(headers: GuardResponseHeaders) -> TypeGuard[_AppendableHeaders]:
    return callable(getattr(headers, "append", None))


def _require_appendable(headers: GuardResponseHeaders) -> _AppendableHeaders:
    if not _is_appendable(headers):
        raise AttributeError(
            f"{type(headers).__name__!r} object has no attribute 'append'"
        )
    return headers


def _is_iterable(headers: GuardResponseHeaders) -> TypeGuard[_IterableHeaders]:
    return callable(getattr(headers, "__iter__", None))


def _is_sized(headers: GuardResponseHeaders) -> TypeGuard[_SizedHeaders]:
    return callable(getattr(headers, "__len__", None))


class _Absent(Enum):
    ABSENT = 1


_ABSENT: Final = _Absent.ABSENT
_HeaderUndo = str | list[tuple[str, str]] | _Absent


class RecordingHeaders(MutableMapping[str, str]):
    """The real headers, written through, with an undo log only a replay uses.

    Reads and writes act on the real headers at once, as they do at base; every
    write first notes what it replaced, so ``undo`` can restore them when the
    first call of a replayed modifier is discarded. ``append`` (Starlette's
    ``MutableHeaders``) notes a full snapshot; any other attribute is forwarded.
    """

    def __init__(self, real: GuardResponseHeaders) -> None:
        self._real = real
        self._multi_valued = callable(getattr(real, "append", None))
        self._undo: list[tuple[str, _HeaderUndo]] = []

    def __getitem__(self, key: str) -> str:
        return self._real[key]

    def __setitem__(self, key: str, value: str) -> None:
        real = self._real
        if self._multi_valued and _is_appendable(real):
            # Headers that can hold several values of one name (Starlette's
            # ``MutableHeaders``) are undone from a full snapshot: ``real[key]`` is
            # one value of N.
            self._undo += [("", list(real.items()))]
        else:
            try:
                previous: _HeaderUndo = real[key]
            except KeyError:
                previous = _ABSENT
            self._undo += [(key, previous)]
        real[key] = value

    def __delitem__(self, key: str) -> None:
        real = self._real
        if self._multi_valued and _is_appendable(real):
            self._undo += [("", list(real.items()))]
        else:
            self._undo += [(key, real[key])]
        del real[key]

    def append(self, key: str, value: str) -> None:
        real = _require_appendable(self._real)
        self._undo += [("", list(real.items()))]
        real.append(key, value)

    def __getattr__(self, name: str) -> object:
        return getattr(self._real, name)

    def __iter__(self) -> Iterator[str]:
        real = self._real
        if not _is_iterable(real):
            raise TypeError(f"{type(real).__name__!r} object is not iterable")
        return iter(real)

    def __len__(self) -> int:
        real = self._real
        if not _is_sized(real):
            raise TypeError(f"object of type {type(real).__name__!r} has no len()")
        return len(real)

    def commit(self) -> None:
        """Nothing to apply: writes already went through."""

    def undo(self) -> None:
        real = self._real
        for key, previous in reversed(self._undo):
            if previous is _ABSENT:
                try:
                    del real[key]
                except KeyError:
                    pass
            elif isinstance(previous, list):
                _restore_items(real, previous)
            else:
                real[key] = previous
        self._undo = []


def _restore_items(real: GuardResponseHeaders, items: list[tuple[str, str]]) -> None:
    appendable = _require_appendable(real)
    for key in {name for name, _ in list(appendable.items())}:
        del real[key]
    for name, value in items:
        appendable.append(name, value)


class ModifierResponseView:
    """The response a ``custom_response_modifier`` sees.

    Writes go through to the real response (as at base) and are noted so a
    discarded first call can be undone; ``.body`` returns the bounded bytes when
    the view was built with them, otherwise it records that the modifier asked
    for it and raises ``ResponseBodyUnavailableError``.
    """

    status_code: int
    headers: RecordingHeaders
    body: bytes | None
    body_requested: bool

    def __init__(
        self,
        real: GuardResponse,
        body: bytes | None = None,
        refusal: str | None = None,
        gate_args: tuple[GuardResponse, str, int] | None = None,
        record_writes: bool = True,
    ) -> None:
        state = self.__dict__
        state["_real"] = real
        state["_refusal"] = refusal
        state["_declared"] = None
        state["_gate_args"] = gate_args
        state["_attribute_undo"] = []
        state["body_requested"] = False
        state["headers"] = (
            RecordingHeaders(real.headers) if record_writes else real.headers
        )
        if body is not None:
            state["body"] = body

    def gate_refusal(self) -> str | None:
        """The gate's reason to refuse the body, asked at most once per view."""
        state = self.__dict__
        if state["_refusal"] is None and state["_gate_args"] is not None:
            state["_refusal"], state["_declared"] = body_gate(*state["_gate_args"])
            state["_gate_args"] = None
        refusal: str | None = state["_refusal"]
        return refusal

    def __getattr__(self, name: str) -> object:
        state = self.__dict__
        if name != "body":
            return getattr(state["_real"], name)
        # ``body`` is never an attribute until a replay stores the bytes, so this
        # one call both records the request and raises: the real response's body
        # must never answer.
        state["body_requested"] = True
        if state["_refusal"] is None and state["_gate_args"] is not None:
            state["_refusal"], state["_declared"] = body_gate(*state["_gate_args"])
            state["_gate_args"] = None
        raise ResponseBodyUnavailableError(state["_refusal"] or _BODY_NOT_YET_AVAILABLE)

    def __setattr__(self, name: str, value: object) -> None:
        state = self.__dict__
        real = state["_real"]
        state["_attribute_undo"].append((name, getattr(real, name, _ABSENT)))
        setattr(real, name, value)
        if name == "headers":
            state["headers"] = RecordingHeaders(real.headers)

    def commit(self) -> GuardResponse:
        """Nothing to apply: writes already went through."""
        real: GuardResponse = self.__dict__["_real"]
        return real

    def undo(self) -> None:
        state = self.__dict__
        state["headers"].undo()
        real = state["_real"]
        for name, previous in reversed(state["_attribute_undo"]):
            if previous is not _ABSENT:
                setattr(real, name, previous)
        state["_attribute_undo"] = []


def _header_value(headers: GuardResponseHeaders, name: str, cased: str) -> str | None:
    value = headers.get(name)
    if value is None:
        value = headers.get(cased)
    if value is not None or type(headers) is not dict:
        return value
    for key in headers:
        if key.lower() == name:
            found: str = headers[key]
            return found
    return None


def declared_content_length(response: GuardResponse) -> int | None:
    headers = response.headers
    declared = headers.get("content-length")
    if declared is None:
        declared = _header_value(headers, "content-length", "Content-Length")
        if declared is None:
            return None
    if _ASCII_DIGITS.fullmatch(declared.strip()) is None:
        return None
    return int(declared)


def _plain_dict_gate_headers(
    headers: GuardResponseHeaders, content_type: str | None, declared: str | None
) -> tuple[str | None, str | None]:
    """Casing fallback for a plain ``dict`` of headers (every adapter's mapping is
    case-insensitive and never gets here)."""
    return (
        content_type or _header_value(headers, "content-type", "Content-Type"),
        declared or _header_value(headers, "content-length", "Content-Length"),
    )


def body_gate(
    response: GuardResponse, method: str, max_bytes: int
) -> tuple[str | None, int | None]:
    """Why ``.body`` must not be offered for this response (None when it may) and,
    when it may, the declared Content-Length.

    ``method`` is the request method in upper case (the request protocol).
    Header lookups use ``.get`` once: every adapter's headers are
    case-insensitive; only a plain ``dict`` gets the casing fallback.
    """
    if method == "HEAD":
        return "a HEAD response has no body", None
    status = response.status_code
    if status < 200 or status in _BODYLESS_STATUSES:
        return f"a {status} response has no body", None
    headers = response.headers
    content_type = headers.get("content-type")
    declared = headers.get("content-length")
    if type(headers) is dict:
        content_type, declared = _plain_dict_gate_headers(
            headers, content_type, declared
        )
    if content_type and content_type.lower().lstrip().startswith("text/event-stream"):
        return "text/event-stream has no end", None
    if declared is None or _ASCII_DIGITS.fullmatch(declared) is None:
        return "the response declares no Content-Length", None
    length = int(declared)
    if length > max_bytes:
        return f"the declared Content-Length {declared} is over {max_bytes} bytes", None
    return None, length


def body_gate_refusal(
    response: GuardResponse, method: str, max_bytes: int
) -> str | None:
    """The refusal reason of ``body_gate``, or None when ``.body`` may be offered."""
    return body_gate(response, method, max_bytes)[0]


async def report_body_refused(
    logger: logging.Logger,
    config: SecurityConfig,
    agent_handler: AgentHandlerProtocol | None,
    request: GuardRequest,
    reason: str,
) -> None:
    now = time.monotonic()
    reported = _reported_refusals.for_app(config)
    last = reported.get(reason)
    if last is not None and now - last < _REFUSAL_REPORT_SECONDS:
        return
    if len(reported) >= _REFUSAL_REPORT_MAX_REASONS:
        reported.clear()
    reported[reason] = now
    logger.warning(
        "custom_response_modifier read .body but it is unavailable: %s; "
        "header edits still apply",
        reason,
    )
    if not agent_handler or not config.agent_enable_events:
        return
    await send_agent_event(
        agent_handler,
        EVENT_RESPONSE_BODY_UNAVAILABLE,
        await extract_client_ip(request, config, agent_handler),
        "headers_only",
        reason,
        request,
        metadata={"max_body_bytes": config.custom_response_modifier_max_body_bytes},
    )
