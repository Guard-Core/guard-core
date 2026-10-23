import logging
import time
from collections.abc import Callable, Iterator, MutableMapping
from typing import Any, TypeVar, cast

from guard_core._utils.agent_events import send_agent_event
from guard_core.core.events.event_types import EVENT_RESPONSE_BODY_UNAVAILABLE
from guard_core.exceptions import ResponseBodyUnavailableError
from guard_core.models import SecurityConfig
from guard_core.protocols.request_protocol import GuardRequest
from guard_core.protocols.response_protocol import GuardResponse
from guard_core.utils import extract_client_ip

ModifierT = TypeVar("ModifierT", bound=Callable[..., Any])

READS_BODY_MARKER = "__guard_core_reads_response_body__"
_BODY_NOT_YET_AVAILABLE = "the first call of a modifier that is replayed with the body"
_BODYLESS_STATUSES = frozenset({204, 304})
_REFUSAL_REPORT_SECONDS = 60
_REFUSAL_REPORT_MAX_REASONS = 64
_reported_refusals: dict[str, float] = {}


def reads_response_body(modifier: ModifierT) -> ModifierT:
    """Mark a ``custom_response_modifier`` that has side effects and reads ``.body``.

    A marked modifier is called once, with the bounded body already read, instead
    of once without it and again with it.
    """
    setattr(modifier, READS_BODY_MARKER, True)
    return modifier


def modifier_reads_response_body(modifier: Callable[..., Any]) -> bool:
    return getattr(modifier, READS_BODY_MARKER, False) is True


class RecordingHeaders(MutableMapping[str, str]):
    """The real headers, written through, with an undo log only a replay uses.

    Reads and writes act on the real headers at once, as they do at base; every
    write first notes what it replaced, so ``undo`` can restore them when the
    first call of a replayed modifier is discarded. ``append`` (Starlette's
    ``MutableHeaders``) notes a full snapshot; any other attribute is forwarded.
    """

    def __init__(self, real: MutableMapping[str, str]) -> None:
        self._real = real
        self._undo: list[tuple[str, Any]] = []

    def __getitem__(self, key: str) -> str:
        return self._real[key]

    def __setitem__(self, key: str, value: str) -> None:
        real = self._real
        try:
            previous: Any = real[key]
        except KeyError:
            previous = _ABSENT
        self._undo += [(key, previous)]
        real[key] = value

    def __delitem__(self, key: str) -> None:
        real = self._real
        self._undo += [(key, real[key])]
        del real[key]

    def append(self, key: str, value: str) -> None:
        real = self._real
        self._undo += [("", list(cast(Any, real).items()))]
        cast(Any, real).append(key, value)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._real, name)

    def __iter__(self) -> Iterator[str]:
        return iter(self._real)

    def __len__(self) -> int:
        return len(self._real)

    def commit(self) -> None:
        """Nothing to apply: writes already went through."""

    def undo(self) -> None:
        real = self._real
        for key, previous in reversed(self._undo):
            if key == "":
                _restore_items(real, previous)
            elif previous is _ABSENT:
                if key in real:
                    del real[key]
            else:
                real[key] = previous
        self._undo = []


def _restore_items(
    real: MutableMapping[str, str], items: list[tuple[str, str]]
) -> None:
    for key in {name for name, _ in list(cast(Any, real).items())}:
        del real[key]
    for name, value in items:
        cast(Any, real).append(name, value)


_ABSENT: Any = object()


class ModifierResponseView:
    """The response a ``custom_response_modifier`` sees.

    Writes go through to the real response (as at base) and are noted so a
    discarded first call can be undone; ``.body`` returns the bounded bytes when
    the view was built with them, otherwise it records that the modifier asked
    for it and raises ``ResponseBodyUnavailableError``.
    """

    headers: RecordingHeaders
    body: bytes | None
    body_requested: bool

    def __init__(
        self,
        real: GuardResponse,
        body: bytes | None = None,
        refusal: str | None = None,
        gate_args: tuple[GuardResponse, str, int] | None = None,
    ) -> None:
        state = self.__dict__
        state["_real"] = real
        state["_refusal"] = refusal
        state["_gate_args"] = gate_args
        state["_attribute_undo"] = []
        state["body_requested"] = False
        state["headers"] = RecordingHeaders(real.headers)
        if body is not None:
            state["body"] = body

    def gate_refusal(self) -> str | None:
        """The gate's reason to refuse the body, asked at most once per view."""
        state = self.__dict__
        if state["_refusal"] is None and state["_gate_args"] is not None:
            state["_refusal"] = body_gate_refusal(*state["_gate_args"])
            state["_gate_args"] = None
        refusal: str | None = state["_refusal"]
        return refusal

    def __getattr__(self, name: str) -> Any:
        state = self.__dict__
        if name != "body":
            return getattr(state["_real"], name)
        # ``body`` is never an attribute until a replay stores the bytes, so this
        # one call both records the request and raises: the real response's body
        # must never answer.
        state["body_requested"] = True
        if state["_refusal"] is None and state["_gate_args"] is not None:
            state["_refusal"] = body_gate_refusal(*state["_gate_args"])
            state["_gate_args"] = None
        raise ResponseBodyUnavailableError(state["_refusal"] or _BODY_NOT_YET_AVAILABLE)

    def __setattr__(self, name: str, value: Any) -> None:
        state = self.__dict__
        real = state["_real"]
        state["_attribute_undo"].append((name, getattr(real, name, _ABSENT)))
        setattr(real, name, value)
        if name == "headers":
            state["headers"] = RecordingHeaders(value)

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


def _header_value(
    headers: MutableMapping[str, str], name: str, cased: str
) -> str | None:
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
    declared = _header_value(response.headers, "content-length", "Content-Length")
    if declared is None or not declared.strip().isdigit():
        return None
    return int(declared)


def body_gate_refusal(
    response: GuardResponse, method: str, max_bytes: int
) -> str | None:
    """Why ``.body`` must not be offered for this response, or None when it may.

    ``method`` is the request method in upper case (the request protocol).
    Header lookups use ``.get`` once: every adapter's headers are
    case-insensitive; only a plain ``dict`` gets the casing fallback.
    """
    if method == "HEAD":
        return "a HEAD response has no body"
    status = response.status_code
    if status < 200 or status in _BODYLESS_STATUSES:
        return f"a {status} response has no body"
    headers = response.headers
    content_type = headers.get("content-type")
    declared = headers.get("content-length")
    if (content_type is None or declared is None) and type(headers) is dict:
        content_type = content_type or _header_value(
            headers, "content-type", "Content-Type"
        )
        declared = declared or _header_value(
            headers, "content-length", "Content-Length"
        )
    if content_type and content_type.lower().lstrip().startswith("text/event-stream"):
        return "text/event-stream has no end"
    if declared is None:
        return "the response declares no Content-Length"
    if not declared.isdigit():
        declared = declared.strip()
        if not declared.isdigit():
            return "the response declares no Content-Length"
    if int(declared) > max_bytes:
        return f"the declared Content-Length {declared} is over {max_bytes} bytes"
    return None


async def report_body_refused(
    logger: logging.Logger,
    config: SecurityConfig,
    agent_handler: Any | None,
    request: GuardRequest,
    reason: str,
) -> None:
    now = time.monotonic()
    last = _reported_refusals.get(reason)
    if last is not None and now - last < _REFUSAL_REPORT_SECONDS:
        return
    if len(_reported_refusals) >= _REFUSAL_REPORT_MAX_REASONS:
        _reported_refusals.clear()
    _reported_refusals[reason] = now
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
