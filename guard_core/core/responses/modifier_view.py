import logging
from collections.abc import Callable, Iterator, MutableMapping
from typing import Any, TypeVar, cast

from cachetools import TTLCache

from guard_core._utils.agent_events import send_agent_event
from guard_core.core.events.event_types import EVENT_RESPONSE_BODY_UNAVAILABLE
from guard_core.exceptions import ResponseBodyUnavailableError
from guard_core.models import SecurityConfig
from guard_core.protocols.request_protocol import GuardRequest
from guard_core.protocols.response_protocol import GuardResponse
from guard_core.utils import extract_client_ip

ModifierT = TypeVar("ModifierT", bound=Callable[..., Any])

_READS_BODY_MARKER = "__guard_core_reads_response_body__"
_BODY_NOT_YET_AVAILABLE = "the first call of a modifier that is replayed with the body"
_BODYLESS_STATUSES = frozenset({204, 304})
_REFUSAL_REPORT_SECONDS = 60
_reported_refusals: TTLCache[str, bool] = TTLCache(
    maxsize=64, ttl=_REFUSAL_REPORT_SECONDS
)


def reads_response_body(modifier: ModifierT) -> ModifierT:
    """Mark a ``custom_response_modifier`` that has side effects and reads ``.body``.

    A marked modifier is called once, with the bounded body already read, instead
    of once without it and again with it.
    """
    setattr(modifier, _READS_BODY_MARKER, True)
    return modifier


def modifier_reads_response_body(modifier: Callable[..., Any]) -> bool:
    return getattr(modifier, _READS_BODY_MARKER, False) is True


class RecordingHeaders(MutableMapping[str, str]):
    """Header writes of one modifier call, applied to the real headers on commit.

    ``append`` (Starlette's ``MutableHeaders``) is recorded too; any other
    attribute of the real headers is forwarded and acts on them at once.
    """

    def __init__(self, real: MutableMapping[str, str]) -> None:
        self._real = real
        self._overlay: dict[str, tuple[str, str | None]] = {}
        self._log: list[tuple[str, str, str | None]] = []

    def __getitem__(self, key: str) -> str:
        shadow = self._overlay.get(key.lower())
        if shadow is None:
            return self._real[key]
        if shadow[1] is None:
            raise KeyError(key)
        return shadow[1]

    def __setitem__(self, key: str, value: str) -> None:
        self._overlay[key.lower()] = (key, value)
        self._log.append(("set", key, value))

    def __delitem__(self, key: str) -> None:
        if key not in self:
            raise KeyError(key)
        self._overlay[key.lower()] = (key, None)
        self._log.append(("delete", key, None))

    def append(self, key: str, value: str) -> None:
        if key not in self:
            self._overlay[key.lower()] = (key, value)
        self._log.append(("append", key, value))

    def __getattr__(self, name: str) -> Any:
        return getattr(self._real, name)

    def __iter__(self) -> Iterator[str]:
        for key in self._real:
            if key.lower() not in self._overlay:
                yield key
        for name, value in self._overlay.values():
            if value is not None:
                yield name

    def __len__(self) -> int:
        return sum(1 for _ in self)

    def commit(self) -> None:
        for operation, name, value in self._log:
            if operation == "append":
                cast(Any, self._real).append(name, value)
            elif value is not None:
                self._real[name] = value
            elif name in self._real:
                del self._real[name]


class ModifierResponseView:
    """The response a ``custom_response_modifier`` sees.

    Header and attribute writes are recorded and reach the real response only on
    ``commit``, so a call that is replayed leaves nothing behind. ``.body``
    returns the bounded bytes when the view was built with them, otherwise it
    records that the modifier asked for it and raises
    ``ResponseBodyUnavailableError``.
    """

    __slots__ = (
        "_real",
        "_body",
        "_refusal",
        "_gate",
        "_recorded_headers",
        "_attribute_writes",
        "body_requested",
    )

    _real: GuardResponse
    _body: bytes | None
    _refusal: str | None
    _gate: Callable[[], str | None] | None
    _recorded_headers: RecordingHeaders | None
    _attribute_writes: dict[str, Any]
    body_requested: bool

    def __init__(
        self,
        real: GuardResponse,
        body: bytes | None = None,
        refusal: str | None = None,
        gate: Callable[[], str | None] | None = None,
    ) -> None:
        object.__setattr__(self, "_real", real)
        object.__setattr__(self, "_body", body)
        object.__setattr__(self, "_refusal", refusal)
        object.__setattr__(self, "_gate", gate)
        object.__setattr__(self, "_recorded_headers", None)
        object.__setattr__(self, "_attribute_writes", {})
        object.__setattr__(self, "body_requested", False)

    @property
    def headers(self) -> MutableMapping[str, str]:
        if "headers" in self._attribute_writes:
            assigned: MutableMapping[str, str] = self._attribute_writes["headers"]
            return assigned
        recorded = self._recorded_headers
        if recorded is None:
            recorded = RecordingHeaders(self._real.headers)
            object.__setattr__(self, "_recorded_headers", recorded)
        return recorded

    def gate_refusal(self) -> str | None:
        """The gate's reason to refuse the body, asked at most once per view."""
        if self._refusal is None and self._gate is not None:
            object.__setattr__(self, "_refusal", self._gate())
            object.__setattr__(self, "_gate", None)
        return self._refusal

    @property
    def body(self) -> bytes | None:
        object.__setattr__(self, "body_requested", True)
        if self._body is None:
            raise ResponseBodyUnavailableError(
                self.gate_refusal() or _BODY_NOT_YET_AVAILABLE
            )
        return self._body

    def __getattr__(self, name: str) -> Any:
        if name == "body":
            # Python calls __getattr__ again when the ``body`` property raises
            # an AttributeError; the real response's body must never answer then.
            raise ResponseBodyUnavailableError(
                self.gate_refusal() or _BODY_NOT_YET_AVAILABLE
            )
        if name in self._attribute_writes:
            return self._attribute_writes[name]
        return getattr(self._real, name)

    def __setattr__(self, name: str, value: Any) -> None:
        self._attribute_writes[name] = value

    def commit(self) -> GuardResponse:
        if self._recorded_headers is not None:
            self._recorded_headers.commit()
        for name, value in self._attribute_writes.items():
            setattr(self._real, name, value)
        return self._real


def _header_value(headers: MutableMapping[str, str], name: str) -> str | None:
    value = headers.get(name)
    if value is not None:
        return value
    for key in headers:
        if key.lower() == name:
            return headers[key]
    return None


def declared_content_length(response: GuardResponse) -> int | None:
    declared = _header_value(response.headers, "content-length")
    if declared is None or not declared.strip().isdigit():
        return None
    return int(declared)


def body_gate_refusal(
    response: GuardResponse, method: str, max_bytes: int
) -> str | None:
    """Why ``.body`` must not be offered for this response, or None when it may."""
    if method.upper() == "HEAD":
        return "a HEAD response has no body"
    status = response.status_code
    if status < 200 or status in _BODYLESS_STATUSES:
        return f"a {status} response has no body"
    content_type = _header_value(response.headers, "content-type") or ""
    if content_type.strip().lower().startswith("text/event-stream"):
        return "text/event-stream has no end"
    declared = declared_content_length(response)
    if declared is None:
        return "the response declares no Content-Length"
    if declared > max_bytes:
        return f"the declared Content-Length {declared} is over {max_bytes} bytes"
    return None


async def report_body_refused(
    logger: logging.Logger,
    config: SecurityConfig,
    agent_handler: Any | None,
    request: GuardRequest,
    reason: str,
) -> None:
    if _reported_refusals.get(reason) is not None:
        return
    _reported_refusals[reason] = True
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
