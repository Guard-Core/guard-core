import logging
from collections.abc import Callable
from typing import Any, cast

from guard_core.exceptions import ResponseBodyUnavailableError
from guard_core.models import SecurityConfig
from guard_core.protocols.response_protocol import GuardResponse
from guard_core.sync._utils.response_prefetch import (
    ResponseBodyPrefetch,
)
from guard_core.sync.core.responses.modifier_view import (
    ModifierResponseView,
    body_gate_refusal,
    declared_content_length,
    report_body_refused,
)
from guard_core.sync.protocols.request_protocol import SyncGuardRequest

Modifier = Callable[[Any], Any]

_PREFETCH_INCOMPLETE = (
    "the bounded read did not return exactly the declared Content-Length bytes"
)


class LazyBodyResponseView(ModifierResponseView):
    """Sync engines read the bounded prefix on the first ``.body`` access: one call."""

    def __init__(self, real: GuardResponse, load: Callable[[], bytes]) -> None:
        super().__init__(real)
        self.__dict__["_load"] = load

    def __getattr__(self, name: str) -> Any:
        state = self.__dict__
        if name != "body":
            return getattr(state["_real"], name)
        state["body_requested"] = True
        if state["_refusal"] is None:
            try:
                state["body"] = state["_load"]()
                return state["body"]
            except ResponseBodyUnavailableError as refusal:
                state["_refusal"] = refusal.reason
        raise ResponseBodyUnavailableError(cast(str, state["_refusal"]))


def apply_modifier_with_bounded_body(
    modifier: Modifier,
    response: GuardResponse,
    request: SyncGuardRequest,
    prefetch: ResponseBodyPrefetch | None,
    config: SecurityConfig,
    logger: logging.Logger,
    agent_handler: Any | None,
) -> GuardResponse:
    def load() -> bytes:
        cap = config.custom_response_modifier_max_body_bytes
        refusal = body_gate_refusal(response, request.method, cap)
        body = None
        if refusal is None:
            body = (prefetch or ResponseBodyPrefetch(response)).read(
                cap, config.body_read_timeout
            )
            if body is None or len(body) != declared_content_length(response):
                body, refusal = None, _PREFETCH_INCOMPLETE
        if body is None:
            report_body_refused(
                logger, config, agent_handler, request, cast(str, refusal)
            )
            raise ResponseBodyUnavailableError(cast(str, refusal))
        return body

    view = LazyBodyResponseView(response, load)
    result: Any = view
    try:
        result = modifier(view)
    except Exception as exc:
        logger.exception(
            "custom_response_modifier raised %s; returning unmodified response", exc
        )
    return response if result is view else result
