import logging
from collections.abc import Callable
from typing import Any

from guard_core.exceptions import CallableShapeError, ResponseBodyUnavailableError
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


def _load_bounded_body(state: dict[str, Any]) -> bytes | None:
    response, method, cap = state["_gate_args"]
    config, prefetch, logger, agent_handler, request = state["_lazy"]
    refusal = body_gate_refusal(response, method, cap)
    body = None
    if refusal is None:
        body = (prefetch or ResponseBodyPrefetch(response)).read(
            cap, config.body_read_timeout
        )
        if body is None or len(body) != declared_content_length(response):
            body, refusal = None, _PREFETCH_INCOMPLETE
    if body is not None:
        state["body"] = body
        return body
    state["_refusal"] = refusal
    report_body_refused(logger, config, agent_handler, request, refusal)
    return None


class LazyBodyResponseView(ModifierResponseView):
    """Sync engines read the bounded prefix on the first ``.body`` access: one call."""

    def __getattr__(self, name: str) -> Any:
        state = self.__dict__
        if name != "body":
            return getattr(state["_real"], name)
        state["body_requested"] = True
        if state["_refusal"] is None:
            body = _load_bounded_body(state)
            if body is not None:
                return body
        raise ResponseBodyUnavailableError(state["_refusal"])


def apply_modifier_with_bounded_body(
    modifier: Modifier,
    response: GuardResponse,
    request: SyncGuardRequest,
    prefetch: ResponseBodyPrefetch | None,
    config: SecurityConfig,
    logger: logging.Logger,
    agent_handler: Any | None,
) -> GuardResponse:
    view = LazyBodyResponseView(
        response,
        gate_args=(
            response,
            request.method,
            config.custom_response_modifier_max_body_bytes,
        ),
        record_writes=False,
    )
    view.__dict__["_lazy"] = (config, prefetch, logger, agent_handler, request)
    result: Any = view
    try:
        result = modifier(view)
    except CallableShapeError:
        raise
    except Exception as exc:
        logger.exception(
            "custom_response_modifier raised %s; returning unmodified response", exc
        )
    return response if result is view else result
