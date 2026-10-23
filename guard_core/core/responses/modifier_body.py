import logging
from collections.abc import Awaitable, Callable
from typing import Any

from guard_core._utils.response_prefetch import SHARED_PREFETCH, ResponseBodyPrefetch
from guard_core.core.responses.modifier_view import (
    READS_BODY_MARKER,
    ModifierResponseView,
    body_gate_refusal,
    declared_content_length,
    report_body_refused,
)
from guard_core.models import SecurityConfig
from guard_core.protocols.request_protocol import GuardRequest
from guard_core.protocols.response_protocol import GuardResponse

Modifier = Callable[[Any], Awaitable[Any]]

_PREFETCH_INCOMPLETE = (
    "the bounded read did not return exactly the declared Content-Length bytes"
)
_MODIFIER_RAISED = "custom_response_modifier raised %s; returning unmodified response"


async def _prefetched_body(
    config: SecurityConfig, response: GuardResponse, prefetch: ResponseBodyPrefetch
) -> tuple[bytes | None, str | None]:
    cap = config.custom_response_modifier_max_body_bytes
    body = await prefetch.read(cap, config.body_read_timeout)
    if body is None or len(body) != declared_content_length(response):
        return None, _PREFETCH_INCOMPLETE
    return body, None


async def _call_on_view(
    modifier: Modifier,
    view: ModifierResponseView,
    real: GuardResponse,
    logger: logging.Logger,
) -> GuardResponse:
    try:
        result: GuardResponse = await modifier(view)
    except Exception as exc:
        logger.exception(_MODIFIER_RAISED, exc)
        return real
    return real if result is view else result


async def _call_marked_modifier(
    modifier: Modifier,
    response: GuardResponse,
    request: GuardRequest,
    shared: ResponseBodyPrefetch | None,
    config: SecurityConfig,
    logger: logging.Logger,
    agent_handler: Any | None,
    gate: Callable[[], str | None],
) -> GuardResponse:
    refusal = gate()
    body = None
    if refusal is None:
        body, refusal = await _prefetched_body(
            config, response, shared or ResponseBodyPrefetch(response)
        )
    view = ModifierResponseView(response, body, refusal)
    result = await _call_on_view(modifier, view, response, logger)
    if refusal is not None and view.__dict__["body_requested"]:
        await report_body_refused(logger, config, agent_handler, request, refusal)
    return result


async def apply_modifier_with_bounded_body(
    modifier: Modifier,
    response: GuardResponse,
    request: GuardRequest,
    prefetch: ResponseBodyPrefetch | None,
    config: SecurityConfig,
    logger: logging.Logger,
    agent_handler: Any | None,
) -> GuardResponse:
    cap = config.custom_response_modifier_max_body_bytes

    def gate() -> str | None:
        return body_gate_refusal(response, request.method, cap)

    try:
        if getattr(modifier, READS_BODY_MARKER, False) is True:
            return await _call_marked_modifier(
                modifier,
                response,
                request,
                prefetch,
                config,
                logger,
                agent_handler,
                gate,
            )
        first = ModifierResponseView(response, gate=gate)
        result: Any = first
        try:
            result = await modifier(first)
        except Exception as exc:
            logger.exception(_MODIFIER_RAISED, exc)
        if not first.__dict__["body_requested"]:
            return response if result is first else result
        body, refusal = None, first.gate_refusal()
        if refusal is None:
            body, refusal = await _prefetched_body(
                config, response, prefetch or ResponseBodyPrefetch(response)
            )
        if refusal is not None:
            await report_body_refused(logger, config, agent_handler, request, refusal)
            return response if result is first else result
        first.undo()
        return await _call_on_view(
            modifier, ModifierResponseView(response, body), response, logger
        )
    finally:
        if prefetch is not None:
            SHARED_PREFETCH.set(None)
