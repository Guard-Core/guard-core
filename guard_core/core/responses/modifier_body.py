import logging
from collections.abc import Awaitable, Callable
from typing import Any, cast

from guard_core._utils.response_prefetch import SHARED_PREFETCH, ResponseBodyPrefetch
from guard_core.core.responses.modifier_view import (
    ModifierResponseView,
    body_gate_refusal,
    declared_content_length,
    modifier_reads_response_body,
    report_body_refused,
)
from guard_core.models import SecurityConfig
from guard_core.protocols.request_protocol import GuardRequest
from guard_core.protocols.response_protocol import GuardResponse

Modifier = Callable[[GuardResponse], Awaitable[GuardResponse]]

_PREFETCH_INCOMPLETE = (
    "the bounded read did not return exactly the declared Content-Length bytes"
)


async def _prefetched_body(
    config: SecurityConfig, response: GuardResponse, prefetch: ResponseBodyPrefetch
) -> tuple[bytes | None, str | None]:
    cap = config.custom_response_modifier_max_body_bytes
    body = await prefetch.read(cap, config.body_read_timeout)
    if body is None or len(body) != declared_content_length(response):
        return None, _PREFETCH_INCOMPLETE
    return body, None


async def _invoke(
    modifier: Modifier,
    view: ModifierResponseView,
    real: GuardResponse,
    logger: logging.Logger,
) -> Any:
    try:
        return await modifier(cast(GuardResponse, view))
    except Exception as exc:
        logger.exception(
            "custom_response_modifier raised %s; returning unmodified response", exc
        )
        return real


def _commit(view: ModifierResponseView, result: Any) -> GuardResponse:
    real = view.commit()
    return real if result is view else cast(GuardResponse, result)


async def apply_modifier_with_bounded_body(
    modifier: Modifier,
    response: GuardResponse,
    request: GuardRequest,
    prefetch: ResponseBodyPrefetch | None,
    config: SecurityConfig,
    logger: logging.Logger,
    agent_handler: Any | None,
) -> GuardResponse:
    prefetch = prefetch or ResponseBodyPrefetch(response)
    cap = config.custom_response_modifier_max_body_bytes

    def gate() -> str | None:
        return body_gate_refusal(response, request.method, cap)

    try:
        if modifier_reads_response_body(modifier):
            refusal = gate()
            body = None
            if refusal is None:
                body, refusal = await _prefetched_body(config, response, prefetch)
            view = ModifierResponseView(response, body, refusal)
            result = await _invoke(modifier, view, response, logger)
            if refusal is not None and view.body_requested:
                await report_body_refused(
                    logger, config, agent_handler, request, refusal
                )
            return _commit(view, result)
        first = ModifierResponseView(response, gate=gate)
        result = await _invoke(modifier, first, response, logger)
        if not first.body_requested:
            return _commit(first, result)
        body, refusal = None, first.gate_refusal()
        if refusal is None:
            body, refusal = await _prefetched_body(config, response, prefetch)
        if refusal is not None:
            await report_body_refused(logger, config, agent_handler, request, refusal)
            return _commit(first, result)
        replay = ModifierResponseView(response, body)
        return _commit(replay, await _invoke(modifier, replay, response, logger))
    finally:
        SHARED_PREFETCH.set(None)
