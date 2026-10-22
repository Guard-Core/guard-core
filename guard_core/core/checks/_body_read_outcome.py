from guard_core.core.checks.base import SecurityCheck
from guard_core.core.events.event_types import EVENT_SUSPICIOUS_REQUEST
from guard_core.detection_result import BODY_READ_STALLED, DetectionResult
from guard_core.protocols.request_protocol import GuardRequest
from guard_core.protocols.response_protocol import GuardResponse
from guard_core.utils import log_activity


async def body_read_outcome(
    check: SecurityCheck,
    request: GuardRequest,
    client_ip: str,
    result: DetectionResult,
) -> GuardResponse | None:
    config = check.config
    stalled = result.body_read_error == BODY_READ_STALLED
    outcome = "stalled" if stalled else "failed"
    blocks = config.fail_secure and not config.passive_mode
    await log_activity(
        request,
        check.logger,
        log_type="suspicious",
        reason=f"Request body read {outcome} for IP: {client_ip}",
        passive_mode=config.passive_mode,
        trigger_info=result.body_read_detail,
        level=config.log_suspicious_level,
        check_name=check.check_name,
        muted_check_logs=config.muted_check_logs,
        on_block=config.on_block,
        sensitive_headers=config.log_sensitive_headers,
        sensitive_params=config.log_sensitive_params,
        sensitive_body_fields=config.log_sensitive_body_fields,
    )
    await check.middleware.event_bus.send_middleware_event(
        event_type=EVENT_SUSPICIOUS_REQUEST,
        request=request,
        action_taken="request_blocked" if blocks else "logged_only",
        reason=f"Request body read {outcome}: {result.body_read_detail}",
        passive_mode=config.passive_mode,
        trigger_info=result.body_read_detail,
    )
    if not blocks:
        return None
    return await _refusal(check, stalled)


async def _refusal(check: SecurityCheck, stalled: bool) -> GuardResponse:
    if stalled:
        return await check.middleware.create_error_response(
            status_code=408, default_message="Request body read timed out"
        )
    return await check.middleware.create_error_response(
        status_code=400, default_message="Request body could not be read"
    )
