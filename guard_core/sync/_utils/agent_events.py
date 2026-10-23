import logging
import time
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any

from guard_core.sync.protocols.agent_protocol import SyncAgentHandlerProtocol
from guard_core.sync.protocols.request_protocol import SyncGuardRequest

logger = logging.getLogger("guard_core")

_IP_EXTRACTION_HANDLER_NAME = "ip_extraction"


def invoke_error_hook(
    hook: Callable[[str, BaseException, dict[str, Any]], None] | None,
    stage: str,
    exc: BaseException,
    context: dict[str, Any],
) -> None:
    if hook is None:
        return
    try:
        hook(stage, exc, context)
    except Exception as hook_error:
        logger.error(f"on_error hook raised while handling '{stage}': {hook_error}")


def get_pipeline_response_time(request: SyncGuardRequest | None) -> float | None:
    if request is None:
        return None
    pipeline_start = getattr(request.state, "_guard_pipeline_start", None)
    if not isinstance(pipeline_start, int | float):
        pipeline_start = time.monotonic()
        request.state._guard_pipeline_start = pipeline_start
    return time.monotonic() - pipeline_start


def agent_receives_events(event_bus: Any, config: Any) -> bool:
    """True when an agent is attached to the bus and events are enabled; a bus
    without an ``agent_handler`` attribute has no agent."""
    try:
        agent_handler = event_bus.agent_handler
    except AttributeError:
        return False
    return bool(agent_handler and config.agent_enable_events)


def send_agent_event(
    agent_handler: SyncAgentHandlerProtocol | None,
    event_type: str,
    ip_address: str,
    action_taken: str,
    reason: str,
    request: SyncGuardRequest | None = None,
    **kwargs: Any,
) -> None:
    if not agent_handler:
        return

    try:
        endpoint = None
        method = None
        user_agent = None
        country = None

        if request:
            endpoint = request.url_path
            method = request.method
            user_agent = request.headers.get("User-Agent")

        from guard_core._pydantic_plugin_mute import get_telemetry_model

        SecurityEvent = get_telemetry_model("SecurityEvent")

        decorator_type = kwargs.pop("decorator_type", None)
        rule_type = kwargs.pop("rule_type", None)
        metadata: dict[str, Any] = kwargs.pop("metadata", {})
        if decorator_type is not None:
            metadata = {**metadata, "decorator_type": decorator_type}
        if rule_type is not None:
            metadata = {**metadata, "rule_type": rule_type}

        event = SecurityEvent(
            timestamp=datetime.now(timezone.utc),
            event_type=event_type,
            ip_address=ip_address,
            country=country,
            user_agent=user_agent,
            action_taken=action_taken,
            reason=reason,
            endpoint=endpoint,
            method=method,
            response_time=get_pipeline_response_time(request),
            decorator_type=decorator_type,
            rule_type=rule_type,
            handler_name=_IP_EXTRACTION_HANDLER_NAME,
            metadata=metadata,
            **kwargs,
        )

        agent_handler.send_event(event)
    except Exception as e:
        logging.getLogger("guard_core.sync.utils").error(f"Failed to send agent event: {e}")
