import inspect
import logging
from collections.abc import Callable

from guard_core.sync._utils.ip_extraction import (
    UNKNOWN_CLIENT_IDENTITY,
    _canonicalize_ip,
)
from guard_core.sync.protocols.request_protocol import SyncGuardRequest

logger = logging.getLogger("guard_core")

ON_BLOCK_EXCLUDED_CHECK_NAMES = frozenset(
    {"custom_request", "custom_validators", "https_enforcement"}
)


def invoke_block_hook(
    hook: Callable[[SyncGuardRequest, dict[str, object]], object] | None,
    request: SyncGuardRequest,
    payload: dict[str, object],
) -> None:
    if hook is None:
        return
    try:
        result = hook(request, payload)
    except Exception as hook_error:
        logger.error(f"on_block hook raised: {hook_error}")
        return
    if inspect.isawaitable(result):
        raise TypeError(
            "async on_block hook not supported in sync (WSGI) deployments; "
            "supply a sync on_block hook"
        )


def build_block_payload(
    request: SyncGuardRequest,
    check_name: str,
    reason: str,
    trigger_info: str,
    passive_mode: bool,
    status_code: int | None,
    sensitive_params: frozenset[str] | None = None,
    sensitive_body_fields: frozenset[str] | None = None,
    sensitive_headers: frozenset[str] | None = None,
) -> dict[str, object]:
    from guard_core.sync._utils.request_logging import redact_url_for_display

    cached_ip = getattr(request.state, "client_ip", None)
    if cached_ip:
        client_ip = cached_ip
    elif request.client_host:
        client_ip = _canonicalize_ip(request.client_host)
    else:
        client_ip = UNKNOWN_CLIENT_IDENTITY

    return {
        "check_name": check_name,
        "reason": reason,
        "trigger_info": trigger_info,
        "passive_mode": passive_mode,
        "client_ip": client_ip,
        "path": redact_url_for_display(
            request.url_path, sensitive_params, sensitive_body_fields, sensitive_headers
        ),
        "method": request.method,
        "status_code": status_code,
    }


def fire_block_hook(
    hook: Callable[[SyncGuardRequest, dict[str, object]], object] | None,
    request: SyncGuardRequest,
    check_name: str,
    reason: str,
    trigger_info: str,
    passive_mode: bool,
    status_code: int | None,
    sensitive_params: frozenset[str] | None = None,
    sensitive_body_fields: frozenset[str] | None = None,
    sensitive_headers: frozenset[str] | None = None,
) -> None:
    if hook is None or check_name in ON_BLOCK_EXCLUDED_CHECK_NAMES:
        return
    payload = build_block_payload(
        request,
        check_name,
        reason,
        trigger_info,
        passive_mode,
        status_code,
        sensitive_params,
        sensitive_body_fields,
        sensitive_headers,
    )
    invoke_block_hook(hook, request, payload)
