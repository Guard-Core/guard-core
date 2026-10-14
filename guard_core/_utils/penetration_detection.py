from typing import TYPE_CHECKING

from guard_core._utils.body_content_scan import (
    _scan_headers,
    _scan_query_params,
    _scan_request_body,
)
from guard_core._utils.body_reader import _read_capped_body
from guard_core._utils.detection_config import (
    _resolve_binary_min_run_length,
    _resolve_enabled_categories,
    _resolve_excluded_body_fields,
    _resolve_excluded_headers,
    _resolve_excluded_params,
    _resolve_log_level,
    _resolve_max_json_depth,
    _resolve_max_scan_chars,
    _resolve_max_scan_seconds,
    _resolve_max_scan_values,
    _resolve_scan_body,
    _resolve_semantic_excluded_headers,
    _resolve_sensitive_log_body_fields,
    _resolve_sensitive_log_headers,
    _resolve_sensitive_log_params,
)
from guard_core._utils.detection_result_builders import (
    _build_detection_hit,
    _build_detection_miss,
)
from guard_core._utils.detection_scan import (
    _check_request_component,
    _scan_value_budget,
)
from guard_core._utils.ip_extraction import (
    UNKNOWN_CLIENT_IDENTITY,
    _canonicalize_ip,
    extract_client_ip,
)
from guard_core._utils.request_logging import redact_url_for_display
from guard_core.detection_result import DetectionResult
from guard_core.protocols.request_protocol import GuardRequest

if TYPE_CHECKING:
    from guard_core.decorators.base import RouteConfig
    from guard_core.models import SecurityConfig


async def _scan_request_surface(
    request: GuardRequest,
    excluded_params: set[str],
    excluded_headers: set[str],
    enabled_categories: set[str] | None,
    client_ip: str,
    correlation_id: str,
    log_level: str | None,
    sensitive_headers: frozenset[str],
    sensitive_params: frozenset[str],
    sensitive_body_fields: frozenset[str] = frozenset(),
    excluded_body_fields: frozenset[str] = frozenset(),
) -> DetectionResult | None:
    detected, trigger, threats = await _scan_query_params(
        request,
        excluded_params,
        enabled_categories,
        client_ip,
        correlation_id,
        log_level,
        sensitive_params,
        sensitive_body_fields,
        excluded_body_fields,
        sensitive_headers,
    )
    if detected:
        return _build_detection_hit(trigger, threats)

    redacted_url_path = redact_url_for_display(
        request.url_path, sensitive_params, sensitive_body_fields, sensitive_headers
    )
    detected, trigger, threats = await _check_request_component(
        request.url_path,
        "url_path",
        "URL path",
        client_ip,
        correlation_id,
        enabled_categories,
        log_level,
        content_preview=redacted_url_path,
        sensitive_body_fields=sensitive_body_fields,
        excluded_body_fields=excluded_body_fields,
        json_redact_all=False,
    )
    if detected:
        return _build_detection_hit(f"URL path: {trigger}", threats)

    detected, trigger, threats = await _scan_headers(
        request,
        excluded_headers,
        enabled_categories,
        client_ip,
        correlation_id,
        log_level,
        sensitive_headers,
        sensitive_body_fields,
        excluded_body_fields,
        sensitive_params,
    )
    if detected:
        return _build_detection_hit(trigger, threats)

    return None


async def _scan_body_surface(
    request: GuardRequest,
    config: "SecurityConfig | None",
    route_config: "RouteConfig | None",
    excluded_body_fields: set[str],
    enabled_categories: set[str] | None,
    client_ip: str,
    correlation_id: str,
    log_level: str | None,
    sensitive_body_fields: frozenset[str],
    sensitive_params: frozenset[str] = frozenset(),
) -> DetectionResult:
    if not _resolve_scan_body(config, route_config):
        return _build_detection_miss()

    body_bytes = await _read_capped_body(request, config, client_ip)
    if body_bytes is None:
        return _build_detection_miss()

    raw_body = body_bytes.decode("utf-8", errors="surrogateescape")

    content_type = request.headers.get("content-type") or ""
    detected, trigger, threats = await _scan_request_body(
        raw_body,
        content_type,
        excluded_body_fields,
        enabled_categories,
        client_ip,
        correlation_id,
        log_level,
        sensitive_body_fields,
        sensitive_params,
    )
    if detected:
        return _build_detection_hit(trigger, threats)
    return _build_detection_miss()


def _ensure_detection_singleton_configured(config: "SecurityConfig | None") -> None:
    if config is None:
        return

    from guard_core.handlers.suspatterns_handler import sus_patterns_handler

    if (
        sus_patterns_handler._detection_state.compiler is None
        or sus_patterns_handler._config is not config
    ):
        sus_patterns_handler.configure(config)


async def detect_penetration_attempt(
    request: GuardRequest,
    config: "SecurityConfig | None" = None,
    route_config: "RouteConfig | None" = None,
) -> DetectionResult:
    import uuid

    _ensure_detection_singleton_configured(config)

    if config is not None:
        client_ip = await extract_client_ip(request, config)
    else:
        client_ip = (
            _canonicalize_ip(request.client_host)
            if request.client_host
            else UNKNOWN_CLIENT_IDENTITY
        )
    correlation_id = str(uuid.uuid4())

    excluded_params = _resolve_excluded_params(config, route_config)
    excluded_body_fields = _resolve_excluded_body_fields(config, route_config)
    enabled_categories = _resolve_enabled_categories(config, route_config)
    excluded_headers = _resolve_excluded_headers(config, route_config)
    log_level = _resolve_log_level(config)
    sensitive_headers = _resolve_sensitive_log_headers(config)
    sensitive_params = _resolve_sensitive_log_params(config)
    sensitive_body_fields = _resolve_sensitive_log_body_fields(config)
    max_scan_values = _resolve_max_scan_values(config)
    max_json_depth = _resolve_max_json_depth(config)
    max_scan_chars = _resolve_max_scan_chars(config)
    binary_min_run = _resolve_binary_min_run_length(config)
    max_scan_seconds = _resolve_max_scan_seconds(config)
    semantic_excluded_headers = _resolve_semantic_excluded_headers(config, route_config)

    with _scan_value_budget(
        max_scan_values,
        max_json_depth,
        max_scan_chars,
        binary_min_run,
        max_scan_seconds,
        semantic_excluded_headers,
    ):
        surface_hit = await _scan_request_surface(
            request,
            excluded_params,
            excluded_headers,
            enabled_categories,
            client_ip,
            correlation_id,
            log_level,
            sensitive_headers,
            sensitive_params,
            sensitive_body_fields,
            frozenset(excluded_body_fields),
        )
        if surface_hit is not None:
            return surface_hit

        return await _scan_body_surface(
            request,
            config,
            route_config,
            excluded_body_fields,
            enabled_categories,
            client_ip,
            correlation_id,
            log_level,
            sensitive_body_fields,
            sensitive_params,
        )
