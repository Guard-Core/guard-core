from collections.abc import Mapping
from typing import TYPE_CHECKING

from guard_core._utils.body_content_scan import (
    _scan_headers,
    _scan_query_param_value,
    _scan_query_params,
    _scan_request_body,
)
from guard_core._utils.body_reader import (
    _read_capped_body_or_raise,
    inspect_limit_fix_hint,
    read_body_for_inspection,
    resolve_inspect_cap,
)
from guard_core._utils.detection_config import (
    _resolve_binary_min_run_length,
    _resolve_body_field_category_skips,
    _resolve_declared_path_params,
    _resolve_enabled_categories,
    _resolve_excluded_body_fields,
    _resolve_excluded_headers,
    _resolve_excluded_params,
    _resolve_log_level,
    _resolve_max_json_depth,
    _resolve_max_scan_chars,
    _resolve_max_scan_seconds,
    _resolve_max_scan_values,
    _resolve_operator_excluded_headers,
    _resolve_scan_body,
    _resolve_semantic_excluded_headers,
    _resolve_sensitive_log_body_fields,
    _resolve_sensitive_log_headers,
    _resolve_sensitive_log_params,
)
from guard_core._utils.detection_result_builders import (
    _build_body_read_error,
    _build_detection_hit,
    _build_detection_miss,
)
from guard_core._utils.detection_scan import (
    LazyPreview,
    _budget_that_is_never_spent,
    _check_request_component,
    _scan_value_budget,
)
from guard_core._utils.ip_extraction import (
    UNKNOWN_CLIENT_IDENTITY,
    _canonicalize_ip,
    extract_client_ip,
)
from guard_core._utils.request_logging import redact_url_for_display
from guard_core._utils.request_path import resolve_dot_and_empty_segments
from guard_core._utils.route_gate import (
    declared_path_param_values,
    declared_path_params_var,
    route_knowledge,
    route_state_template,
    scanning_declared_path_param_values,
    static_file_state_served,
)
from guard_core._utils.scan_config_scope import (
    ScanConfigScope,
    configure_lock,
    scan_config_scope_of,
)
from guard_core.detection_engine.compressed_payloads import (
    bounded_inflate,
    looks_like_gzip,
)
from guard_core.detection_result import DetectionResult
from guard_core.exceptions import BodyReadFailedError, BodyReadStalledError
from guard_core.handlers._suspatterns_sources import (
    _DEFAULT_MAX_BODY_INSPECT_BYTES,
    _scan_window_bytes,
)
from guard_core.protocols.request_protocol import GuardRequest

if TYPE_CHECKING:
    from guard_core.decorators.base import RouteConfig
    from guard_core.handlers.suspatterns_handler import SusPatternsManager
    from guard_core.models import SecurityConfig


async def _scan_url_path_variants(
    request: GuardRequest,
    redacted_url_path: LazyPreview,
    client_ip: str,
    correlation_id: str,
    enabled_categories: set[str] | None,
    log_level: str | None,
    sensitive_body_fields: frozenset[str],
    excluded_body_fields: frozenset[str],
    *,
    patterns: "SusPatternsManager | None" = None,
) -> tuple[bool, str, list[dict]]:
    literal_path = request.url_path
    resolved_path = resolve_dot_and_empty_segments(literal_path)
    variants = (
        (literal_path,)
        if resolved_path == literal_path
        else (literal_path, resolved_path)
    )
    detected, trigger, threats = False, "", list[dict]()
    for variant in variants:
        with _budget_that_is_never_spent():
            detected, trigger, threats = await _check_request_component(
                variant,
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
                patterns=patterns,
            )
        if detected:
            break
    return detected, trigger, threats


async def _scan_declared_path_param_values(
    request: GuardRequest,
    enabled_categories: set[str] | None,
    client_ip: str,
    correlation_id: str,
    log_level: str | None,
    sensitive_params: frozenset[str],
    sensitive_body_fields: frozenset[str],
    excluded_body_fields: frozenset[str],
    sensitive_headers: frozenset[str],
    *,
    patterns: "SusPatternsManager | None" = None,
) -> tuple[bool, str, list[dict]]:
    for name, value in declared_path_param_values(request.url_path):
        with scanning_declared_path_param_values():
            detected, trigger, threats = await _scan_query_param_value(
                name,
                name,
                value,
                enabled_categories,
                client_ip,
                correlation_id,
                log_level,
                sensitive_params,
                sensitive_body_fields,
                excluded_body_fields,
                sensitive_headers,
                patterns=patterns,
            )
        if detected:
            return True, f"Path param '{name}': {trigger}", threats
    return False, "", []


async def _scan_request_surface(
    request: GuardRequest,
    excluded_params: Mapping[str, frozenset[str]],
    excluded_headers: set[str],
    enabled_categories: set[str] | None,
    client_ip: str,
    correlation_id: str,
    log_level: str | None,
    sensitive_headers: frozenset[str],
    sensitive_params: frozenset[str],
    sensitive_body_fields: frozenset[str] = frozenset(),
    excluded_body_fields: frozenset[str] = frozenset(),
    operator_excluded_headers: frozenset[str] = frozenset(),
    *,
    patterns: "SusPatternsManager | None" = None,
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
        patterns=patterns,
    )
    if detected:
        return _build_detection_hit(trigger, threats)

    redacted_url_path = LazyPreview(
        lambda: redact_url_for_display(
            request.url_path,
            sensitive_params,
            sensitive_body_fields,
            sensitive_headers,
        )
    )
    detected, trigger, threats = await _scan_url_path_variants(
        request,
        redacted_url_path,
        client_ip,
        correlation_id,
        enabled_categories,
        log_level,
        sensitive_body_fields,
        excluded_body_fields,
        patterns=patterns,
    )
    if detected:
        return _build_detection_hit(f"URL path: {trigger}", threats)

    if declared_path_params_var.get():
        detected, trigger, threats = await _scan_declared_path_param_values(
            request,
            enabled_categories,
            client_ip,
            correlation_id,
            log_level,
            sensitive_params,
            sensitive_body_fields,
            excluded_body_fields,
            sensitive_headers,
            patterns=patterns,
        )
        if detected:
            return _build_detection_hit(trigger, threats)

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
        operator_excluded_headers,
        patterns=patterns,
    )
    if detected:
        return _build_detection_hit(trigger, threats)

    return None


_BODY_PAST_CAP_DETAIL = (
    "the body is past the inspect cap, so only its first bytes were scanned"
)


_BODY_DECOMPRESSED_PAST_CAP_DETAIL = (
    "the compressed body inflates past the inspect cap or the decompression ratio "
    "bound, so only its first inflated bytes were scanned"
)


def _inflate_gzip_body(
    body_bytes: bytes, inspect_cap: int | None
) -> tuple[bytes, bool]:
    if not looks_like_gzip(body_bytes):
        return body_bytes, False
    inflated = bounded_inflate(
        body_bytes, inspect_cap or _DEFAULT_MAX_BODY_INSPECT_BYTES
    )
    return (body_bytes, False) if inflated is None else inflated


async def _read_body_for_scan(
    request: GuardRequest,
    config: "SecurityConfig | None",
    inspect_cap: int | None,
    client_ip: str,
    *,
    patterns: "SusPatternsManager | None" = None,
) -> tuple[bytes | None, bool]:
    if config is None or inspect_cap is None:
        return (
            await _read_capped_body_or_raise(
                request, config, client_ip, patterns=patterns
            ),
            False,
        )
    return await read_body_for_inspection(
        request, config, client_ip, inspect_cap, patterns=patterns
    )


async def _scan_body_surface(
    request: GuardRequest,
    config: "SecurityConfig | None",
    route_config: "RouteConfig | None",
    inspect_cap: int | None,
    excluded_body_fields: set[str],
    enabled_categories: set[str] | None,
    client_ip: str,
    correlation_id: str,
    log_level: str | None,
    sensitive_body_fields: frozenset[str],
    sensitive_params: frozenset[str] = frozenset(),
    *,
    patterns: "SusPatternsManager | None" = None,
) -> DetectionResult:
    if not _resolve_scan_body(config, route_config):
        return _build_detection_miss()

    try:
        body_bytes, past_cap = await _read_body_for_scan(
            request, config, inspect_cap, client_ip, patterns=patterns
        )
    except BodyReadStalledError as error:
        return _build_body_read_error(True, error.detail)
    except BodyReadFailedError as error:
        return _build_body_read_error(False, error.detail)
    if body_bytes is None:
        return _build_detection_miss()

    body_bytes, decompression_cut = _inflate_gzip_body(body_bytes, inspect_cap)
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
        patterns=patterns,
    )
    if detected:
        return _build_detection_hit(trigger, threats)
    if decompression_cut:
        return _build_body_read_error(False, _BODY_DECOMPRESSED_PAST_CAP_DETAIL)
    if past_cap:
        hint = inspect_limit_fix_hint(content_type)
        return _build_body_read_error(False, f"{_BODY_PAST_CAP_DETAIL} ({hint})")
    return _build_detection_miss()


def _ensure_detection_singleton_configured(
    config: "SecurityConfig | None",
) -> "SusPatternsManager":
    from guard_core.handlers.suspatterns_handler import (
        sus_patterns_handler,
        sus_patterns_manager_for,
    )

    if config is None:
        return sus_patterns_handler
    manager = config._guard_pattern_manager
    if manager is not None and manager._config is config:
        return manager
    bound = sus_patterns_manager_for(config, bind=True)
    if bound._detection_state.compiler is None or bound._config is not config:
        bound.configure(config)
    return bound


def _configured_manager_and_scope(
    config: "SecurityConfig | None",
) -> "tuple[SusPatternsManager, ScanConfigScope | None]":
    with configure_lock:
        manager = _ensure_detection_singleton_configured(config)
        return manager, scan_config_scope_of(config, manager)


async def detect_penetration_attempt(
    request: GuardRequest,
    config: "SecurityConfig | None" = None,
    route_config: "RouteConfig | None" = None,
) -> DetectionResult:
    import uuid

    patterns_manager, config_scope = _configured_manager_and_scope(config)

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
    body_field_category_skips = _resolve_body_field_category_skips(config, route_config)
    enabled_categories = _resolve_enabled_categories(config, route_config)
    excluded_headers = _resolve_excluded_headers(config, route_config)
    operator_excluded_headers = _resolve_operator_excluded_headers(config, route_config)
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
    inspect_cap = (
        None
        if config is None
        else resolve_inspect_cap(
            config, route_config, request.headers.get("content-type")
        )
    )
    # The window is the request's inspect limit, never above the pattern validation cap
    # (the larger of the two limits), which a route raised past both limits keeps.
    scan_window = (
        None if inspect_cap is None else min(inspect_cap, _scan_window_bytes(config))
    )

    with (
        route_knowledge(
            route_state_template(request.state),
            static_file_state_served(request.state),
            _resolve_declared_path_params(route_config),
        ),
        _scan_value_budget(
            max_scan_values,
            max_json_depth,
            max_scan_chars,
            binary_min_run,
            max_scan_seconds,
            semantic_excluded_headers,
            (request, sensitive_params, sensitive_body_fields, sensitive_headers),
            body_field_category_skips,
            patterns_manager,
            config_scope,
            scan_window,
        ),
    ):
        try:
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
                operator_excluded_headers,
                patterns=patterns_manager,
            )
            if surface_hit is not None:
                surface_hit.correlation_id = correlation_id
                return surface_hit

            body_result = await _scan_body_surface(
                request,
                config,
                route_config,
                inspect_cap,
                excluded_body_fields,
                enabled_categories,
                client_ip,
                correlation_id,
                log_level,
                sensitive_body_fields,
                sensitive_params,
                patterns=patterns_manager,
            )
            body_result.correlation_id = correlation_id
            return body_result
        except BodyReadFailedError as error:
            read_error = _build_body_read_error(False, error.detail)
            read_error.correlation_id = correlation_id
            return read_error
