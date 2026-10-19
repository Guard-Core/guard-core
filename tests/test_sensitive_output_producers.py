import ast
from dataclasses import dataclass
from pathlib import Path

import guard_core
from tests.test_sensitive_data_invariant import _CASES, _COMPONENT_SCENARIOS

_CALL_NAMES = frozenset(
    {
        "_log_at_level",
        "log_activity",
        "_log_detected_component",
        "send_event",
        "send_middleware_event",
        "_send_pattern_event",
        "fire_block_hook",
        "build_block_payload",
        "set_attribute",
        "set_attributes",
    }
)
_LOG_LEVEL_METHODS = frozenset(
    {"debug", "info", "warning", "error", "critical", "exception"}
)
_INTERPOLATION_MARKERS = ("request.", "headers", "url", "body", "value")


def _call_name(node: ast.Call) -> str | None:
    func = node.func
    if isinstance(func, ast.Attribute):
        if isinstance(func.value, ast.Name) and func.value.id == "logfire":
            return f"logfire.{func.attr}"
        if func.attr in _CALL_NAMES:
            return func.attr
        if func.attr in _LOG_LEVEL_METHODS:
            return f"logger.{func.attr}"
        return None
    if isinstance(func, ast.Name) and func.id in _CALL_NAMES:
        return func.id
    return None


def _joined_str_has_interpolation(node: ast.JoinedStr) -> bool:
    dumped = ast.dump(node)
    return any(marker in dumped for marker in _INTERPOLATION_MARKERS)


def _call_has_interpolated_argument(node: ast.Call) -> bool:
    for arg in (*node.args, *(kw.value for kw in node.keywords)):
        if isinstance(arg, ast.JoinedStr) and _joined_str_has_interpolation(arg):
            return True
    return False


@dataclass(frozen=True)
class ProducerHit:
    relpath: str
    lineno: int
    qualname: str
    call_name: str
    has_interpolated_argument: bool


class _ProducerWalker(ast.NodeVisitor):
    def __init__(self, relpath: str) -> None:
        self._relpath = relpath
        self._stack: list[str] = []
        self.hits: list[ProducerHit] = []

    def _qualname(self) -> str:
        return ".".join(self._stack) if self._stack else "<module>"

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self._stack.append(node.name)
        self.generic_visit(node)
        self._stack.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_function(node)

    def _visit_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        self._stack.append(node.name)
        self.generic_visit(node)
        self._stack.pop()

    def visit_Call(self, node: ast.Call) -> None:
        name = _call_name(node)
        if name is not None:
            self.hits.append(
                ProducerHit(
                    relpath=self._relpath,
                    lineno=node.lineno,
                    qualname=self._qualname(),
                    call_name=name,
                    has_interpolated_argument=_call_has_interpolated_argument(node),
                )
            )
        self.generic_visit(node)


def _guard_core_root() -> Path:
    return Path(guard_core.__file__).resolve().parent


def collect_producer_hits() -> list[ProducerHit]:
    root = _guard_core_root()
    hits: list[ProducerHit] = []
    for path in sorted(root.rglob("*.py")):
        relative = path.relative_to(root)
        if relative.parts[0] == "sync":
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        walker = _ProducerWalker(relative.as_posix())
        walker.visit(tree)
        hits.extend(walker.hits)
    return hits


def producer_key(relpath: str, qualname: str) -> str:
    return f"{relpath}:{qualname}"


def group_producer_hits(hits: list[ProducerHit]) -> dict[str, list[ProducerHit]]:
    grouped: dict[str, list[ProducerHit]] = {}
    for hit in hits:
        key = producer_key(hit.relpath, hit.qualname)
        grouped.setdefault(key, []).append(hit)
    return grouped


_DETECTION_MATRIX_SCENARIO = "detection_matrix"

COVERED_PRODUCERS: dict[str, frozenset[str]] = {
    "_utils/agent_events.py:send_agent_event": frozenset({"xff_spoof_warning"}),
    "_utils/body_content_scan.py:_scan_body_field": frozenset(
        {_DETECTION_MATRIX_SCENARIO}
    ),
    "_utils/body_content_scan.py:_scan_excluded_header_component": frozenset(
        {_DETECTION_MATRIX_SCENARIO}
    ),
    "_utils/body_content_scan.py:_scan_query_param_value": frozenset(
        {_DETECTION_MATRIX_SCENARIO}
    ),
    "_utils/body_content_scan.py:_scan_sensitive_header": frozenset(
        {_DETECTION_MATRIX_SCENARIO}
    ),
    "_utils/detection_scan.py:_check_request_component": frozenset(
        {_DETECTION_MATRIX_SCENARIO}
    ),
    "_utils/detection_scan.py:_check_value_enhanced": frozenset(
        {_DETECTION_MATRIX_SCENARIO}
    ),
    "_utils/detection_scan.py:_fallback_pattern_check": frozenset(
        {_DETECTION_MATRIX_SCENARIO}
    ),
    "_utils/detection_scan.py:_log_detected_component": frozenset(
        {_DETECTION_MATRIX_SCENARIO}
    ),
    "_utils/detection_scan.py:_scan_char_budget_exhausted": frozenset(
        {"size_query_param_value_over_100_chars_never_partially_leaks"}
    ),
    "_utils/detection_scan.py:_scan_value_budget_exhausted": frozenset(
        {"size_query_param_value_over_100_chars_never_partially_leaks"}
    ),
    "_utils/detection_scan.py:_warn_json_depth_cap_reached_once": frozenset(
        {
            "json_body_sensitive_leaf_deeper_than_max_json_depth_under_"
            "non_sensitive_wrapper",
            "size_json_body_300_level_nested_wrapper_must_not_raise",
        }
    ),
    "_utils/detection_scan.py:_warn_scan_time_cap_reached_once": frozenset(
        {"scan_time_budget_exhausted"}
    ),
    "_utils/ip_extraction.py:_warn_forwarded_header_chain_too_short": frozenset(
        {"xff_spoof_warning"}
    ),
    "_utils/ip_extraction.py:_warn_forwarded_header_depth_overcounts_hops": (
        frozenset({"xff_spoof_warning"})
    ),
    "_utils/ip_extraction.py:_warn_forwarded_header_preempted": frozenset(
        {"xff_spoof_warning"}
    ),
    "_utils/logging_utils.py:_log_at_level": frozenset({_DETECTION_MATRIX_SCENARIO}),
    "_utils/request_logging.py:_dispatch_block_hook": frozenset(
        {"blacklist_hit", "banned_ip"}
    ),
    "_utils/request_logging.py:log_activity": frozenset({_DETECTION_MATRIX_SCENARIO}),
    "core/behavioral/processor.py:BehavioralProcessor._report_decorator_violation": (
        frozenset(
            {"behavior_usage_frequency_endpoint", "behavior_return_pattern_body_scan"}
        )
    ),
    "core/bypass/handler.py:BypassHandler.handle_security_bypass": frozenset(
        {"security_bypass_event"}
    ),
    "core/checks/base.py:SecurityCheck.log_if_allowed": frozenset({"blacklist_hit"}),
    "core/checks/base.py:SecurityCheck.send_event": frozenset({"blacklist_hit"}),
    "core/checks/helpers.py:_try_threshold_ban": frozenset(
        {"suspicious_auto_ban_threshold_1", "blacklist_hit"}
    ),
    "core/checks/helpers.py:emit_access_denied_event": frozenset(
        {"route_ip_restricted"}
    ),
    "core/checks/helpers.py:emit_authentication_failed_event": frozenset(
        {"auth_invalid"}
    ),
    "core/checks/helpers.py:emit_decorator_event": frozenset({"custom_validator_echo"}),
    "core/checks/helpers.py:emit_rate_limit_event": frozenset({"rate_limit_exceeded"}),
    "core/checks/helpers.py:escalate_identity_violation": frozenset({"blacklist_hit"}),
    "core/checks/implementations/authentication.py:"
    "AuthenticationCheck._handle_auth_failure": frozenset(
        {"auth_missing", "auth_invalid"}
    ),
    "core/checks/implementations/custom_request.py:CustomRequestCheck.check": (
        frozenset({"custom_request_check_reason"})
    ),
    "core/checks/implementations/custom_validators.py:"
    "CustomValidatorsCheck.check": frozenset({"custom_validator_echo"}),
    "core/checks/implementations/emergency_mode.py:EmergencyModeCheck._deny": (
        frozenset({"emergency_mode_denied"})
    ),
    "core/checks/implementations/emergency_mode.py:"
    "EmergencyModeCheck._log_allowed": frozenset({"emergency_mode_whitelisted"}),
    "core/checks/implementations/ip_security.py:IpSecurityCheck._check_banned_ip": (
        frozenset({"banned_ip"})
    ),
    "core/checks/implementations/ip_security.py:"
    "IpSecurityCheck._check_global_ip_restrictions": frozenset({"blacklist_hit"}),
    "core/checks/implementations/ip_security.py:"
    "IpSecurityCheck._check_route_ip_restrictions": frozenset({"route_ip_restricted"}),
    "core/checks/implementations/rate_limit.py:"
    "RateLimitCheck._send_rate_limit_event": frozenset({"rate_limit_exceeded"}),
    "core/checks/implementations/referrer.py:"
    "ReferrerCheck._handle_invalid_referrer": frozenset({"referrer_invalid"}),
    "core/checks/implementations/request_logging.py:RequestLoggingCheck.check": (
        frozenset({"custom_request_check_reason"})
    ),
    "core/checks/implementations/request_size_content.py:"
    "RequestSizeContentCheck._check_content_type_allowed": frozenset(
        {"content_type_violation"}
    ),
    "core/checks/implementations/request_size_content.py:"
    "RequestSizeContentCheck._check_request_size_limit": frozenset(
        {
            "request_size_violation",
            "request_size_content_length_malformed_raises",
        }
    ),
    "core/checks/implementations/required_headers.py:"
    "RequiredHeadersCheck._report_header_violation": frozenset(
        {"required_header_missing", "required_header_mismatched"}
    ),
    "core/checks/implementations/suspicious_activity.py:"
    "SuspiciousActivityCheck._handle_suspicious_active_mode": frozenset(
        {"suspicious_auto_ban_threshold_1", _DETECTION_MATRIX_SCENARIO}
    ),
    "core/checks/implementations/suspicious_activity.py:"
    "SuspiciousActivityCheck._handle_suspicious_passive_mode": frozenset(
        {"passive_mode_suspicious", _DETECTION_MATRIX_SCENARIO}
    ),
    "core/checks/implementations/time_window.py:TimeWindowCheck.check": frozenset(
        {"time_window_closed"}
    ),
    "core/checks/implementations/user_agent.py:UserAgentCheck._deny": frozenset(
        {"user_agent_block"}
    ),
    "core/checks/pipeline.py:SecurityCheckPipeline._fire_block_hook": frozenset(
        {"blacklist_hit"}
    ),
    "core/checks/pipeline.py:SecurityCheckPipeline._handle_check_error": frozenset(
        {"request_size_content_length_malformed_raises"}
    ),
    "core/checks/pipeline.py:SecurityCheckPipeline.execute": frozenset(
        {"blacklist_hit"}
    ),
    "core/events/logfire_handler.py:LogfireHandler.send_event": frozenset(
        {"blacklist_hit"}
    ),
    "core/events/logfire_handler.py:LogfireHandler.send_metric": frozenset(
        {"agent_metrics_endpoint"}
    ),
    "core/events/middleware_events.py:SecurityEventBus._lookup_country": frozenset(
        {"blacklist_hit"}
    ),
    "core/events/middleware_events.py:"
    "SecurityEventBus.send_https_violation_event": frozenset(
        {"https_redirect_url_leak"}
    ),
    "core/events/middleware_events.py:SecurityEventBus.send_middleware_event": (
        frozenset({"blacklist_hit"})
    ),
    "core/events/otel_handler.py:OtelHandler._apply_event_attributes": frozenset(
        {"blacklist_hit"}
    ),
    "core/events/otel_handler.py:OtelHandler._forward_enrichment_metadata": (
        frozenset({"blacklist_hit"})
    ),
    "core/validation/validator.py:RequestValidator.is_path_excluded": frozenset(
        {"path_excluded_event"}
    ),
    "decorators/base.py:BaseSecurityDecorator.send_decorator_event": frozenset(
        {"decorator_event_leak"}
    ),
    "handlers/_behavior_action_dispatch.py:"
    "BehaviorActionDispatchMixin._execute_active_mode_action": frozenset(
        {"behavior_usage_frequency_endpoint"}
    ),
    "handlers/_behavior_action_dispatch.py:"
    "BehaviorActionDispatchMixin._execute_ban_action": frozenset(
        {"behavior_usage_frequency_endpoint"}
    ),
    "handlers/_behavior_action_dispatch.py:"
    "BehaviorActionDispatchMixin._send_behavior_event": frozenset(
        {"behavior_usage_frequency_endpoint"}
    ),
    "handlers/_behavior_response_pattern.py:"
    "BehaviorResponsePatternMixin._check_response_pattern": frozenset(
        {"behavior_return_pattern_body_scan"}
    ),
    "handlers/_dynamic_rule_snapshot.py:"
    "DynamicRuleSnapshotMixin._persist_last_known_rules": frozenset(
        {"dynamic_rules_snapshot_no_leak"}
    ),
    "handlers/_ipban_bans.py:IpBanOperationsMixin._warn_if_private_target": (
        frozenset({"suspicious_auto_ban_threshold_1"})
    ),
    "handlers/_ipban_events.py:IpBanEventMixin._send_ban_event": frozenset(
        {"suspicious_auto_ban_threshold_1", "blacklist_hit"}
    ),
    "handlers/_security_headers_events.py:"
    "SecurityHeadersEventsMixin._send_csp_violation_event": frozenset(
        {"security_headers_csp_report"}
    ),
    "handlers/_security_headers_events.py:"
    "SecurityHeadersEventsMixin._send_headers_applied_event": frozenset(
        {"security_headers_csp_report"}
    ),
    "handlers/_security_headers_events.py:"
    "SecurityHeadersEventsMixin.validate_csp_report": frozenset(
        {"security_headers_csp_report"}
    ),
    "handlers/ratelimit_handler.py:RateLimitManager._handle_rate_limit_exceeded": (
        frozenset({"rate_limit_exceeded"})
    ),
    "handlers/ratelimit_handler.py:RateLimitManager._send_rate_limit_event": (
        frozenset({"rate_limit_exceeded"})
    ),
    "handlers/suspatterns_handler.py:SusPatternsManager._send_threat_event": (
        frozenset({_DETECTION_MATRIX_SCENARIO})
    ),
    "_utils/block_events.py:fire_block_hook": frozenset({"blacklist_hit", "banned_ip"}),
}

NON_REQUEST_PRODUCERS: dict[str, str] = {
    "_utils/body_reader.py:_body_read_slot": (
        "logs the configured max_concurrent of body reads when the limit is "
        "reached; a number from the configuration, no request value is "
        "interpolated"
    ),
    "_utils/body_reader.py:_resolve_body_reader_kind": (
        "logs the adapter class name, once per adapter class, when it lacks "
        "read_body_prefix_until_idle; a class name from the adapter's own "
        "code, no request value is interpolated"
    ),
    "_utils/body_reader.py:_read_capped_body": (
        "logs the typed body-read error on the honeypot path: a fixed message "
        "or the exception class name the engine built, never a request value"
    ),
    "core/checks/implementations/suspicious_activity.py:"
    "SuspiciousActivityCheck._handle_body_read_error": (
        "logs 'Request body read stalled|failed for IP: <client identity>' "
        "and sends the matching event; the detail is the typed error's own "
        "fixed text, and the request goes through log_activity and "
        "send_middleware_event, which apply the same redaction as every "
        "other producer in this module, with no header, parameter, URL or "
        "body value interpolated"
    ),
    "core/initialization/_ban_threshold_report.py:"
    "log_unreachable_ban_thresholds_after_rule_change": (
        "advisory naming the configured rate limit, window and ban thresholds "
        "after a dynamic rule changed them; configuration values only, no "
        "request in scope"
    ),
    "handlers/dynamic_rule_handler.py:"
    "DynamicRuleManager._log_unreachable_ban_thresholds_after_swap": (
        "logs the exception of the threshold advisory after a rule swap; the "
        "traceback names configuration values only, no request in scope"
    ),
    "core/routing/resolver.py:RouteConfigResolver._flag_route_unknown_to_decorator": (
        "logs the route id the adapter stamped on the decorated function, once "
        "per route id; no request value is interpolated"
    ),
    "core/checks/implementations/authentication.py:"
    "AuthenticationCheck._verify_credential": (
        "logs the exception type name and traceback of the operator's own "
        "verifier; no request value is interpolated by guard_core"
    ),
    "_emergency_exemptions.py:warn_unexempted_probe_paths": (
        "advisory naming the exclude_paths entries that emergency_exempt_paths "
        "does not cover, logged when emergency mode turns on; operator "
        "configuration only, no request value is interpolated"
    ),
    "handlers/_security_headers_cache.py:"
    "SecurityHeadersCacheMixin._validated_cached_record": (
        "warns that a CSP or HSTS record read back from Redis was ignored; names "
        "the record and the fixed validation reason, sanitised for the log, no "
        "request value is interpolated"
    ),
    "_misconfiguration.py:report_misconfiguration": (
        "startup advisory naming a config field or decorator "
        "argument and its configured value; startup only, no request in scope"
    ),
    "core/checks/route_prefixes.py:warn_unmatched_exclude_paths": (
        "first-request advisory that the adapter's static_route_prefixes() "
        "raised; names the exception repr of the adapter's own routing call, no "
        "request value is interpolated"
    ),
    "core/checks/endpoint_limit_keys.py:_identities_of": (
        "advisory that the adapter's resolve_route() raised for a configured "
        "endpoint_rate_limits key; names the key and the exception repr of the "
        "adapter's own routing call, no request value is interpolated"
    ),
    "core/checks/route_prefixes.py:_warn_once": (
        "first-request advisory naming a configured exclude_paths entry or "
        "endpoint_rate_limits key that matches no route; operator configuration "
        "only, no request value is interpolated"
    ),
    "_pydantic_plugin_mute.py:_mute_pydantic_plugin_instrumentation": (
        "line 46: warns once about pydantic-plugin instrumentation at import "
        "time; no request in scope"
    ),
    "_staged_defaults.py:_warn_redis_default_on": (
        "SecurityConfig construction warning about the unset enable_redis flag, "
        "evaluated before any request, carries no request data"
    ),
    "_staged_defaults.py:_warn_rate_limit_default_in_effect": (
        "SecurityConfig construction warning about the unset rate_limit default, "
        "evaluated before any request, carries no request data"
    ),
    "_staged_defaults.py:_warn_whitelist_access_only_default_off": (
        "SecurityConfig construction warning about an unset config flag, "
        "evaluated before any request, carries no request data"
    ),
    "_staged_defaults.py:_warn_default_redis_prefix": (
        "SecurityConfig construction warning about the default redis_prefix, "
        "evaluated before any request, carries no request data"
    ),
    "_security_config_field_validators.py:_warn_hostile_signal_bans_default_off": (
        "SecurityConfig construction warning about an unset config flag, "
        "evaluated before any request, carries no request data"
    ),
    "_security_config_field_validators.py:_warn_empty_enabled_detection_categories": (
        "line 211: SecurityConfig field-validator warning about the config "
        "value itself, evaluated at config construction, before any request"
    ),
    "_security_config_field_validators.py:_warn_trusted_proxies_prefix_zero": (
        "line 192: SecurityConfig field-validator warning about a configured "
        "CIDR prefix, not request data"
    ),
    "_security_config_field_validators.py:_warn_whitelist_prefix_zero": (
        "line 202: SecurityConfig field-validator warning about a configured "
        "CIDR prefix, not request data"
    ),
    "_security_config_field_validators.py:_warn_exempt_ips_prefix_zero": (
        "line 216: SecurityConfig field-validator warning about a configured "
        "CIDR prefix, not request data"
    ),
    "_utils/access_control.py:_log_country_check_result": (
        "lines 40,45,53,63,70: interpolates only the resolved client_ip and a "
        "2-letter country code from the geolocation lookup, never header/"
        "query/body content; client_ip is outside the secret matrix (see "
        "module docstring policy)"
    ),
    "_utils/agent_events.py:invoke_error_hook": (
        "line 24: logs only the stage name and the on_error hook's own "
        "raised exception text; the hook is caller-authored, not "
        "constructed by guard_core from request content"
    ),
    "_utils/block_events.py:invoke_block_hook": (
        "line 28: logs only 'on_block hook raised: {hook_error}', the "
        "caller-authored hook's own exception, never the request payload "
        "itself (that payload is built separately by build_block_payload, "
        "covered)"
    ),
    "_utils/body_reader.py:_read_and_cache_body": (
        "line 82: logs the adapter class name, accessor method name, and "
        "the *type name* of an unexpected body value, never body bytes"
    ),
    "_utils/body_reader.py:_warn_body_inspect_bytes_cap_reached": (
        "line 118: interpolates only max_bytes (config int) and client_ip, "
        "never body content"
    ),
    "_utils/body_reader.py:_warn_body_inspect_bytes_cap_reached_no_bounded_reader": (
        "line 130: interpolates only max_bytes and client_ip, never body content"
    ),
    "_utils/ip_extraction.py:_resolve_client_ip_from_forwarded_chain": (
        "line 317 (except branch): logs only str(ValueError|IndexError) "
        "raised while parsing an already-extracted IP token, never the raw "
        "X-Forwarded-For header text"
    ),
    "_utils/ip_extraction.py:_warn_forwarded_header_selected_entry_trusted_proxy": (
        "line 258: the only argument is `entry`, a single chain token that "
        "_extract_from_forwarded_header already validated as a parseable IP "
        "address before returning it here; a non-IP (secret) token can "
        "never reach this call"
    ),
    "_utils/logging_utils.py:setup_custom_logging": (
        "line 140: adapter-init helper; the one dynamic value is the "
        "operator-configured log_file path, never request content"
    ),
    "core/bypass/handler.py:BypassHandler.handle_passthrough": (
        "lines 26-31 warning is static text with only a fixed outcome "
        "string; the fire_block_hook call passes the static reason "
        "'Client address could not be determined' and trigger_info='' - "
        "never request-derived text (the path threaded through "
        "build_block_payload is already redacted there, a separately "
        "covered producer)"
    ),
    "core/checks/implementations/custom_validators.py:"
    "CustomValidatorsCheck._handle_honeypot_hit": (
        "the fire_block_hook call passes the static reason 'Honeypot trap "
        "field filled' and trigger_info 'honeypot field filled', never "
        "request-derived text (the path threaded through build_block_payload "
        "is already redacted there, a separately covered producer)"
    ),
    "core/checks/_strike_forget.py:register_strike_middleware": (
        "static text about a middleware that cannot be weakly referenced; "
        "no request content"
    ),
    "handlers/_ipban_queries.py:IpBanQueryMixin._forget_strikes": (
        "logs the unbanned client_ip (outside the secret matrix) and the Redis "
        "exception text; never header, query or body content"
    ),
    "handlers/_ipban_queries.py:IpBanQueryMixin.forget_strikes_inside": (
        "logs only the Redis exception text of the range strike clear; never "
        "header, query or body content"
    ),
    "core/initialization/_whitelist_strikes.py:reset_strikes_for_changed_whitelist": (
        "logs only the Redis exception text of the startup whitelist strike "
        "reset; never header, query or body content"
    ),
    "handlers/ratelimit_handler.py:RateLimitManager._warn_unbound_reset": (
        "static text plus the list of what the reset cleared (fixed phrases); "
        "never header, query or body content"
    ),
    "handlers/_ipban_queries.py:IpBanQueryMixin._forget_all_strikes": (
        "logs only the Redis exception text of the strike clear; never header, "
        "query or body content"
    ),
    "handlers/ratelimit_handler.py:RateLimitManager._clear_redis_state": (
        "logs only the Redis exception text of the rate-limit reset; never "
        "header, query or body content"
    ),
    "handlers/ratelimit_handler.py:RateLimitManager._guarded_apps_to_reset": (
        "logs the count of guarded apps and their config object identities "
        "(memory addresses); never header, query or body content"
    ),
    "core/checks/_shared_strikes.py:record_shared_detection_strikes": (
        "logs only the Redis exception text of the shared detection strike "
        "counter; never header, query or body content"
    ),
    "core/checks/_shared_strikes.py:read_shared_detection_categories": (
        "logs only the Redis exception text of the shared detection category "
        "read; never header, query or body content"
    ),
    "core/checks/_shared_strikes.py:forget_shared_detection_strikes": (
        "logs the banned client_ip (outside the secret matrix) and the Redis "
        "exception text; never header, query or body content"
    ),
    "core/checks/helpers.py:_emit_ban_escalation_failed": (
        "line 335: reason is f'Escalation ban failed for {client_ip}: "
        "{error}' - client_ip plus the ban_ip() call's own exception; "
        "ban_ip() (handlers/_ipban_bans.py) never raises with header/query/"
        "body content embedded in its message"
    ),
    "core/checks/helpers.py:_log_exception_safely": (
        "lines 346,348: logger.exception(message, *args) where callers "
        "only ever pass the static string 'escalate_identity_violation "
        "failed for %s' plus client_ip - never request content"
    ),
    "core/checks/implementations/cloud_provider.py:CloudProviderCheck.check": (
        "reason is f'Blocked cloud provider IP: {client_ip}' plus the "
        "provider name and network CIDR from the cloud range tables, and "
        "send_cloud_detection_events forwards only client_ip/provider/"
        "network - never header/query/body content; client_ip is outside "
        "the secret matrix"
    ),
    "core/checks/implementations/cloud_provider.py:"
    "CloudProviderCheck._emit_global_cloud_ip_blocked_event": (
        "the ip_blocked event carries client_ip and either the static "
        "'Blocked cloud provider IP' text or the provider name and network "
        "CIDR from the cloud range tables - never header/query/body content; "
        "client_ip is outside the secret matrix"
    ),
    "core/checks/implementations/referrer.py:ReferrerCheck._handle_missing_referrer": (
        "line 32: reason is the static string 'Missing referrer header' - "
        "no request data, since the header is by definition absent on "
        "this path"
    ),
    "core/checks/implementations/route_config.py:RouteConfigCheck._allow_header": (
        "line 63: the message is a fixed string, no request data and no "
        "exception text or traceback"
    ),
    "core/checks/implementations/route_config.py:RouteConfigCheck._unresolved_status": (
        "line 75: the message is a fixed string, no request data and no "
        "exception text or traceback"
    ),
    "core/checks/implementations/route_config.py:"
    "RouteConfigCheck._handle_unresolved_route": (
        "line 22: reason is the module constant UNRESOLVED_ROUTE_REASON, a "
        "fixed string with no interpolation of any kind"
    ),
    "core/checks/implementations/suspicious_activity.py:"
    "SuspiciousActivityCheck._record_served_static_file": (
        "logs the fixed text 'static_file_exists failed; the path is judged without "
        "it' when an adapter's static_file_exists raises; no request value is "
        "interpolated"
    ),
    "handlers/_suspatterns_registry.py:_reconciled_custom_patterns": (
        "logs the fixed text that patterns:custom_list is not what "
        "patterns:custom splits into and that patterns:custom is used; no stored "
        "pattern and no request value is interpolated"
    ),
    "core/checks/implementations/suspicious_activity.py:"
    "SuspiciousActivityCheck._record_route_template": (
        "logs the fixed text 'route_template failed; the path is judged without "
        "it' when an adapter's route_template raises; no request value is "
        "interpolated"
    ),
    "core/checks/implementations/suspicious_activity.py:"
    "SuspiciousActivityCheck.check": (
        "line 158 (disabled_by_decorator branch): reason is the static "
        "string 'Suspicious pattern detection disabled by route decorator'"
    ),
    "core/checks/implementations/time_window.py:TimeWindowCheck._check_time_window": (
        "line 51: logs f'Error checking time window: {error}' where "
        "time_restrictions is the operator/decorator-configured dict, not "
        "request data; the exception concerns malformed config values"
    ),
    "core/checks/pipeline.py:SecurityCheckPipeline._handle_rebuild_error": (
        "line 142: the message text is f'Error rebuilding security checks: "
        "{error}' (the rebuild_checks callable's own exception, never "
        "request content); request.url_path/method are threaded only "
        "through extra=, which the default logging.Formatter never renders "
        "into caplog.text or any other producer surface in this suite "
        "(verified directly by the pipeline_rebuild_error_path_leak "
        "scenario, which forces this exact branch with a secret in the "
        "path and observes no leak)"
    ),
    "core/events/composite_handler.py:CompositeAgentHandler.flush_buffer": (
        "line 90: logger.exception on a sub-handler's flush_buffer failure "
        "- exception text only, no request in scope for this lifecycle call"
    ),
    "core/events/composite_handler.py:CompositeAgentHandler.get_dynamic_rules": (
        "line 99: logger.exception on a sub-handler failure fetching "
        "policy rules - exception text only, no request in scope"
    ),
    "core/events/composite_handler.py:CompositeAgentHandler.health_check": (
        "line 110: logger.exception on a sub-handler health-check failure "
        "- exception text only, no request in scope"
    ),
    "core/events/composite_handler.py:CompositeAgentHandler.initialize_redis": (
        "line 65: logger.exception on a sub-handler init failure - "
        "exception text only, no request in scope"
    ),
    "core/events/composite_handler.py:CompositeAgentHandler.send_event": (
        "line 44: forwards an already-built SecurityEvent object to each "
        "sub-handler (that event's own content is assessed at its origin "
        "producer); line 46's logger.exception on a sub-handler failure is "
        "exception text only"
    ),
    "core/events/composite_handler.py:CompositeAgentHandler.send_metric": (
        "line 58: logger.exception on a sub-handler send_metric failure - "
        "exception text only"
    ),
    "core/events/composite_handler.py:CompositeAgentHandler.start": (
        "line 75: logger.error on a sub-handler start() failure - "
        "exception text only, no request in scope"
    ),
    "core/events/composite_handler.py:CompositeAgentHandler.stop": (
        "line 83: logger.exception on a sub-handler stop() failure - "
        "exception text only, no request in scope"
    ),
    "core/events/enricher.py:EventEnricher.enrich_event": (
        "line 75: logger.exception when enrichment of an already-built "
        "event fails - exception text only; the event's own content is "
        "assessed at its origin producer"
    ),
    "core/events/enricher.py:EventEnricher.enrich_metric": (
        "line 84: logger.exception when enrichment of an already-built "
        "metric fails - exception text only"
    ),
    "core/events/logfire_handler.py:LogfireHandler.start": (
        "lines 29,36: 'logfire not installed' / 'logfire already "
        "configured' warnings plus logfire.configure(service_name=...) - "
        "process lifecycle only, never called by any invariant scenario "
        "(request/response wiring bypasses .start() the same way the "
        "OTel idiom bypasses OtelHandler.start()), no request data"
    ),
    "core/events/logfire_handler.py:LogfireHandler.stop": (
        "line 52: logfire.shutdown() - process lifecycle only, no request "
        "data, not called by any scenario"
    ),
    "core/events/metrics.py:MetricsCollector.send_metric": (
        "line 46: logger.error('Failed to send metric to agent: {e}') "
        "fires only on a send failure; e is the agent_handler's own "
        "transport exception, not request content (the metric's own "
        "content is assessed at collect_request_metrics, covered)"
    ),
    "core/events/otel_handler.py:OtelHandler._claim_meter_provider": (
        "line 118: ambient-provider ownership warning, ownership/ "
        "lifecycle state only, no request data; not reached since "
        "OtelHandler.start() is never called by any scenario (the tracer "
        "is wired directly, matching the repo's established idiom)"
    ),
    "core/events/otel_handler.py:OtelHandler._claim_tracer_provider": (
        "line 100: ambient-provider ownership warning, same as "
        "_claim_meter_provider - not reached, no request data"
    ),
    "core/events/otel_handler.py:OtelHandler.send_metric": (
        "line 216: 'Unknown OTEL metric type %s' fires only for a "
        "metric_type outside the small fixed set of METRIC_* constants in "
        "event_types.py - never request-derived text"
    ),
    "core/events/otel_handler.py:OtelHandler.start": (
        "line 64: provider-claim lifecycle warning; not reached, since no "
        "scenario calls OtelHandler.start()"
    ),
    "core/initialization/_handler_initializer_steps.py:"
    "_HandlerInitializerStepsMixin._connect_redis": (
        "line 92: Redis-unavailable-at-startup error; adapter init only, "
        "no request in scope"
    ),
    "core/initialization/_route_limit_report.py:"
    "report_route_limits_with_global_switch_off": (
        "startup INFO naming the route ids whose own rate limits stay "
        "on while enable_rate_limiting is False; adapter init only, no request "
        "in scope"
    ),
    "core/initialization/_handler_initializer_steps.py:"
    "_HandlerInitializerStepsMixin._run_lazy_init": (
        "lines 39,47: lazy cloud-IP/geo-IP init failure warnings; adapter "
        "init only, no request in scope"
    ),
    "core/initialization/_handler_initializer_steps.py:"
    "_HandlerInitializerStepsMixin._warn_if_lazy_init_is_inert": (
        "line 71: static advisory about lazy_init without Redis; adapter "
        "init only, no request in scope"
    ),
    "core/initialization/_handler_initializer_steps.py:"
    "_HandlerInitializerStepsMixin.initialize_dynamic_rule_manager": (
        "line 167: static advisory about dynamic rules without an agent; "
        "adapter init only, no request in scope"
    ),
    "core/responses/factory.py:ErrorResponseFactory.apply_modifier": (
        "line 72: logger.exception when the operator's own "
        "custom_response_modifier callback raises; exc is that callback's "
        "exception, not text guard_core constructs from request data"
    ),
    "core/validation/validator.py:RequestValidator.check_time_window": (
        "line 65: logs f'Error checking time window: {error}' where "
        "time_restrictions is the decorator-configured dict, not request "
        "data (mirrors TimeWindowCheck._check_time_window)"
    ),
    "decorators/access_control.py:AccessControlMixin.bypass.decorator": (
        "line 78: 'ignored unknown checks %s' where the list comes from "
        "the @bypass(...) decorator argument, evaluated once at "
        "route-definition time, never per-request"
    ),
    "decorators/advanced.py:_log_unparsable_json": (
        "logs a fixed message for a too-deeply-nested body, or the "
        "JSONDecodeError str(), which is built from parse-position numbers "
        "and never carries a copy of the body text or honeypot field values"
    ),
    "decorators/advanced.py:_warn_if_body_not_fully_inspected": (
        "logs only the configured detection_max_body_inspect_bytes limit, "
        "never any request value or client address"
    ),
    "detection_engine/_redos_cost_arbiter.py:_log_structural_disagreement": (
        "line 183: logs the regex *rule* text being validated at compile "
        "time (an admin-authored pattern) plus internal analysis labels, "
        "never a scanned request value"
    ),
    "detection_engine/_redos_cost_arbiter.py:_stride_sampled_probe_sets": (
        "line 366: logs only the sampled and total probe-set counts and "
        "the stride length; no pattern text or scanned value is involved"
    ),
    "detection_engine/_validation_cache.py:PatternValidationCache._load": (
        "lines 57,75: the warning carries only the OSError/ValueError text "
        "from reading or parsing the cache file; no pattern, verdict, or "
        "scanned value is interpolated"
    ),
    "detection_engine/_validation_cache.py:PatternValidationCache._save": (
        "line 114: the warning carries only the OSError text from the "
        "atomic write; no pattern or verdict is interpolated"
    ),
    "detection_engine/compiler.py:report_scan_timeout": (
        "line 63: takes no arguments beyond a module-global consecutive-"
        "timeout counter; no pattern or scanned value is even accessible "
        "here"
    ),
    "detection_engine/monitor.py:PerformanceMonitor._send_anomaly_event": (
        "lines 156,158: the anomaly event carries only pattern.pattern "
        "(rule text), execution_time, and content_length (an int); the "
        "logger.error fallback is exception text about the agent send"
    ),
    "detection_engine/monitor.py:PerformanceMonitor._send_callback_error_event": (
        "lines 175,177: carries str(error) from a user monitor-callback's "
        "own exception plus the same pattern-only anomaly summary, never "
        "scanned content"
    ),
    "detection_engine/preprocessor.py:ContentPreprocessor._send_preprocessor_event": (
        "lines 100,105: callers only ever pass a fixed reason string "
        "('Failed to URL/HTML decode content') and str(e) from a stdlib "
        "unquote/unescape failure; the raw content being preprocessed is "
        "never passed into this function"
    ),
    "detection_engine/semantic.py:SemanticAnalyzer._check_ast_parsing_risk": (
        "line 305: fixed message 'AST parsing risk check failed and was "
        "skipped' with exc_info=True; the parsed content variable is never "
        "interpolated into the message"
    ),
    "handlers/_behavior_response_pattern.py:"
    "BehaviorResponsePatternMixin._log_body_unavailable": (
        "line 28: logs only the admin-configured rule.pattern string "
        "(e.g. 'password'), never the response/request body"
    ),
    "handlers/_cloud_azure_fetch.py:_select_azure_cloud_prefixes": (
        "line 155: Azure service-tags parsing failure - provider-fetch "
        "infra only, no request in scope"
    ),
    "handlers/_cloud_azure_fetch.py:_warn_if_service_tags_url_is_stale": (
        "lines 91,99: stale service-tags URL warnings - infra only"
    ),
    "handlers/_cloud_azure_fetch.py:fetch_azure_ip_ranges": (
        "line 197: provider IP-range fetch failure - infra only"
    ),
    "handlers/_cloud_provider_fetchers.py:fetch_aws_ip_ranges": (
        "line 32: provider IP-range fetch failure - infra only"
    ),
    "handlers/_cloud_provider_fetchers.py:fetch_digitalocean_ip_ranges": (
        "line 98: provider IP-range fetch failure - infra only"
    ),
    "handlers/_cloud_provider_fetchers.py:fetch_gcp_ip_ranges": (
        "line 60: provider IP-range fetch failure - infra only"
    ),
    "handlers/_cloud_provider_fetchers.py:fetch_linode_ip_ranges": (
        "line 108: provider IP-range fetch failure - infra only"
    ),
    "handlers/_cloud_provider_fetchers.py:fetch_vultr_ip_ranges": (
        "line 133: provider IP-range fetch failure - infra only"
    ),
    "handlers/_dynamic_rule_application.py:DynamicRuleApplicationMixin._revoke_owned": (
        "lines 59,61,66,71: revoking SaaS-pushed bans and patterns, not a request"
    ),
    "handlers/_dynamic_rule_application.py:"
    "DynamicRuleApplicationMixin._stale_rule_bans": (
        "line 221: listing the bans a SaaS-pushed rule owns, not a request"
    ),
    "handlers/_dynamic_rule_application.py:"
    "DynamicRuleApplicationMixin._announce_emergency_mode": (
        "line 65: reports on a SaaS-pushed emergency-mode policy change, "
        "never an inbound HTTP request"
    ),
    "handlers/_dynamic_rule_application.py:"
    "DynamicRuleApplicationMixin._apply_ip_bans": (
        "lines 39,41: applying SaaS-pushed IP-ban policy, not a request"
    ),
    "handlers/_dynamic_rule_application.py:DynamicRuleApplicationMixin._ban_rule_ip": (
        "line 118: applying SaaS-pushed IP-ban policy, not a request"
    ),
    "handlers/_dynamic_rule_application.py:"
    "DynamicRuleApplicationMixin._apply_ip_whitelist": (
        "lines 49,51: applying SaaS-pushed IP-whitelist policy, not a request"
    ),
    "handlers/_dynamic_rule_application.py:"
    "DynamicRuleApplicationMixin._apply_pattern_rules": (
        "lines 142,147: applying SaaS-pushed suspicious-pattern policy, not a "
        "request; the logged pattern text is also now redacted via "
        "_redact_pattern_source, in case a pushed pattern's source is secret-shaped"
    ),
    "handlers/_dynamic_rule_events.py:"
    "DynamicRuleEventSenderMixin._send_emergency_event": (
        "lines 95,97: reports on a SaaS-pushed emergency-mode policy "
        "change, not a request; logger.error fallback is send-failure text"
    ),
    "handlers/_dynamic_rule_events.py:"
    "DynamicRuleEventSenderMixin._send_rule_rejected_event": (
        "lines 107,109: reports on a rejected SaaS-pushed rule, not a request; "
        "logger.error fallback is send-failure text"
    ),
    "handlers/_dynamic_rule_events.py:"
    "DynamicRuleEventSenderMixin._send_rule_applied_event": (
        "lines 69,71: reports on a SaaS-pushed rule application, not a request"
    ),
    "handlers/_dynamic_rule_events.py:"
    "DynamicRuleEventSenderMixin._send_rule_received_event": (
        "lines 40,42: reports on a SaaS-pushed rule receipt, not a request"
    ),
    "handlers/_dynamic_rule_snapshot.py:"
    "DynamicRuleSnapshotMixin._hydrate_last_known_rules": (
        "lines 38,43: restoring the last-known DynamicRules snapshot at "
        "startup - policy data, not a request; DynamicRules has no field "
        "carrying request content (see the dynamic_rules_snapshot_no_leak "
        "scenario's persisted-payload assertion)"
    ),
    "handlers/_dynamic_rule_snapshot.py:"
    "DynamicRuleSnapshotMixin._load_last_known_rules": (
        "line 55: 'Discarding expired last-known dynamic rules' - policy "
        "metadata only (rule_id/version), not a request"
    ),
    "handlers/_dynamic_rule_snapshot.py:"
    "DynamicRuleSnapshotMixin._parse_last_known_rules": (
        "line 97: 'Discarding unusable last-known dynamic rules payload: "
        "{e}' - a JSON/pydantic parse error on the policy snapshot, not a "
        "request"
    ),
    "handlers/_dynamic_rule_snapshot.py:DynamicRuleSnapshotMixin._read_file_payload": (
        "line 90: file-read error for the snapshot cache path (config "
        "value), not a request"
    ),
    "handlers/_dynamic_rule_snapshot.py:DynamicRuleSnapshotMixin._read_redis_payload": (
        "line 73: Redis-read error for the snapshot key, not a request"
    ),
    "core/events/composite_handler.py:CompositeAgentHandler.get_status": (
        "line 110: logs.exception for a failing handler's get_status call, no "
        "request content"
    ),
    "core/initialization/_handler_initializer_steps.py:"
    "_HandlerInitializerStepsMixin._purge_configured_dynamic_rules": (
        "line 181: logs.exception when the start-time purge of a configured rule "
        "set fails, no request content"
    ),
    "handlers/_dynamic_rule_purge.py:"
    "DynamicRulePurgeMixin._agent_status_with_rules_check_time": (
        "line 250: failure reading the agent status, no request content"
    ),
    "handlers/_dynamic_rule_purge.py:DynamicRulePurgeMixin._clear_purge_marker": (
        "line 195: Redis failure deleting the purge marker, no request content"
    ),
    "handlers/_dynamic_rule_purge.py:DynamicRulePurgeMixin._parse_if_holding": (
        "line 115: a parse error on the policy snapshot while purging, not a request"
    ),
    "handlers/_dynamic_rule_purge.py:DynamicRulePurgeMixin._read_purge_marker": (
        "line 181: an unusable purge marker value, not a request"
    ),
    "handlers/_dynamic_rule_purge.py:DynamicRulePurgeMixin._remove_purged_patterns": (
        "line 129: failure removing a purged pattern; the message carries the "
        "error only, not the pattern or a request"
    ),
    "handlers/_dynamic_rule_purge.py:DynamicRulePurgeMixin._revert_if_purged": (
        "lines 226,227: failure removing a purged pattern (error only) and the "
        "rule id and version a worker reverted from, not a request"
    ),
    "handlers/_dynamic_rule_purge.py:DynamicRulePurgeMixin._write_purge_marker": (
        "line 157: Redis failure writing the purge marker, no request content"
    ),
    "handlers/_dynamic_rule_purge.py:"
    "DynamicRulePurgeMixin.purge_configured_dynamic_rules": (
        "line 62: the start WARNING naming the configured rule_id:version, not a "
        "request"
    ),
    "handlers/_dynamic_rule_purge.py:DynamicRulePurgeMixin.purge_dynamic_rules": (
        "line 90: the purge INFO with rule id, version and ban counts, not a request"
    ),
    "handlers/_ipban_bans.py:IpBanOperationsMixin.purge_rule_owned_bans": (
        "line 191: a failed rule-ban purge logs the ban key and the error; the "
        "key is a ban-target address, outside the secret matrix"
    ),
    "handlers/_ipban_bans.py:IpBanOperationsMixin._log_refused_ban": (
        "line 124: logs the ban-target IP and the overlapping loopback/"
        "trusted-proxy CIDR only; client_ip is outside the secret matrix"
    ),
    "handlers/_ipban_bans.py:IpBanOperationsMixin._refuse_rule_exempt_target": (
        "line 137: logs the ban-target IP covered by a dynamic ip_whitelist "
        "entry only; client_ip is outside the secret matrix"
    ),
    "handlers/_ipban_queries.py:IpBanQueryMixin._unban_redis_inside": (
        "line 151: Redis range-unban failure for SaaS-pushed policy, infra only"
    ),
    "core/checks/implementations/rate_limit.py:"
    "RateLimitCheck._log_non_ip_ban_refusal": (
        "logs the non-IP client identity, always the literal 'unknown', once per "
        "process; never header, query or body content"
    ),
    "handlers/_ipban_events.py:IpBanEventMixin._send_ban_refused_event": (
        "the event carries the ban-target IP (outside the secret matrix), the "
        "refusal kind and the caller-supplied ban reason; logger.error fallback is "
        "send-failure text"
    ),
    "handlers/_ipban_events.py:IpBanEventMixin._send_unban_event": (
        "line 49: unban is never exercised by any scenario; the event "
        "carries only ip/reason (ip outside the secret matrix, reason is "
        "the caller-supplied unban reason string, never header/query/body "
        "content per the ban_ip/unban_ip call sites in _ipban_bans.py/"
        "_ipban_queries.py); logger.error fallback is send-failure text"
    ),
    "handlers/_ipban_migration.py:IpBanMigrationMixin._migrate_legacy_ban_keys": (
        "lines 32,44: legacy Redis key-format migration at startup, no request in scope"
    ),
    "handlers/_security_headers_cache.py:"
    "SecurityHeadersCacheMixin._cache_configuration": (
        "line 101: Redis-cache-write failure for the security-headers "
        "config blob, not a request"
    ),
    "handlers/_security_headers_cache.py:"
    "SecurityHeadersCacheMixin._load_cached_config": (
        "line 70: Redis-cache-read failure for the security-headers "
        "config blob, not a request"
    ),
    "handlers/_security_headers_cache.py:SecurityHeadersCacheMixin.reset": (
        "line 121: Redis-reset failure, not a request"
    ),
    "handlers/_security_headers_override_state.py:SecurityHeadersOverrideMixin."
    "_adopt_cleared_override": ("line 206: fixed text, no data"),
    "handlers/_security_headers_override_state.py:SecurityHeadersOverrideMixin."
    "_log_override_change": (
        "lines 95 and 105: operator-configured header names and values of a "
        "configure() call, every value through _redact_sensitive_headers (name "
        "tokens and value redaction), then _sanitize_for_log; no request data"
    ),
    "handlers/_security_headers_override_state.py:SecurityHeadersOverrideMixin."
    "_pull_override": (
        "lines 172, 184 and 193: Redis read failure text, unreadable-record "
        "text and the pulled override's header names, values through "
        "_redact_sensitive_headers; no request data"
    ),
    "handlers/_security_headers_override_state.py:SecurityHeadersOverrideMixin."
    "_save_override_record": ("line 158: Redis write failure text, not a request"),
    "handlers/_security_headers_override_state.py:SecurityHeadersOverrideMixin."
    "_send_override_event_for": (
        "lines 228 and 230: the override event carries the redacted override "
        "and dropped values (_redact_sensitive_headers) and key names; the "
        "failure line carries redacted exception text; no request data"
    ),
    "handlers/_security_headers_override_state.py:SecurityHeadersOverrideMixin."
    "_apply_shared_own_state": (
        "line 339: the failure text of unreadable cached own state in Redis, "
        "redacted by _sanitize_for_log; no request data"
    ),
    "handlers/_security_headers_override_state.py:SecurityHeadersOverrideMixin."
    "_log_cors_override": (
        "lines 127, 131 and 138: operator-configured CORS origins and flags of "
        "a flagged configure() call and a fixed reason string; no request data"
    ),
    "handlers/_security_headers_config.py:"
    "SecurityHeadersConfigMixin._compute_cors_config": (
        "line 95: CORS config validation error at construction time or "
        "per-config header resolution, not a request"
    ),
    "handlers/_security_headers_config.py:"
    "SecurityHeadersConfigMixin._compute_csp_config": (
        "line 43: CSP config validation warning at construction time or "
        "per-config header resolution, not a request"
    ),
    "handlers/_security_headers_config.py:"
    "SecurityHeadersConfigMixin._compute_hsts_config": (
        "lines 62,65: HSTS config validation warnings at construction "
        "time or per-config header resolution, not a request"
    ),
    "handlers/_security_headers_cors.py:"
    "SecurityHeadersCorsMixin._is_wildcard_with_credentials": (
        "line 27: CORS config validation warning at construction time or "
        "per-config header resolution, not a request"
    ),
    "handlers/_suspatterns_regex.py:"
    "_SusPatternsRegexMixin._check_pattern_with_timeout": (
        "lines 439,448: interpolates _redact_pattern_source(pattern.pattern)[:50] "
        "(the compiled rule text, redacted) and ip_address only; the scanned "
        "request value is never referenced"
    ),
    "handlers/_suspatterns_regex.py:_SusPatternsRegexMixin._check_regex_pattern": (
        "line 339: interpolates _redact_pattern_source(pattern.pattern)[:50] "
        "only, never the scanned value"
    ),
    "handlers/_suspatterns_regex.py:_SusPatternsRegexMixin._check_windowed_pattern": (
        "lines 372,379: interpolates _redact_pattern_source(pattern.pattern)[:50] "
        "and the regex engine's own exception text, never the scanned value"
    ),
    "handlers/_suspatterns_registry.py:_SusPatternsRegistryMixin._send_pattern_event": (
        "lines 53,55: reports on an admin add_pattern/remove_pattern "
        "call - the pattern being registered is operator-authored config, "
        "not request content; logger.error fallback is send-failure text"
    ),
    "handlers/_suspatterns_registry.py:"
    "_SusPatternsRegistryMixin._send_pattern_removal_event": (
        "line 172: forwards to _send_pattern_event, same as add_pattern - "
        "operator-authored pattern config, not a request"
    ),
    "handlers/_suspatterns_registry.py:_SusPatternsRegistryMixin.add_pattern": (
        "lines 69,74,91,113: registering an operator-authored custom "
        "detection pattern, not a request"
    ),
    "handlers/cloud_handler.py:CloudManager._log_range_changes": (
        "line 198: logs provider IP-range diff counts, not a request"
    ),
    "handlers/cloud_handler.py:CloudManager._refresh_providers": (
        "line 216: provider IP-range refresh failure, infra only"
    ),
    "handlers/cloud_handler.py:CloudManager._refresh_providers_via_redis_handler": (
        "line 304: Redis-backed refresh failure, infra only"
    ),
    "handlers/cloud_handler.py:CloudManager._send_cloud_event": (
        "line 418: event carries only client_ip/provider/network; "
        "client_ip is outside the secret matrix; logger.error fallback "
        "is send-failure text"
    ),
    "handlers/cloud_handler.py:CloudManager._warn_empty_ranges": (
        "line 317: warns that a provider's IP-range set is empty, no request in scope"
    ),
    "handlers/cloud_handler.py:CloudManager.get_cloud_provider_details": (
        "line 370: logs an invalid-IP ValueError for the ip argument - "
        "client_ip is outside the secret matrix"
    ),
    "handlers/cloud_handler.py:CloudManager.is_cloud_ip": (
        "line 345: logs an invalid-IP ValueError for the ip argument - "
        "client_ip is outside the secret matrix"
    ),
    "handlers/cloud_handler.py:CloudManager.refresh_async": (
        "line 270: provider IP-range refresh failure, infra only"
    ),
    "handlers/cloud_handler.py:CloudManager.schedule_refresh._run_refresh": (
        "line 172: background refresh-task failure, infra only"
    ),
    "handlers/cloud_handler.py:CloudManager.schedule_refresh": (
        "line 183: scheduling failure for the refresh task, infra only"
    ),
    "handlers/_dynamic_rule_snapshot.py:"
    "DynamicRuleSnapshotMixin._clear_last_known_rules": (
        "lines 114,124: persistence cleanup failure for SaaS-pushed rules, infra only"
    ),
    "handlers/dynamic_rule_handler.py:DynamicRuleManager._apply_rules": (
        "line 204: applying a SaaS-pushed DynamicRules payload, not a request"
    ),
    "handlers/dynamic_rule_handler.py:DynamicRuleManager._revoke_active_rules": (
        "line 197: rule-revocation lifecycle log, policy metadata only"
    ),
    "handlers/_dynamic_rule_intake.py:DynamicRuleIntakeMixin._reject_if_malformed": (
        "line 257: rejects a malformed pushed rule set, policy metadata only"
    ),
    "handlers/_dynamic_rule_intake.py:"
    "DynamicRuleIntakeMixin._ignore_platform_default": (
        "line 189: ignores the SaaS platform default shape, policy metadata only"
    ),
    "handlers/dynamic_rule_handler.py:DynamicRuleManager._check_rule_expiry": (
        "line 162: rule-expiry lifecycle log, policy metadata only"
    ),
    "handlers/_dynamic_rule_intake.py:"
    "DynamicRuleIntakeMixin._reject_if_already_expired": (
        "line 179: rejects an already-expired pushed rule set, policy metadata only"
    ),
    "handlers/dynamic_rule_handler.py:DynamicRuleManager._rule_update_loop": (
        "lines 127,130: periodic SaaS rule-fetch loop, not a request"
    ),
    "handlers/dynamic_rule_handler.py:DynamicRuleManager.initialize_agent": (
        "line 82: agent-initialization lifecycle log, not a request"
    ),
    "handlers/dynamic_rule_handler.py:DynamicRuleManager.stop": (
        "line 272: shutdown lifecycle log, not a request"
    ),
    "handlers/_dynamic_rule_intake.py:DynamicRuleIntakeMixin.update_rules": (
        "lines 204,215: SaaS rule-fetch/apply lifecycle log, not a request"
    ),
    "handlers/ipban_handler.py:IPBanManager._on_eviction": (
        "line 60: 'IP ban cache full; %d entries evicted' - a running "
        "counter, no request data"
    ),
    "handlers/ipinfo_handler.py:IPInfoManager._download_database": (
        "line 211: MMDB database download-failure warning, infra only"
    ),
    "handlers/ipinfo_handler.py:IPInfoManager._open_database_or_none": (
        "line 91: MMDB file-open failure, infra only"
    ),
    "_utils/nat64.py:_unwrap_nat64": (
        "line 58: sampled warning naming the non-global IPv4 address embedded "
        "in a translated client address, an IP outside the secret matrix"
    ),
    "_utils/ip_extraction.py:_malformed_forwarded_for_identity": (
        "line 460: warning with the X-Forwarded-For chain passed through "
        "_display_forwarded_chain (non-IP entries shown as [REDACTED]) and "
        "_sanitize_for_log, plus the peer address"
    ),
    "handlers/_ipban_bans.py:IpBanOperationsMixin._warn_kept_in_this_process": (
        "line 37: Redis write failure for a ban, names the banned client identity "
        "(outside the secret matrix) and says the ban stays in this process"
    ),
    "handlers/_ipban_events.py:IpBanEventMixin._send_ban_evicted_event": (
        "lines 90,92: ip_ban_evicted event carries the evicted identity, its "
        "remaining seconds and counters, no request data; logger.error fallback "
        "is send-failure text"
    ),
    "handlers/_ipban_bans.py:IpBanOperationsMixin._store_ban": (
        "INFO line with the banned client identity, the applied duration "
        "and the recidive count, no request data"
    ),
    "handlers/_ipban_recidive.py:IpBanRecidiveMixin._claim_ban_key": (
        "the Redis ban claim failed, carries the client identity and the Redis "
        "error only, no request data"
    ),
    "handlers/_ipban_recidive.py:IpBanRecidiveMixin._recidive_prior_bans": (
        "line 51: the Redis recidive count could not be read, carries the "
        "client identity and the Redis error only, no request data"
    ),
    "handlers/_ipban_recidive.py:IpBanRecidiveMixin._record_recidive_ban": (
        "line 70: the Redis recidive count could not be stored, carries the "
        "client identity and the Redis error only, no request data"
    ),
    "handlers/_ipban_prefix_contract.py:_recorded_prefix_length": (
        "line 35: the recorded ipv6_prefix_length could not be read, carries the "
        "Redis error only, no request data"
    ),
    "handlers/_ipban_version.py:IpBanVersionMixin._bump_ban_version": (
        "line 43: the shared ban version could not be advanced, carries the "
        "Redis error only, no request data"
    ),
    "handlers/_ipban_version.py:IpBanVersionMixin._positive_survives_recheck": (
        "line 102: the shared ban version could not be read, carries the Redis "
        "error only, no request data"
    ),
    "handlers/_ipinfo_events.py:IpInfoEventsMixin._send_geo_event": (
        "line 43: geolocation lookup event carries only ip/country, "
        "client_ip is outside the secret matrix; logger.error fallback "
        "is send-failure text"
    ),
    "handlers/_ipinfo_background.py:IpInfoBackgroundMixin._load_in_background": (
        "line 48: background GeoIP database load failure with its traceback, "
        "infra only, no request data"
    ),
    "handlers/_ipinfo_background.py:IpInfoBackgroundMixin.schedule_database_load": (
        "line 38: GeoIP background load could not be scheduled, infra only"
    ),
    "handlers/_ipinfo_redis_copy.py:IpInfoRedisCopyMixin._adopt_redis_copy": (
        "line 28: Redis-cached GeoIP database unavailable, infra only"
    ),
    "handlers/_ipinfo_redis_copy.py:IpInfoRedisCopyMixin._claim_download_lock": (
        "line 64: GeoIP download lock unavailable, infra only"
    ),
    "handlers/_ipinfo_redis_copy.py:IpInfoRedisCopyMixin._drop_cached_database": (
        "lines 49,53: unusable cached GeoIP database dropped, infra only"
    ),
    "handlers/ipinfo_handler.py:IPInfoManager._fetch_and_store_database": (
        "line 232: failure to cache the GeoIP database in Redis, infra only"
    ),
    "handlers/ipinfo_handler.py:IPInfoManager._warn_country_rules_without_database": (
        "line 184: states what country rules do without a GeoIP database, "
        "static text, no request data"
    ),
    "core/checks/implementations/ip_security.py:"
    "IpSecurityCheck._is_banned_failing_open_on_redis_loss": (
        "line 132: Redis outage warning naming the client_ip, which is outside "
        "the secret matrix (see module docstring policy)"
    ),
    "core/checks/implementations/ip_security.py:IpSecurityCheck._report_geo_failure": (
        "line 351: GeoIP lookup failure naming the client_ip and the error class, "
        "never the error text or request data"
    ),
    "core/checks/implementations/ip_security.py:"
    "IpSecurityCheck._send_country_blocked_event": (
        "line 345: country_blocked event carries only client_ip, the country "
        "code and the rule name, outside the secret matrix"
    ),
    "handlers/ipinfo_handler.py:IPInfoManager.get_country": (
        "lines 234,241: interpolates only the ip argument (client_ip), "
        "outside the secret matrix"
    ),
    "handlers/ipinfo_handler.py:IPInfoManager._initialize_database": (
        "lines 122,137: MMDB reader initialization failure, infra only"
    ),
    "handlers/ipinfo_handler.py:IPInfoManager._refresh_database": (
        "line 313: MMDB refresh failure, infra only"
    ),
    "handlers/ratelimit_handler.py:RateLimitManager.initialize_redis": (
        "lines 323,325: Lua rate-limit script load lifecycle log, infra only"
    ),
    "handlers/ratelimit_handler.py:RateLimitManager.reset": (
        "line 526: Redis-reset failure, infra only"
    ),
    "handlers/ratelimit_handler.py:RateLimitManager._emit_script_reloaded_event": (
        "line 345: NOSCRIPT-recovery event carries a static reason string "
        "and ip_address='system', no request data; logger.error fallback "
        "is send-failure text"
    ),
    "handlers/ratelimit_handler.py:_send_by_ip_event": (
        "the rate_limited event of the request-free check_rate_limit_by_ip "
        "primitive: client IP (outside the secret matrix), the limit, window and "
        "count, and the endpoint_path argument redacted like the pipeline's "
        "endpoint; logger.error fallback is send-failure text; never called by "
        "any scenario"
    ),
    "handlers/ratelimit_handler.py:_shared_primitive_counts": (
        "static warning plus the Redis client's own exception text when the "
        "shared violation counter is unavailable, never request content; the "
        "standalone check_rate_limit_by_ip primitive, never called by any scenario"
    ),
    "core/checks/implementations/rate_limit.py:"
    "RateLimitCheck._shared_violation_counts": (
        "static warning plus the Redis client's own exception text when the "
        "shared violation counter is unavailable, never request content"
    ),
    "handlers/ratelimit_handler.py:_feed_rate_limit_autoban": (
        "line 185: 'auto-banned %s (rate_limit_exceeded)' interpolates "
        "only the ip argument, outside the secret matrix; this is the "
        "standalone check_rate_limit_by_ip primitive, never called by any "
        "scenario"
    ),
    "handlers/ratelimit_handler.py:_evalsha_tiers": (
        "line 86: 'Rate limit Lua script reloaded after NOSCRIPT' is a "
        "static message with no interpolation"
    ),
    "handlers/ratelimit_handler.py:_resolve_redis_rate_limit_failure": (
        "line 47: logs f'{context}: {error}' where context is a fixed "
        "caller-supplied label and error is the Redis client's own "
        "exception, never request content"
    ),
    "handlers/_behavior_throttle.py:_warn_throttle_fail_open": (
        "line 36: static warning about the in-memory throttle fallback, "
        "no interpolation"
    ),
    "core/behavioral/_throttle.py:_warn_throttle_needs_middleware": (
        "line 34: static warning that the adapter passes no middleware, "
        "no interpolation"
    ),
    "core/behavioral/_throttle.py:BehavioralThrottleMixin._throttle_check_failed": (
        "lines 178 and 183: the redacted text of the GuardRedisError the throttle "
        "raises itself (a fixed message) and a static fail-secure line, never "
        "request content"
    ),
    "handlers/ratelimit_handler.py:_warn_redis_fail_open_in_memory_fallback": (
        "line 31: static warning about the in-memory fallback mode, no interpolation"
    ),
    "handlers/redis_handler.py:RedisManager._safe_aclose": (
        "line 113: connection-close failure, infra only"
    ),
    "handlers/redis_handler.py:RedisManager._send_redis_event": (
        "line 85: event uses ip_address='system' unconditionally, no "
        "request data; logger.error fallback is send-failure text"
    ),
    "handlers/redis_handler.py:RedisManager.close": (
        "line 172: connection-close lifecycle log, infra only"
    ),
    "handlers/redis_handler.py:RedisManager.get_connection": (
        "line 207: connection-acquire failure, infra only"
    ),
    "handlers/redis_handler.py:RedisManager.initialize": (
        "lines 142,151,154: connection-init lifecycle/failure log, infra only"
    ),
    "handlers/redis_handler.py:RedisManager.safe_operation": (
        "line 226: wrapped-operation failure, infra only (the operation's "
        "own exception text, not request content)"
    ),
    "core/bypass/handler.py:_warn_no_client_address": (
        "lines 26-31: static advisory text with only a fixed 'rejected'/"
        "'unknown identity' outcome branch, no request data (mirrors the "
        "handle_passthrough entry above, which calls this)"
    ),
    "core/events/middleware_events.py:SecurityEventBus.send_cloud_detection_events": (
        "line 163-171: forwards to send_middleware_event with "
        "reason=f'Cloud provider IP {client_ip} blocked' and "
        "blocked_providers=list(cloud_providers_to_check) (a config list) "
        "- client_ip is outside the secret matrix, and "
        "send_cloud_detection_event (cloud_handler.py) similarly carries "
        "only client_ip/provider/network"
    ),
    "handlers/_behavior_action_dispatch.py:"
    "BehaviorActionDispatchMixin._log_passive_mode_action": (
        "lines 23,31,37,41: `details` is always built by "
        "BehavioralProcessor as f'{threshold} calls in {window}s' or "
        "f'{threshold} for {pattern!r} in {window}s' (numeric/"
        "admin-pattern config values, never request content) at its two "
        "call sites in core/behavioral/processor.py (both covered); "
        "client_ip is outside the secret matrix; not reached by any "
        "scenario since they all use passive_mode=False"
    ),
    "handlers/_suspatterns_registry.py:_SusPatternsRegistryMixin.initialize_redis": (
        "lines 69,74: Redis-backed pattern-registry initialization "
        "lifecycle log, not a request"
    ),
    "handlers/_behavior_action_dispatch.py:"
    "BehaviorActionDispatchMixin._run_custom_action": (
        "line 90: logs the exception raised by an operator-supplied "
        "custom_action together with the client IP and the endpoint id "
        "(the endpoint id is route-derived or redacted by "
        "get_endpoint_id); the exception text comes from operator code, "
        "not from the request"
    ),
    "handlers/suspatterns_handler.py:_warn_if_legacy_detection": (
        "line 344: logs the fixed _LEGACY_DETECTION_WARNING deprecation "
        "text, identical to the stacklevel-3 warnings.warn call two lines "
        "above; no request in scope, module-level state only"
    ),
    "models.py:SecurityConfig.warn_unknown_fields": (
        "line 139: pydantic model-validator warning about unrecognized "
        "SecurityConfig keys at construction time, before any request "
        "exists"
    ),
}


def _known_scenario_ids() -> frozenset[str]:
    return frozenset(
        {_DETECTION_MATRIX_SCENARIO}
        | {case.id for case in _CASES}
        | {scenario.id for scenario in _COMPONENT_SCENARIOS}
    )


def test_covered_producers_only_cite_scenarios_that_actually_exist() -> None:
    known = _known_scenario_ids()
    unknown_citations = {
        producer: sorted(scenario_ids - known)
        for producer, scenario_ids in COVERED_PRODUCERS.items()
        if scenario_ids - known
    }
    assert not unknown_citations, (
        "COVERED_PRODUCERS cites scenario ids that do not exist in "
        f"tests/test_sensitive_data_invariant.py: {unknown_citations}"
    )


def test_non_request_producers_have_non_vacuous_reasons() -> None:
    empty_reasons = [
        key for key, reason in NON_REQUEST_PRODUCERS.items() if len(reason) < 20
    ]
    assert not empty_reasons, (
        "NON_REQUEST_PRODUCERS entries with a suspiciously short reason: "
        f"{empty_reasons}"
    )


def test_covered_and_non_request_registries_do_not_overlap() -> None:
    overlap = set(COVERED_PRODUCERS) & set(NON_REQUEST_PRODUCERS)
    assert not overlap, (
        f"producers registered in both COVERED_PRODUCERS and "
        f"NON_REQUEST_PRODUCERS: {sorted(overlap)}"
    )


def test_every_producer_call_site_is_registered() -> None:
    hits = collect_producer_hits()
    assert hits, "AST walk found no producer call sites at all - walker is broken"

    grouped = group_producer_hits(hits)
    registered = set(COVERED_PRODUCERS) | set(NON_REQUEST_PRODUCERS)
    unregistered = sorted(set(grouped) - registered)

    if unregistered:
        details = []
        for key in unregistered:
            sites = ", ".join(
                f"{hit.relpath}:{hit.lineno} ({hit.call_name})" for hit in grouped[key]
            )
            details.append(f"{key} -> {sites}")
        raise AssertionError(
            "producer call sites missing from both COVERED_PRODUCERS and "
            "NON_REQUEST_PRODUCERS:\n" + "\n".join(details)
        )

    stale = sorted(registered - set(grouped))
    assert not stale, (
        "COVERED_PRODUCERS/NON_REQUEST_PRODUCERS entries whose call site no "
        f"longer exists in guard_core/ (rename or removal): {stale}"
    )
