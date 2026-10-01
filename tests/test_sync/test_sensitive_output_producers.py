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
    "core/behavioral/processor.py:BehavioralProcessor._evaluate_global_return_rule": (
        frozenset({"behavior_return_pattern_body_scan"})
    ),
    "core/behavioral/processor.py:BehavioralProcessor.process_return_rules": (
        frozenset({"behavior_return_pattern_body_scan"})
    ),
    "core/behavioral/processor.py:BehavioralProcessor.process_usage_rules": (
        frozenset({"behavior_usage_frequency_endpoint"})
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
    "core/checks/implementations/emergency_mode.py:EmergencyModeCheck.check": (
        frozenset({"emergency_mode_denied", "emergency_mode_whitelisted"})
    ),
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
    "core/checks/implementations/user_agent.py:UserAgentCheck.check": frozenset(
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
    "_pydantic_plugin_mute.py:_mute_pydantic_plugin_instrumentation": (
        "line 46: warns once about pydantic-plugin instrumentation at import "
        "time; no request in scope"
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
    "_utils/access_control.py:check_ip_access": (
        "line 265: logs f'Error checking IP {ip}: {error}' where error "
        "originates from internal IP-list/geo/cloud-provider evaluation "
        "code, never header/query/body content"
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
        "line 61: reason is f'Blocked cloud provider IP: {client_ip}' and "
        "send_cloud_detection_events forwards only client_ip/provider/"
        "network - never header/query/body content; client_ip is outside "
        "the secret matrix"
    ),
    "core/checks/implementations/referrer.py:ReferrerCheck._handle_missing_referrer": (
        "line 32: reason is the static string 'Missing referrer header' - "
        "no request data, since the header is by definition absent on "
        "this path"
    ),
    "core/checks/implementations/route_config.py:"
    "RouteConfigCheck._handle_unresolved_route": (
        "line 22: reason is the module constant UNRESOLVED_ROUTE_REASON, a "
        "fixed string with no interpolation of any kind"
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
    "decorators/access_control.py:AccessControlMixin.block_clouds.decorator": (
        "line 61: 'ignored unknown cloud providers %s' where the list "
        "comes from the @block_clouds(...) decorator argument, evaluated "
        "once at route-definition time, never per-request"
    ),
    "decorators/access_control.py:AccessControlMixin.bypass.decorator": (
        "line 78: 'ignored unknown checks %s' where the list comes from "
        "the @bypass(...) decorator argument, evaluated once at "
        "route-definition time, never per-request"
    ),
    "decorators/advanced.py:AdvancedMixin.honeypot_detection.decorator."
    "honeypot_validator._validate_json_data": (
        "line 91: logger.debug('...skipping unparsable JSON body: %s', "
        "exc) logs only the JSONDecodeError/TypeError/RecursionError "
        "object, whose str() is built from parse-position numbers, never "
        "a copy of the body text or honeypot field values"
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
    "handlers/_dynamic_rule_application.py:"
    "DynamicRuleApplicationMixin._activate_emergency_mode": (
        "lines 183,194: applying a SaaS-pushed DynamicRules payload "
        "(admin/operator policy), never an inbound HTTP request"
    ),
    "handlers/_dynamic_rule_application.py:"
    "DynamicRuleApplicationMixin._apply_cloud_provider_rules": (
        "lines 106,109: applying SaaS-pushed policy, not a request"
    ),
    "handlers/_dynamic_rule_application.py:"
    "DynamicRuleApplicationMixin._apply_country_rules": (
        "lines 61,71,78: applying SaaS-pushed policy, not a request"
    ),
    "handlers/_dynamic_rule_application.py:"
    "DynamicRuleApplicationMixin._apply_feature_toggles": (
        "lines 152,156,160,166,172,178: applying SaaS-pushed feature "
        "toggles, not a request"
    ),
    "handlers/_dynamic_rule_application.py:"
    "DynamicRuleApplicationMixin._apply_ip_bans": (
        "lines 39,41: applying SaaS-pushed IP-ban policy, not a request"
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
    "handlers/_dynamic_rule_application.py:"
    "DynamicRuleApplicationMixin._apply_rate_limit_rules": (
        "lines 89,93: applying SaaS-pushed rate-limit policy, not a request"
    ),
    "handlers/_dynamic_rule_application.py:"
    "DynamicRuleApplicationMixin._apply_user_agent_rules": (
        "lines 129,133: applying SaaS-pushed blocked-user-agent policy, not a request"
    ),
    "handlers/_dynamic_rule_events.py:"
    "DynamicRuleEventSenderMixin._send_emergency_event": (
        "lines 95,97: reports on a SaaS-pushed emergency-mode policy "
        "change, not a request; logger.error fallback is send-failure text"
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
    "handlers/_ipban_bans.py:IpBanOperationsMixin._clamp_to_local_cap": (
        "line 33: 'Redis unavailable: ban shortened from Xs to Ys' - "
        "duration numbers only, no request data"
    ),
    "handlers/_ipban_bans.py:IpBanOperationsMixin._log_refused_ban": (
        "line 124: logs the ban-target IP and the overlapping loopback/"
        "trusted-proxy CIDR only; client_ip is outside the secret matrix"
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
    "handlers/dynamic_rule_handler.py:DynamicRuleManager._apply_rules": (
        "line 250: applying a SaaS-pushed DynamicRules payload, not a request"
    ),
    "handlers/dynamic_rule_handler.py:DynamicRuleManager._check_rule_expiry": (
        "line 162: rule-expiry lifecycle log, policy metadata only"
    ),
    "handlers/dynamic_rule_handler.py:DynamicRuleManager._reject_if_already_expired": (
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
    "handlers/dynamic_rule_handler.py:DynamicRuleManager.update_rules": (
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
    "handlers/ipinfo_handler.py:IPInfoManager._send_geo_event": (
        "line 182: geolocation lookup event carries only ip/country, "
        "client_ip is outside the secret matrix; logger.error fallback "
        "is send-failure text"
    ),
    "handlers/ipinfo_handler.py:IPInfoManager.get_country": (
        "lines 234,241: interpolates only the ip argument (client_ip), "
        "outside the secret matrix"
    ),
    "handlers/ipinfo_handler.py:IPInfoManager.initialize": (
        "lines 122,137: MMDB reader initialization failure, infra only"
    ),
    "handlers/ipinfo_handler.py:IPInfoManager.refresh": (
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
    "handlers/ratelimit_handler.py:_feed_rate_limit_autoban": (
        "line 185: 'auto-banned %s (rate_limit_exceeded)' interpolates "
        "only the ip argument, outside the secret matrix; this is the "
        "standalone check_rate_limit_by_ip primitive, never called by any "
        "scenario"
    ),
    "handlers/ratelimit_handler.py:_redis_request_count": (
        "line 86: 'Rate limit Lua script reloaded after NOSCRIPT' is a "
        "static message with no interpolation"
    ),
    "handlers/ratelimit_handler.py:_resolve_redis_rate_limit_failure": (
        "line 47: logs f'{context}: {error}' where context is a fixed "
        "caller-supplied label and error is the Redis client's own "
        "exception, never request content"
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
