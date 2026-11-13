"""The registry of every logging and warning call site of guard_core.

A site is either KINDED (it carries a registered misconfiguration kind) or excluded
under one reason of EXCLUSION_REASONS. The key is the async-tree path (the sync
mirror shares it) and the qualified function name; the value lists the disposition
of each site of that function in source order.
"""

KINDED = "kinded"

EXCLUSION_REASONS: dict[str, str] = {
    "adapter_capability": (
        "the framework adapter's request, response or middleware lacks an optional "
        "capability; the adapter's code decides, not a setting"
    ),
    "api_call_argument": (
        "one argument of a public call names something the engine does not hold (a "
        "reset of a foreign config, an unscoped ban call), not a setting or "
        "declaration"
    ),
    "attack_signal": (
        "a client sent something the engine reports as an attack signal (a CSP "
        "violation report, a spoofed X-Forwarded-For header)"
    ),
    "audit_log_line": (
        "the log line is the product (activity log, alert or announcement), not a "
        "warning about a setting"
    ),
    "ban_decision": (
        "a ban was refused, widened or fed by an automatic decision, logged as a "
        "security event"
    ),
    "check_failure_decision": (
        "a check, rebuild or time-window evaluation raised and the outcome (fail open "
        "or fail secure) is logged"
    ),
    "dependency_state": (
        "an optional dependency or collaborator (agent, logfire, OpenTelemetry) is "
        "absent or already claimed at run time"
    ),
    "deprecated_api_use": (
        "running detection without a config, which already raises a DeprecationWarning"
    ),
    "detection_signal": (
        "a detection scan or pattern-safety outcome driven by request or pattern "
        "content"
    ),
    "internal_recovery": (
        "the engine's own cleanup or recovery bookkeeping failed, not a setting"
    ),
    "io_failure": ("an external fetch, file, cache, database or GeoIP load failed"),
    "override_reported_by_event": (
        "a configure() override was refused or changed; the override events are the "
        "structured channel"
    ),
    "redis_outage": (
        "Redis unavailable or its stored state unreadable, and the engine degraded to "
        "in-process state"
    ),
    "remote_rule_content": (
        "a dynamic rule from the SaaS was ignored, rejected, expired or unusable; its "
        "own event reports it"
    ),
    "request_cap": (
        "a per-request, per-app or per-process cap or budget was reached by the traffic"
    ),
    "request_dependent": (
        "depends on the content, headers or connection of one request, not on a "
        "setting alone"
    ),
    "telemetry_failure": (
        "delivering an event, metric or handler call to the agent or an exporter failed"
    ),
    "user_callback_raised": (
        "a hook, verifier, modifier or custom action the application supplied raised "
        "or misbehaved at run time"
    ),
}

SITES: dict[tuple[str, str], tuple[str, ...]] = {
    ("_emergency_exemptions.py", "warn_unexempted_probe_paths"): ("kinded",),
    ("_misconfiguration.py", "report_misconfiguration"): ("kinded",),
    ("_misconfiguration.py", "report_misconfigurations"): ("kinded",),
    ("_misconfiguration_kinds.py", "log_problem"): ("kinded",),
    ("_pydantic_plugin_mute.py", "_mute_pydantic_plugin_instrumentation"): (
        "internal_recovery",
    ),
    ("_redis_abandoned_client.py", "_drop_everything_pending_at_exit"): (
        "internal_recovery",
    ),
    ("_redis_abandoned_client.py", "_drop_once_and_survive_failure"): (
        "internal_recovery",
    ),
    (
        "_security_config_field_validators.py",
        "_warn_empty_enabled_detection_categories",
    ): ("kinded",),
    ("_security_config_field_validators.py", "_warn_exclude_all_paths"): ("kinded",),
    ("_security_config_field_validators.py", "warn_agent_endpoint_in_clear"): (
        "kinded",
    ),
    (
        "_security_config_geo_validators.py",
        "_warn_country_allowlist_shadows_blocklist",
    ): ("kinded",),
    ("_staged_defaults.py", "_warn_default_redis_prefix"): ("kinded",),
    ("_staged_defaults.py", "signal_changed_defaults"): ("kinded",),
    ("_utils/agent_events.py", "invoke_error_hook"): ("user_callback_raised",),
    ("_utils/agent_events.py", "send_agent_event"): ("telemetry_failure",),
    ("_utils/app_managers.py", "_warn_split_connection"): ("kinded",),
    ("_utils/block_events.py", "invoke_block_hook"): ("user_callback_raised",),
    ("_utils/body_reader.py", "_body_read_slot"): ("request_cap",),
    ("_utils/body_reader.py", "_read_and_cache_body"): ("adapter_capability",),
    ("_utils/body_reader.py", "_read_capped_body"): ("adapter_capability",),
    ("_utils/body_reader.py", "_warn_body_inspect_bytes_cap_reached"): ("request_cap",),
    (
        "_utils/body_reader.py",
        "_warn_body_inspect_bytes_cap_reached_no_bounded_reader",
    ): ("request_cap",),
    ("_utils/body_reader.py", "_warn_body_reader_fallback_once_per_app"): (
        "kinded",
        "kinded",
    ),
    ("_utils/detection_scan.py", "_check_value_enhanced"): ("detection_signal",),
    ("_utils/detection_scan.py", "_fallback_pattern_check"): ("detection_signal",),
    ("_utils/detection_scan.py", "_scan_char_budget_exhausted"): ("request_cap",),
    ("_utils/detection_scan.py", "_scan_value_budget_exhausted"): ("request_cap",),
    ("_utils/detection_scan.py", "_warn_json_depth_cap_reached_once"): ("request_cap",),
    ("_utils/detection_scan.py", "_warn_scan_time_cap_reached_once"): ("request_cap",),
    ("_utils/ip_extraction.py", "_handle_untrusted_proxy"): ("attack_signal",),
    ("_utils/ip_extraction.py", "_malformed_forwarded_for_identity"): (
        "request_dependent",
    ),
    ("_utils/ip_extraction.py", "_resolve_client_ip_from_forwarded_chain"): (
        "check_failure_decision",
    ),
    ("_utils/ip_extraction.py", "_warn_forwarded_header_chain_too_short"): ("kinded",),
    ("_utils/ip_extraction.py", "_warn_forwarded_header_depth_overcounts_hops"): (
        "kinded",
    ),
    ("_utils/ip_extraction.py", "_warn_forwarded_header_preempted"): ("kinded",),
    (
        "_utils/ip_extraction.py",
        "_warn_forwarded_header_selected_entry_trusted_proxy",
    ): ("kinded",),
    ("_utils/logging_utils.py", "_log_at_level"): (
        "audit_log_line",
        "audit_log_line",
        "audit_log_line",
    ),
    ("_utils/logging_utils.py", "setup_custom_logging"): ("io_failure",),
    ("_utils/nat64.py", "_warn_non_global_embedded_once_a_minute"): (
        "request_dependent",
    ),
    ("_utils/route_gate.py", "record_route_template"): ("user_callback_raised",),
    ("_utils/time_window.py", "time_window_allows"): ("check_failure_decision",),
    (
        "core/behavioral/_throttle.py",
        "BehavioralThrottleMixin._throttle_check_failed",
    ): ("check_failure_decision", "check_failure_decision"),
    ("core/behavioral/_throttle.py", "warn_throttle_needs_middleware"): ("kinded",),
    ("core/bypass/handler.py", "_warn_no_client_address"): ("request_dependent",),
    ("core/checks/_ip_ban_read.py", "IpBanReadMixin.warn_ban_lookup_skipped"): (
        "redis_outage",
    ),
    ("core/checks/_shared_strikes.py", "forget_shared_detection_strikes"): (
        "redis_outage",
    ),
    ("core/checks/_shared_strikes.py", "read_shared_detection_categories"): (
        "redis_outage",
    ),
    ("core/checks/_shared_strikes.py", "record_shared_detection_strikes"): (
        "redis_outage",
    ),
    ("core/checks/_strike_forget.py", "register_strike_middleware"): (
        "adapter_capability",
    ),
    ("core/checks/helpers.py", "_log_exception_safely"): (
        "check_failure_decision",
        "check_failure_decision",
    ),
    (
        "core/checks/implementations/authentication.py",
        "AuthenticationCheck._verify_credential",
    ): ("user_callback_raised",),
    (
        "core/checks/implementations/ip_security.py",
        "IpSecurityCheck._report_geo_failure",
    ): ("io_failure",),
    (
        "core/checks/implementations/rate_limit.py",
        "RateLimitCheck._log_non_ip_ban_refusal",
    ): ("ban_decision",),
    (
        "core/checks/implementations/rate_limit.py",
        "RateLimitCheck._shared_violation_counts",
    ): ("redis_outage",),
    ("core/checks/implementations/route_config.py", "RouteConfigCheck._allow_header"): (
        "user_callback_raised",
    ),
    (
        "core/checks/implementations/route_config.py",
        "RouteConfigCheck._unresolved_status",
    ): ("user_callback_raised",),
    (
        "core/checks/implementations/suspicious_activity.py",
        "SuspiciousActivityCheck._record_served_static_file",
    ): ("user_callback_raised",),
    ("core/checks/pipeline.py", "SecurityCheckPipeline._handle_check_error"): (
        "redis_outage",
        "check_failure_decision",
        "check_failure_decision",
    ),
    ("core/checks/pipeline.py", "SecurityCheckPipeline._handle_rebuild_error"): (
        "check_failure_decision",
        "check_failure_decision",
    ),
    ("core/events/composite_handler.py", "CompositeAgentHandler.flush_buffer"): (
        "telemetry_failure",
    ),
    ("core/events/composite_handler.py", "CompositeAgentHandler.get_dynamic_rules"): (
        "telemetry_failure",
    ),
    ("core/events/composite_handler.py", "CompositeAgentHandler.get_stats"): (
        "telemetry_failure",
    ),
    ("core/events/composite_handler.py", "CompositeAgentHandler.get_status"): (
        "telemetry_failure",
    ),
    ("core/events/composite_handler.py", "CompositeAgentHandler.health_check"): (
        "telemetry_failure",
    ),
    ("core/events/composite_handler.py", "CompositeAgentHandler.initialize_redis"): (
        "telemetry_failure",
    ),
    ("core/events/composite_handler.py", "CompositeAgentHandler.send_event"): (
        "telemetry_failure",
    ),
    ("core/events/composite_handler.py", "CompositeAgentHandler.send_metric"): (
        "telemetry_failure",
    ),
    ("core/events/composite_handler.py", "CompositeAgentHandler.start"): (
        "telemetry_failure",
    ),
    ("core/events/composite_handler.py", "CompositeAgentHandler.stop"): (
        "telemetry_failure",
    ),
    ("core/events/enricher.py", "EventEnricher.enrich_event"): ("telemetry_failure",),
    ("core/events/enricher.py", "EventEnricher.enrich_metric"): ("telemetry_failure",),
    ("core/events/logfire_handler.py", "LogfireHandler.start"): (
        "dependency_state",
        "dependency_state",
    ),
    ("core/events/metrics.py", "MetricsCollector.send_metric"): ("telemetry_failure",),
    ("core/events/middleware_events.py", "SecurityEventBus._lookup_country"): (
        "io_failure",
    ),
    ("core/events/middleware_events.py", "SecurityEventBus.send_middleware_event"): (
        "telemetry_failure",
    ),
    ("core/events/otel_handler.py", "OtelHandler._claim_meter_provider"): (
        "dependency_state",
    ),
    ("core/events/otel_handler.py", "OtelHandler._claim_tracer_provider"): (
        "dependency_state",
    ),
    ("core/events/otel_handler.py", "OtelHandler.send_metric"): ("dependency_state",),
    ("core/events/otel_handler.py", "OtelHandler.start"): ("dependency_state",),
    (
        "core/initialization/_ban_threshold_report.py",
        "log_unreachable_ban_thresholds_after_rule_change",
    ): ("kinded",),
    (
        "core/initialization/_handler_initializer_steps.py",
        "_HandlerInitializerStepsMixin._connect_redis",
    ): ("redis_outage",),
    (
        "core/initialization/_handler_initializer_steps.py",
        "_HandlerInitializerStepsMixin._purge_configured_dynamic_rules",
    ): ("io_failure",),
    (
        "core/initialization/_handler_initializer_steps.py",
        "_HandlerInitializerStepsMixin._run_lazy_init_in_scope",
    ): ("io_failure", "io_failure"),
    (
        "core/initialization/_handler_initializer_steps.py",
        "_HandlerInitializerStepsMixin._warn_if_lazy_init_is_inert",
    ): ("kinded",),
    (
        "core/initialization/_handler_initializer_steps.py",
        "_HandlerInitializerStepsMixin.initialize_dynamic_rule_manager",
    ): ("kinded",),
    (
        "core/initialization/_redis_cold_start_recovery.py",
        "RedisColdStartRecoveryMixin._attempt_custom_initialize",
    ): ("redis_outage",),
    (
        "core/initialization/_redis_cold_start_recovery.py",
        "RedisColdStartRecoveryMixin._recover_redis_after_cold_start",
    ): ("redis_outage",),
    (
        "core/initialization/_whitelist_strikes.py",
        "reset_strikes_for_changed_whitelist",
    ): ("redis_outage",),
    ("core/responses/factory.py", "ErrorResponseFactory.apply_modifier"): (
        "user_callback_raised",
    ),
    ("core/responses/modifier_body.py", "_call_on_view"): ("user_callback_raised",),
    ("core/responses/modifier_body.py", "apply_modifier_with_bounded_body"): (
        "user_callback_raised",
    ),
    ("core/responses/modifier_view.py", "report_body_refused"): (
        "user_callback_raised",
    ),
    (
        "core/routing/resolver.py",
        "RouteConfigResolver._flag_route_unknown_to_decorator",
    ): ("kinded",),
    ("decorators/access_control.py", "AccessControlMixin.bypass.decorator"): (
        "kinded",
    ),
    ("decorators/advanced.py", "_log_unparsable_json"): ("request_cap",),
    ("decorators/advanced.py", "_warn_if_body_not_fully_inspected"): ("request_cap",),
    ("decorators/authentication.py", "AuthenticationMixin.require_auth.decorator"): (
        "kinded",
    ),
    (
        "decorators/content_filtering.py",
        "ContentFilteringMixin.max_request_size.decorator",
    ): ("kinded",),
    ("detection_engine/_redos_cost_arbiter.py", "_log_structural_disagreement"): (
        "detection_signal",
    ),
    ("detection_engine/_validation_cache.py", "PatternValidationCache.__init__"): (
        "io_failure",
    ),
    ("detection_engine/_validation_cache.py", "PatternValidationCache._load"): (
        "io_failure",
        "io_failure",
    ),
    ("detection_engine/_validation_cache.py", "PatternValidationCache._save"): (
        "io_failure",
    ),
    ("detection_engine/compiler.py", "report_scan_timeout"): ("detection_signal",),
    ("detection_engine/monitor.py", "PerformanceMonitor._send_anomaly_event"): (
        "telemetry_failure",
    ),
    ("detection_engine/monitor.py", "PerformanceMonitor._send_callback_error_event"): (
        "telemetry_failure",
    ),
    (
        "detection_engine/preprocessor.py",
        "ContentPreprocessor._send_preprocessor_event",
    ): ("telemetry_failure",),
    ("detection_engine/semantic.py", "SemanticAnalyzer._check_ast_parsing_risk"): (
        "detection_signal",
    ),
    (
        "handlers/_behavior_action_dispatch.py",
        "BehaviorActionDispatchMixin._execute_active_mode_action",
    ): ("audit_log_line",),
    (
        "handlers/_behavior_action_dispatch.py",
        "BehaviorActionDispatchMixin._log_passive_mode_action",
    ): ("audit_log_line",),
    (
        "handlers/_behavior_action_dispatch.py",
        "BehaviorActionDispatchMixin._run_custom_action",
    ): ("user_callback_raised",),
    (
        "handlers/_behavior_action_dispatch.py",
        "BehaviorActionDispatchMixin._send_behavior_event",
    ): ("telemetry_failure",),
    ("handlers/_behavior_evictions.py", "BehaviorEvictionMixin._report_eviction"): (
        "request_cap",
    ),
    (
        "handlers/_behavior_response_pattern.py",
        "BehaviorResponsePatternMixin._check_response_pattern",
    ): ("check_failure_decision",),
    (
        "handlers/_behavior_response_pattern.py",
        "BehaviorResponsePatternMixin._log_body_unavailable",
    ): ("adapter_capability",),
    ("handlers/_behavior_throttle.py", "_warn_throttle_fail_open"): ("redis_outage",),
    ("handlers/_cloud_azure_fetch.py", "_select_azure_cloud_prefixes"): ("io_failure",),
    ("handlers/_cloud_azure_fetch.py", "_warn_if_service_tags_url_is_stale"): (
        "io_failure",
        "io_failure",
    ),
    ("handlers/_cloud_azure_fetch.py", "fetch_azure_ip_ranges"): ("io_failure",),
    ("handlers/_cloud_prefix_parse.py", "log_rejected_prefixes"): ("io_failure",),
    ("handlers/_cloud_provider_fetchers.py", "fetch_aws_ip_ranges"): ("io_failure",),
    ("handlers/_cloud_provider_fetchers.py", "fetch_digitalocean_ip_ranges"): (
        "io_failure",
    ),
    ("handlers/_cloud_provider_fetchers.py", "fetch_gcp_ip_ranges"): ("io_failure",),
    ("handlers/_cloud_provider_fetchers.py", "fetch_linode_ip_ranges"): ("io_failure",),
    ("handlers/_cloud_provider_fetchers.py", "fetch_vultr_ip_ranges"): ("io_failure",),
    (
        "handlers/_dynamic_rule_application.py",
        "DynamicRuleApplicationMixin._announce_emergency_mode",
    ): ("audit_log_line",),
    (
        "handlers/_dynamic_rule_application.py",
        "DynamicRuleApplicationMixin._announce_plan",
    ): ("audit_log_line",),
    (
        "handlers/_dynamic_rule_application.py",
        "DynamicRuleApplicationMixin._apply_ip_bans",
    ): ("io_failure",),
    (
        "handlers/_dynamic_rule_application.py",
        "DynamicRuleApplicationMixin._apply_ip_whitelist",
    ): ("io_failure", "io_failure"),
    (
        "handlers/_dynamic_rule_application.py",
        "DynamicRuleApplicationMixin._apply_pattern_rules",
    ): ("remote_rule_content",),
    (
        "handlers/_dynamic_rule_application.py",
        "DynamicRuleApplicationMixin._revoke_owned",
    ): ("io_failure", "io_failure"),
    (
        "handlers/_dynamic_rule_application.py",
        "DynamicRuleApplicationMixin._stale_rule_bans",
    ): ("io_failure",),
    (
        "handlers/_dynamic_rule_events.py",
        "DynamicRuleEventSenderMixin._send_emergency_event",
    ): ("telemetry_failure",),
    (
        "handlers/_dynamic_rule_events.py",
        "DynamicRuleEventSenderMixin._send_rule_applied_event",
    ): ("telemetry_failure",),
    (
        "handlers/_dynamic_rule_events.py",
        "DynamicRuleEventSenderMixin._send_rule_received_event",
    ): ("telemetry_failure",),
    (
        "handlers/_dynamic_rule_events.py",
        "DynamicRuleEventSenderMixin._send_rule_rejected_event",
    ): ("telemetry_failure",),
    (
        "handlers/_dynamic_rule_intake.py",
        "DynamicRuleIntakeMixin._ignore_platform_default",
    ): ("remote_rule_content",),
    (
        "handlers/_dynamic_rule_intake.py",
        "DynamicRuleIntakeMixin._reject_if_already_expired",
    ): ("remote_rule_content",),
    (
        "handlers/_dynamic_rule_intake.py",
        "DynamicRuleIntakeMixin._reject_if_malformed",
    ): ("kinded",),
    (
        "handlers/_dynamic_rule_intake.py",
        "DynamicRuleIntakeMixin._update_rules_in_cycle",
    ): ("io_failure",),
    (
        "handlers/_dynamic_rule_purge.py",
        "DynamicRulePurgeMixin._agent_status_with_rules_check_time",
    ): ("io_failure",),
    ("handlers/_dynamic_rule_purge.py", "DynamicRulePurgeMixin._clear_purge_marker"): (
        "io_failure",
    ),
    ("handlers/_dynamic_rule_purge.py", "DynamicRulePurgeMixin._parse_if_holding"): (
        "io_failure",
    ),
    ("handlers/_dynamic_rule_purge.py", "DynamicRulePurgeMixin._read_purge_marker"): (
        "remote_rule_content",
    ),
    (
        "handlers/_dynamic_rule_purge.py",
        "DynamicRulePurgeMixin._remove_purged_patterns",
    ): ("remote_rule_content",),
    ("handlers/_dynamic_rule_purge.py", "DynamicRulePurgeMixin._revert_if_purged"): (
        "remote_rule_content",
    ),
    ("handlers/_dynamic_rule_purge.py", "DynamicRulePurgeMixin._write_purge_marker"): (
        "io_failure",
    ),
    (
        "handlers/_dynamic_rule_purge.py",
        "DynamicRulePurgeMixin.purge_configured_dynamic_rules",
    ): ("kinded",),
    (
        "handlers/_dynamic_rule_snapshot.py",
        "DynamicRuleSnapshotMixin._clear_last_known_rules",
    ): ("io_failure", "io_failure"),
    (
        "handlers/_dynamic_rule_snapshot.py",
        "DynamicRuleSnapshotMixin._hydrate_last_known_rules",
    ): ("io_failure",),
    (
        "handlers/_dynamic_rule_snapshot.py",
        "DynamicRuleSnapshotMixin._load_last_known_rules",
    ): ("remote_rule_content", "remote_rule_content"),
    (
        "handlers/_dynamic_rule_snapshot.py",
        "DynamicRuleSnapshotMixin._parse_last_known_rules",
    ): ("remote_rule_content",),
    (
        "handlers/_dynamic_rule_snapshot.py",
        "DynamicRuleSnapshotMixin._persist_last_known_rules",
    ): ("io_failure", "io_failure"),
    (
        "handlers/_dynamic_rule_snapshot.py",
        "DynamicRuleSnapshotMixin._persist_snapshot_to_redis",
    ): ("io_failure",),
    (
        "handlers/_dynamic_rule_snapshot.py",
        "DynamicRuleSnapshotMixin._read_cache_file",
    ): ("io_failure",),
    (
        "handlers/_dynamic_rule_snapshot.py",
        "DynamicRuleSnapshotMixin._read_redis_key",
    ): ("io_failure",),
    (
        "handlers/_dynamic_rule_snapshot.py",
        "DynamicRuleSnapshotMixin._reconcile_snapshot",
    ): ("remote_rule_content",),
    ("handlers/_ipban_bans.py", "IpBanOperationsMixin._log_refused_ban"): (
        "ban_decision",
    ),
    ("handlers/_ipban_bans.py", "IpBanOperationsMixin._warn_if_private_target"): (
        "ban_decision",
    ),
    ("handlers/_ipban_bans.py", "IpBanOperationsMixin._warn_kept_in_this_process"): (
        "redis_outage",
    ),
    ("handlers/_ipban_bans.py", "IpBanOperationsMixin.purge_rule_owned_bans"): (
        "redis_outage",
    ),
    ("handlers/_ipban_events.py", "IpBanEventMixin._send_ban_event"): (
        "telemetry_failure",
    ),
    ("handlers/_ipban_events.py", "IpBanEventMixin._send_ban_evicted_event"): (
        "telemetry_failure",
    ),
    ("handlers/_ipban_events.py", "IpBanEventMixin._send_ban_refused_event"): (
        "telemetry_failure",
    ),
    ("handlers/_ipban_events.py", "IpBanEventMixin._send_unban_event"): (
        "telemetry_failure",
    ),
    ("handlers/_ipban_migration.py", "IpBanMigrationMixin._migrate_legacy_ban_keys"): (
        "redis_outage",
        "redis_outage",
    ),
    ("handlers/_ipban_prefix_contract.py", "_recorded_prefix_length"): (
        "redis_outage",
    ),
    ("handlers/_ipban_queries.py", "IpBanQueryMixin._forget_all_strikes"): (
        "redis_outage",
    ),
    ("handlers/_ipban_queries.py", "IpBanQueryMixin._forget_strikes"): (
        "redis_outage",
    ),
    ("handlers/_ipban_queries.py", "IpBanQueryMixin._unban_redis_inside"): (
        "redis_outage",
    ),
    ("handlers/_ipban_queries.py", "IpBanQueryMixin.forget_strikes_inside"): (
        "redis_outage",
    ),
    ("handlers/_ipban_recidive.py", "IpBanRecidiveMixin._claim_ban_key"): (
        "redis_outage",
    ),
    ("handlers/_ipban_recidive.py", "IpBanRecidiveMixin._recidive_prior_bans"): (
        "redis_outage",
    ),
    ("handlers/_ipban_recidive.py", "IpBanRecidiveMixin._record_recidive_ban"): (
        "redis_outage",
    ),
    ("handlers/_ipban_rule_revoke.py", "IpBanRuleRevokeMixin.rule_owns_live_ban"): (
        "redis_outage",
    ),
    ("handlers/_ipban_sharing.py", "IpBanSharedAppsMixin._across_apps_scopes"): (
        "api_call_argument",
    ),
    ("handlers/_ipban_sharing.py", "IpBanSharedAppsMixin._ban_stands_for"): ("kinded",),
    ("handlers/_ipban_version.py", "IpBanVersionMixin._bump_ban_version"): (
        "redis_outage",
    ),
    ("handlers/_ipban_version.py", "IpBanVersionMixin._positive_survives_recheck"): (
        "redis_outage",
    ),
    ("handlers/_ipinfo_background.py", "IpInfoBackgroundMixin._load_in_background"): (
        "io_failure",
    ),
    (
        "handlers/_ipinfo_background.py",
        "IpInfoBackgroundMixin.schedule_database_load",
    ): ("io_failure",),
    (
        "handlers/_ipinfo_database_file.py",
        "IpInfoDatabaseFileMixin._open_database_or_none",
    ): ("io_failure",),
    ("handlers/_ipinfo_download_cap.py", "_reject"): ("io_failure",),
    ("handlers/_ipinfo_events.py", "IpInfoEventsMixin._send_geo_event"): (
        "telemetry_failure",
    ),
    ("handlers/_ipinfo_redis_copy.py", "IpInfoRedisCopyMixin._adopt_redis_pieces"): (
        "io_failure",
        "io_failure",
        "io_failure",
    ),
    (
        "handlers/_ipinfo_redis_copy.py",
        "IpInfoRedisCopyMixin._adopt_whole_redis_copy",
    ): ("io_failure", "io_failure"),
    (
        "handlers/_ipinfo_redis_copy.py",
        "IpInfoRedisCopyMixin._cache_database_in_redis",
    ): ("redis_outage",),
    ("handlers/_ipinfo_redis_copy.py", "IpInfoRedisCopyMixin._claim_download_lock"): (
        "io_failure",
    ),
    ("handlers/_ipinfo_redis_copy.py", "IpInfoRedisCopyMixin._drop_cached_database"): (
        "io_failure",
        "io_failure",
    ),
    ("handlers/_ipinfo_redis_copy.py", "IpInfoRedisCopyMixin._release_download_lock"): (
        "io_failure",
    ),
    (
        "handlers/_security_headers_cache.py",
        "SecurityHeadersCacheMixin._cache_configuration",
    ): ("redis_outage",),
    (
        "handlers/_security_headers_cache.py",
        "SecurityHeadersCacheMixin._load_cached_config",
    ): ("redis_outage",),
    (
        "handlers/_security_headers_cache.py",
        "SecurityHeadersCacheMixin._validated_cached_record",
    ): ("redis_outage",),
    ("handlers/_security_headers_cache.py", "SecurityHeadersCacheMixin.reset"): (
        "redis_outage",
    ),
    (
        "handlers/_security_headers_config.py",
        "SecurityHeadersConfigMixin._compute_cors_config",
    ): ("kinded",),
    (
        "handlers/_security_headers_config.py",
        "SecurityHeadersConfigMixin._compute_csp_config",
    ): ("kinded",),
    (
        "handlers/_security_headers_config.py",
        "SecurityHeadersConfigMixin._compute_hsts_config",
    ): ("kinded", "kinded"),
    (
        "handlers/_security_headers_cors.py",
        "SecurityHeadersCorsMixin._is_wildcard_with_credentials",
    ): ("kinded",),
    (
        "handlers/_security_headers_cors.py",
        "SecurityHeadersCorsMixin.get_cors_headers",
    ): ("kinded",),
    (
        "handlers/_security_headers_events.py",
        "SecurityHeadersEventsMixin.validate_csp_report",
    ): ("attack_signal",),
    (
        "handlers/_security_headers_override_state.py",
        "SecurityHeadersOverrideMixin._apply_shared_own_state",
    ): ("redis_outage",),
    (
        "handlers/_security_headers_override_state.py",
        "SecurityHeadersOverrideMixin._log_cors_override",
    ): ("kinded", "kinded", "kinded"),
    (
        "handlers/_security_headers_override_state.py",
        "SecurityHeadersOverrideMixin._log_override_change",
    ): ("override_reported_by_event",),
    (
        "handlers/_security_headers_override_state.py",
        "SecurityHeadersOverrideMixin._pull_override",
    ): ("redis_outage", "redis_outage"),
    (
        "handlers/_security_headers_override_state.py",
        "SecurityHeadersOverrideMixin._save_override_record",
    ): ("redis_outage",),
    (
        "handlers/_suspatterns_regex.py",
        "_SusPatternsRegexMixin._check_pattern_with_timeout",
    ): ("detection_signal", "detection_signal", "detection_signal"),
    ("handlers/_suspatterns_regex.py", "_SusPatternsRegexMixin._check_regex_pattern"): (
        "detection_signal",
    ),
    (
        "handlers/_suspatterns_regex.py",
        "_SusPatternsRegexMixin._check_windowed_pattern",
    ): ("detection_signal", "detection_signal"),
    (
        "handlers/_suspatterns_registry.py",
        "_SusPatternsRegistryMixin._send_pattern_event",
    ): ("telemetry_failure",),
    ("handlers/_suspatterns_registry.py", "_SusPatternsRegistryMixin.add_pattern"): (
        "detection_signal",
    ),
    (
        "handlers/_suspatterns_registry.py",
        "_SusPatternsRegistryMixin.initialize_redis",
    ): ("detection_signal", "detection_signal"),
    ("handlers/_suspatterns_registry.py", "_reconciled_custom_patterns"): (
        "redis_outage",
    ),
    ("handlers/cloud_handler.py", "CloudManager._refresh_providers"): ("io_failure",),
    (
        "handlers/cloud_handler.py",
        "CloudManager._refresh_providers_via_redis_handler",
    ): ("io_failure",),
    ("handlers/cloud_handler.py", "CloudManager._send_cloud_event"): (
        "telemetry_failure",
    ),
    ("handlers/cloud_handler.py", "CloudManager._warn_empty_ranges"): ("io_failure",),
    ("handlers/cloud_handler.py", "CloudManager._warn_unusable_cache"): ("io_failure",),
    ("handlers/cloud_handler.py", "CloudManager.get_cloud_provider_details"): (
        "request_dependent",
    ),
    ("handlers/cloud_handler.py", "CloudManager.is_cloud_ip"): ("request_dependent",),
    ("handlers/cloud_handler.py", "CloudManager.refresh_async"): ("io_failure",),
    ("handlers/cloud_handler.py", "CloudManager.schedule_refresh"): ("io_failure",),
    ("handlers/cloud_handler.py", "CloudManager.schedule_refresh._run_refresh"): (
        "io_failure",
    ),
    (
        "handlers/dynamic_rule_handler.py",
        "DynamicRuleManager._apply_rules_from_entry",
    ): ("io_failure",),
    (
        "handlers/dynamic_rule_handler.py",
        "DynamicRuleManager._log_unreachable_ban_thresholds_after_swap",
    ): ("io_failure",),
    ("handlers/dynamic_rule_handler.py", "DynamicRuleManager._rule_update_loop"): (
        "io_failure",
    ),
    (
        "handlers/dynamic_rule_handler.py",
        "DynamicRuleManager._withdraw_the_applied_rules",
    ): ("io_failure",),
    ("handlers/ipban_handler.py", "IPBanManager._on_eviction"): ("request_cap",),
    ("handlers/ipinfo_handler.py", "IPInfoManager._initialize_database"): (
        "io_failure",
    ),
    ("handlers/ipinfo_handler.py", "IPInfoManager._refresh_database"): ("io_failure",),
    (
        "handlers/ipinfo_handler.py",
        "IPInfoManager._warn_country_rules_without_database",
    ): ("io_failure",),
    (
        "handlers/ipinfo_handler.py",
        "IPInfoManager._warn_once_if_download_url_ignored",
    ): ("kinded",),
    ("handlers/ipinfo_handler.py", "IPInfoManager._warn_reader_unavailable"): (
        "io_failure",
        "io_failure",
    ),
    ("handlers/ratelimit_handler.py", "RateLimitManager._clear_redis_state"): (
        "redis_outage",
    ),
    ("handlers/ratelimit_handler.py", "RateLimitManager._emit_script_reloaded_event"): (
        "telemetry_failure",
    ),
    ("handlers/ratelimit_handler.py", "RateLimitManager._guarded_apps_to_reset"): (
        "api_call_argument",
    ),
    ("handlers/ratelimit_handler.py", "RateLimitManager._send_rate_limit_event"): (
        "telemetry_failure",
    ),
    ("handlers/ratelimit_handler.py", "RateLimitManager._warn_unbound_reset"): (
        "api_call_argument",
        "api_call_argument",
    ),
    ("handlers/ratelimit_handler.py", "RateLimitManager.initialize_redis"): (
        "redis_outage",
    ),
    ("handlers/ratelimit_handler.py", "_feed_rate_limit_autoban"): ("ban_decision",),
    ("handlers/ratelimit_handler.py", "_report_by_ip_block"): ("audit_log_line",),
    ("handlers/ratelimit_handler.py", "_resolve_redis_rate_limit_failure"): (
        "redis_outage",
    ),
    ("handlers/ratelimit_handler.py", "_send_by_ip_event"): ("telemetry_failure",),
    ("handlers/ratelimit_handler.py", "_shared_primitive_counts"): ("redis_outage",),
    ("handlers/ratelimit_handler.py", "_warn_redis_fail_open_in_memory_fallback"): (
        "redis_outage",
    ),
    ("handlers/redis_handler.py", "RedisManager._fail_on_connection_error"): (
        "redis_outage",
    ),
    ("handlers/redis_handler.py", "RedisManager._open_connection"): ("redis_outage",),
    ("handlers/redis_handler.py", "RedisManager._raise_operation_failure"): (
        "redis_outage",
    ),
    ("handlers/redis_handler.py", "RedisManager._safe_aclose"): ("redis_outage",),
    ("handlers/redis_handler.py", "RedisManager._send_redis_event"): ("redis_outage",),
    ("handlers/redis_handler.py", "RedisManager.initialize"): ("kinded",),
    ("handlers/suspatterns_handler.py", "_warn_if_legacy_detection"): (
        "deprecated_api_use",
        "deprecated_api_use",
    ),
    ("models.py", "SecurityConfig.warn_unknown_fields"): ("kinded",),
}
