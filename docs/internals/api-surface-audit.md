# API Surface Audit

A scoped inventory of the guard-core public API surface (the `SecurityConfig` model and the package exports) with a recommended action per item. The goal is an intuitive, non-bloated, composable surface. This audit's *recommendations* are non-breaking by design: none of the Keep/Deprecate/Group calls below ask for a field to be removed. The *types* in the table reflect the 3.12.0 release as shipped, which does include breaking type changes for nine fields (`whitelist`, `blacklist`, `trusted_proxies`, `threat_ban_config`, `enabled_detection_categories`, `muted_event_types`, `muted_metric_types`, `muted_check_logs`, `block_cloud_providers`) plus a stricter `block_cloud_providers` validator that now raises instead of silently dropping an unrecognized provider -- see [CHANGELOG.md](https://github.com/Guard-Core/guard-core/blob/master/CHANGELOG.md) for the full migration note.

Current totals (re-verified against source for the 3.12.0 release). This audit intentionally does not carry per-field line numbers: `models.py` changes with every release and a line number is stale the moment the next field is inserted above it, which happened here more than once. Field names are the stable identifier; find a field's current line with `grep -n '    <field_name>:' guard_core/models.py`.

- `SecurityConfig`: **115 fields**, 18 validators, 1 `to_agent_config()` method (`guard_core/models.py`).
- `guard_core` exports: **24** symbols (`guard_core/__init__.py`).
- `fastapi-guard` re-exports: derived from the 24 above plus its own `SecurityMiddleware` and `__version__` (not independently re-verified here; see [Exports](#exports)).

Recommendation legend: **Keep** (core/everyday or stable advanced) · **Deprecate** (scheduled for removal, kept working) · **Group?** (candidate for an optional nested sub-config, see [Grouping opportunities](#grouping-opportunities)) · **Remove** (none in this audit, removals are out of scope).

## SecurityConfig fields

Ordered by domain, then by field name.

| Field | Type | Default | Domain | Recommendation |
|---|---|---|---|---|
| `enable_agent` | `bool` | `False` | agent | Keep |
| `agent_api_key` | `str \| None` | `None` | agent | Keep |
| `agent_strict` | `bool` | `False` | agent | Keep |
| `agent_endpoint` | `str` | `"https://api.guard-core.com"` | agent | Keep · Group? |
| `agent_project_id` | `str \| None` | `None` | agent | Keep · Group? |
| `agent_buffer_size` | `int` | `100` | agent | Keep · Group? |
| `agent_flush_interval` | `int` | `30` | agent | Keep · Group? |
| `agent_enable_events` | `bool` | `True` | agent | Keep · Group? |
| `agent_enable_metrics` | `bool` | `True` | agent | Keep · Group? |
| `agent_timeout` | `int` | `30` | agent | Keep · Group? |
| `agent_retry_attempts` | `int` | `3` | agent | Keep · Group? |
| `agent_project_encryption_key` | `str \| None` | `None` | agent | Keep · Group? |
| `agent_guard_version` | `str \| None` | `None` | agent | Keep · Group? |
| `agent_high_watermark_ratio` | `float \| None` | `None` | agent | Keep · Group? |
| `agent_max_concurrent_flushes` | `int \| None` | `None` | agent | Keep · Group? |
| `agent_buffer_overflow_policy` | `Literal["drop","block","raise"] \| None` | `None` | agent | Keep · Group? |
| `agent_backoff_factor` | `float \| None` | `None` | agent | Keep · Group? |
| `agent_sensitive_headers` | `list[str] \| None` | `None` | agent | Keep · Group? |
| `agent_max_payload_size` | `int \| None` | `None` | agent | Keep · Group? |
| `agent_compression_enabled` | `bool \| None` | `None` | agent | Keep · Group? |
| `agent_compression_threshold` | `int \| None` | `None` | agent | Keep · Group? |
| `agent_install_id` | `str \| None` | `None` | agent | Keep · Group? |
| `agent_payload_signing_secret` | `str \| None` | `None` | agent | Keep · Group? |
| `agent_status_interval` | `int` | `300` | agent | Keep · Group? |
| `auto_ban_threshold` | `int` | `10` | auto-ban | Keep |
| `auto_ban_duration` | `int` | `3600` | auto-ban | Keep |
| `threat_ban_config` | `MappingProxyType[str, ThreatBanConfig]` | `mappingproxy` | auto-ban | Keep |
| `global_behavior_rules` | `tuple[BehaviorRuleConfig, ...]` | `tuple` | behavioral | Keep |
| `behavior_scan_response_body` | `bool` | `False` | behavioral | Keep |
| `behavior_max_response_body_inspect_bytes` | `int` | `262144` | behavioral | Keep |
| `body_read_timeout` | `float` | `3.0` | behavioral | Keep |
| `block_cloud_providers` | `frozenset[str] \| None` | `None` | cloud | Keep |
| `cloud_ip_refresh_interval` | `int` | `3600` | cloud | Keep |
| `cloud_ip_store` | `CloudIpStoreProtocol \| CloudIpStoreFactory \| None` | `None` | cloud | Keep |
| `enable_cors` | `bool` | `False` | cors | Keep |
| `cors_allow_origins` | `list[str]` | `["*"]` | cors | Keep · Group? |
| `cors_allow_methods` | `list[str]` | `[GET,POST,PUT,PATCH,DELETE,OPTIONS]` | cors | Keep · Group? |
| `cors_allow_headers` | `list[str]` | `["*"]` | cors | Keep · Group? |
| `cors_allow_credentials` | `bool` | `False` | cors | Keep · Group? |
| `cors_expose_headers` | `list[str]` | `list` | cors | Keep · Group? |
| `cors_max_age` | `int` | `600` | cors | Keep · Group? |
| `whitelist_countries` | `frozenset[str]` | `frozenset` | geo/country | Keep |
| `blocked_countries` | `frozenset[str]` | `frozenset` | geo/country | Keep |
| `geo_ip_handler` | `GeoIPHandler \| None` | `None` | geo/country | Keep |
| `geo_ip_db_max_age` | `int` | `86400` | geo/country | Keep |
| `detection_compiler_timeout` | `float` | `2.0` | detection | Keep · Group? |
| `detection_max_content_length` | `int` | `10000` | detection | Keep · Group? |
| `detection_max_body_inspect_bytes` | `int` | `262144` | detection | Keep · Group? |
| `detection_preserve_attack_patterns` | `bool` | `True` | detection | Keep · Group? |
| `detection_semantic_threshold` | `float` | `0.7` | detection | Keep · Group? |
| `detection_anomaly_threshold` | `float` | `3.0` | detection | Keep · Group? |
| `detection_slow_pattern_threshold` | `float` | `0.1` | detection | Keep · Group? |
| `detection_monitor_history_size` | `int` | `1000` | detection | Keep · Group? |
| `detection_max_tracked_patterns` | `int` | `1000` | detection | Keep · Group? |
| `detection_anomaly_emission_cooldown` | `float` | `60.0` | detection | Keep · Group? |
| `detection_min_samples_for_anomaly` | `int` | `30` | detection | Keep · Group? |
| `detection_threat_score_threshold` | `float` | `1.0` | detection | Keep · Group? |
| `detection_scan_body` | `bool` | `True` | detection | Keep · Group? |
| `enabled_detection_categories` | `frozenset[str]` | `ALL_DETECTION_CATEGORIES` | detection | Keep |
| `excluded_detection_headers` | `set[str]` | `set` | detection (excl.) | Keep |
| `excluded_detection_params` | `set[str]` | `set` | detection (excl.) | Keep |
| `excluded_detection_body_fields` | `set[str]` | `set` | detection (excl.) | Keep |
| `enable_penetration_detection` | `bool` | `True` | detection | Keep |
| `enable_dynamic_rules` | `bool` | `False` | dynamic-rules | Keep |
| `dynamic_rule_interval` | `int` | `300` | dynamic-rules | Keep |
| `emergency_mode` | `bool` | `False` | dynamic-rules | Keep |
| `emergency_whitelist` | `list[str]` | `list` | dynamic-rules | Keep |
| `endpoint_rate_limits` | `dict[str, tuple[int, int]]` | `dict` | dynamic-rules | Keep |
| `enable_enrichment` | `bool` | `False` | enrichment | Keep |
| `ipinfo_token` | `str \| None` | `None` | ipinfo | **Deprecate (warns)** |
| `ipinfo_db_path` | `Path \| None` | `Path("data/ipinfo/country_asn.mmdb")` | ipinfo | **Deprecate (warns)** |
| `custom_log_file` | `str \| None` | `None` | logging | Keep |
| `log_suspicious_level` | `Literal[...] \| None` | `"WARNING"` | logging | Keep |
| `log_request_level` | `Literal[...] \| None` | `None` | logging | Keep |
| `log_country_check_level` | `Literal[...] \| None` | `"INFO"` | logging | Keep |
| `log_format` | `Literal["text","json"]` | `"text"` | logging | Keep |
| `enable_logfire` | `bool` | `False` | logfire | Keep |
| `logfire_service_name` | `str` | `"guard-core"` | logfire | Keep |
| `muted_event_types` | `frozenset[str]` | `frozenset` | muted | Keep |
| `muted_metric_types` | `frozenset[str]` | `frozenset` | muted | Keep |
| `muted_check_logs` | `frozenset[str]` | `frozenset` | muted | Keep |
| `enable_otel` | `bool` | `False` | otel | Keep |
| `otel_service_name` | `str` | `"guard-core"` | otel | Keep · Group? |
| `otel_exporter_endpoint` | `str \| None` | `None` | otel | Keep · Group? |
| `otel_resource_attributes` | `dict[str, str]` | `dict` | otel | Keep · Group? |
| `trusted_proxies` | `tuple[str, ...]` | `tuple` | proxy | Keep |
| `trusted_proxy_depth` | `int` | `1` | proxy | Keep |
| `trust_x_forwarded_proto` | `bool` | `False` | proxy | Keep |
| `rate_limit` | `int` | `10` | rate-limit | Keep |
| `rate_limit_window` | `int` | `60` | rate-limit | Keep |
| `enable_rate_limiting` | `bool` | `True` | rate-limit | Keep |
| `enable_redis` | `bool` | `True` | redis | Keep |
| `redis_url` | `str \| None` | `"redis://localhost:6379"` | redis | Keep |
| `redis_prefix` | `str` | `"guard_core:"` | redis | Keep |
| `redis_socket_connect_timeout` | `float \| None` | `2.0` | redis | Keep · Group? |
| `redis_socket_timeout` | `float \| None` | `2.0` | redis | Keep · Group? |
| `redis_health_check_interval` | `int` | `30` | redis | Keep · Group? |
| `redis_max_connections` | `int \| None` | `None` | redis | Keep · Group? |
| `redis_retries` | `int` | `1` | redis | Keep · Group? |
| `redis_fail_open` | `bool` | `False` | redis | Keep |
| `security_headers` | `dict[str, Any] \| None` | headers dict | security-headers | Keep |
| `enforce_https` | `bool` | `False` | security-headers | Keep |
| `whitelist` | `tuple[str, ...] \| None` | `None` | allow/deny | Keep |
| `blacklist` | `tuple[str, ...]` | `tuple` | allow/deny | Keep |
| `blocked_user_agents` | `list[str]` | `list` | allow/deny | Keep |
| `enable_ip_banning` | `bool` | `True` | ip-banning | Keep |
| `passive_mode` | `bool` | `False` | mode | Keep |
| `custom_error_responses` | `dict[int, str]` | `dict` | hooks | Keep |
| `custom_request_check` | `Callable[...] \| None` | `None` | hooks | Keep |
| `custom_response_modifier` | `Callable[...] \| None` | `None` | hooks | Keep |
| `on_error` | `Callable[[str, BaseException, dict], None] \| None` | `None` | hooks | Keep |
| `lazy_init` | `bool` | `True` | init | Keep |
| `exclude_paths` | `list[str]` | docs/static defaults | init | Keep |
| `fail_secure` | `bool` | `True` | failure-mode | Keep |
| `route_resolution_strict` | `bool` | `False` | failure-mode | Keep |

No field is required (every field has a default or `default_factory`).

## Field counts by domain

- agent: 24
- detection (incl. 3 `excluded_detection_*` + `enable_penetration_detection`): 18
- redis: 9
- hooks: 4 · logging: 5 · geo/country: 4 · otel: 4
- cors: 7 · dynamic-rules: 5
- auto-ban: 3 · cloud: 3 · muted: 3 · proxy: 3 · rate-limit: 3 · allow/deny: 3
- security-headers: 2 · ipinfo: 2 · logfire: 2 · init: 2 · failure-mode: 2
- behavioral: 4 · enrichment: 1 · ip-banning: 1 · mode: 1

**Total: 115 fields, all itemized in the table above.**

## Deprecations (wired in this audit)

`ipinfo_token` and `ipinfo_db_path` have self-described as *Deprecated* for some time, directing users to a custom `geo_ip_handler`. They now emit a runtime `DeprecationWarning` **when explicitly set**: the warning is raised from a `model_validator` keyed on `model_fields_set`, so it fires once at construction and never on internal access or when the field is left at its default.

```text
ipinfo_token is deprecated and will be removed in a future release;
create a custom geo_ip_handler instead.
```

- Non-breaking: both fields keep working; the engine still auto-builds an `IPInfoManager` from them when country lists are set and no `geo_ip_handler` is supplied (`validate_geo_ip_handler_exists`).
- Removal target: a future **major** release. Until then, migrate by passing a `geo_ip_handler` (any `GeoIPHandler`) directly.
- The suite filters this specific warning (`pyproject.toml` `filterwarnings`) so existing fixtures stay quiet; dedicated tests assert it still fires.

## Grouping opportunities

Four prefixes dominate the field count and are good candidates for **optional** nested sub-config models (e.g. `config.agent.*`, `config.cors.*`, `config.detection.*`, `config.otel.*`): agent (24), detection (18), cors (7), otel (4). Presented as an option, **not applied**, because of the trade-offs:

- **For:** smaller top-level namespace; related knobs discoverable together; clearer typing per concern.
- **Against (breaking unless aliased):** the current flat construction (`SecurityConfig(agent_api_key=..., cors_allow_origins=...)`) is the documented, intuitive surface the design partner likes. Any grouping must ship as a **non-breaking additive alias layer** (accept both flat and nested, keep flat in `__init__` signatures) or it breaks every existing call site.

Recommendation: defer. If pursued, do it as an additive alias layer behind its own change with a migration note, never as a silent restructure.

## Exports

`guard_core/__init__.py` `__all__` (24): `SecurityConfig`, `SecurityDecorator`, `RouteConfig`, `BehaviorTracker`, `BehaviorRule`, `ip_ban_manager`, `IPBanManager`, `cloud_handler`, `CloudManager`, `IPInfoManager`, `rate_limit_handler`, `RateLimitManager`, `redis_handler`, `RedisManager`, `security_headers_manager`, `SecurityHeadersManager`, `sus_patterns_handler`, `BoundedBodyReader`, `BoundedResponseBodyReader`, `GeoIPHandler`, `RedisHandlerProtocol`, `GuardRequest`, `GuardResponse`, `GuardResponseFactory`.

`fastapi-guard/guard/__init__.py` `__all__`: the 24 above + the fastapi-guard-only `SecurityMiddleware` and `__version__`, if the derivation this section describes still holds -- not independently re-verified against the fastapi-guard repository as part of this update.

Single source of truth: fastapi-guard derives its `__all__` from `guard_core.__all__` plus its two locals, and a test asserts every exported name is importable, so a new guard-core export can't silently go missing downstream. `IPInfoManager` stays exported even though `ipinfo_*` config is deprecated; custom `geo_ip_handler` implementations may still construct it directly. `BoundedBodyReader` and `BoundedResponseBodyReader` are optional capability protocols (bounded body reading for requests and responses respectively), not part of the required `GuardRequest`/`GuardResponse` surface; see [Protocols](../api/protocols.md).

## Validators & methods (reference)

`warn_unknown_fields` · `validate_ip_lists` · `validate_trusted_proxies` · `validate_proxy_depth` · `coerce_country_set` · `validate_cloud_providers` · `validate_optional_extras_installed` · `validate_geo_ip_handler_exists` · `warn_country_allowlist_shadows_blocklist` · `validate_agent_config` · `validate_global_return_pattern_body_scan` (rejects a `global_behavior_rules` `return_pattern` rule with a non-`status:` pattern when `behavior_scan_response_body=False`) · `warn_deprecated_fields` · `validate_muted_event_types` · `validate_muted_metric_types` · `validate_enabled_detection_categories` · `validate_threat_ban_config` · `validate_muted_check_logs` · `validate_exclude_paths` · `to_agent_config` (method). 18 validators total.
