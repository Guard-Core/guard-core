---

title: Models
description: API reference for guard-core's Pydantic models including SecurityConfig and DynamicRules
keywords: models, security config, dynamic rules, pydantic, guard-core
---

Models
======

The `models` module defines the Pydantic data models that configure guard-core's behavior.

___

SecurityConfig
--------------

The primary configuration model for guard-core. The code block below groups the most commonly used fields; it is not exhaustive (`SecurityConfig.model_fields` currently has 100 entries) -- introspect the installed model for the authoritative full list: `python -c "from guard_core.models import SecurityConfig; print(list(SecurityConfig.model_fields))"`.

```python
class SecurityConfig(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    trusted_proxies: tuple[str, ...] = Field(default_factory=tuple)
    trusted_proxy_depth: int = Field(default=1)
    trust_x_forwarded_proto: bool = Field(default=False)

    passive_mode: bool = Field(default=False)

    geo_ip_handler: GeoIPHandler | None = Field(default=None)

    enable_redis: bool = Field(default=True)
    redis_url: str | None = Field(default="redis://localhost:6379")
    redis_prefix: str = Field(default="guard_core:")

    whitelist: tuple[str, ...] | None = Field(default=None)
    blacklist: tuple[str, ...] = Field(default_factory=tuple)
    whitelist_countries: frozenset[str] = Field(default_factory=frozenset)
    blocked_countries: frozenset[str] = Field(default_factory=frozenset)
    blocked_user_agents: list[str] = Field(default_factory=list)

    auto_ban_threshold: int = Field(default=10, ge=1)
    auto_ban_duration: int = Field(default=3600, ge=1)

    threat_ban_config: MappingProxyType[str, ThreatBanConfig] = Field(
        default_factory=lambda: MappingProxyType({})
    )
    global_behavior_rules: tuple[BehaviorRuleConfig, ...] = Field(default_factory=tuple)

    excluded_detection_headers: set[str] = Field(default_factory=set)
    excluded_semantic_detection_headers: set[str] = Field(default_factory=set)
    excluded_detection_params: set[str] = Field(default_factory=set)
    excluded_detection_body_fields: set[str] = Field(default_factory=set)
    enabled_detection_categories: frozenset[str] = Field(
        default_factory=lambda: frozenset(ALL_DETECTION_CATEGORIES)
    )

    custom_log_file: str | None = Field(default=None)
    log_suspicious_level: (
        Literal["INFO", "DEBUG", "WARNING", "ERROR", "CRITICAL"] | None
    ) = Field(default="WARNING")
    log_request_level: (
        Literal["INFO", "DEBUG", "WARNING", "ERROR", "CRITICAL"] | None
    ) = Field(default=None)
    log_format: Literal["text", "json"] = Field(default="text")

    custom_error_responses: dict[int, str] = Field(default_factory=dict)

    rate_limit: int = Field(default=10)
    rate_limit_window: int = Field(default=60)

    enforce_https: bool = Field(default=False)

    security_headers: dict[str, Any] | None = Field(default_factory=...)

    custom_request_check: (
        Callable[[GuardRequest], Awaitable[GuardResponse | None]] | None
    ) = Field(default=None)
    custom_response_modifier: (
        Callable[[GuardResponse], Awaitable[GuardResponse]] | None
    ) = Field(default=None)

    enable_cors: bool = Field(default=False)
    cors_allow_origins: list[str] = Field(default_factory=lambda: ["*"])
    cors_allow_methods: list[str] = Field(
        default_factory=lambda: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]
    )
    cors_allow_headers: list[str] = Field(default_factory=lambda: ["*"])
    cors_allow_credentials: bool = Field(default=False)
    cors_expose_headers: list[str] = Field(default_factory=list)
    cors_max_age: int = Field(default=600)

    block_cloud_providers: frozenset[str] | None = Field(default=None)
    cloud_ip_refresh_interval: int = Field(default=3600, ge=60, le=86400)
    cloud_ip_store: CloudIpStoreProtocol | CloudIpStoreFactory | None = Field(
        default=None
    )

    lazy_init: bool = Field(default=True)
    geo_ip_db_max_age: int = Field(default=86400, ge=3600, le=604800)

    exclude_paths: list[str] = Field(
        default_factory=lambda: [
            "/docs",
            "/redoc",
            "/openapi.json",
            "/openapi.yaml",
            "/favicon.ico",
            "/static",
        ]
    )

    enable_ip_banning: bool = Field(default=True)
    enable_rate_limiting: bool = Field(default=True)
    enable_penetration_detection: bool = Field(default=True)

    ipinfo_token: str | None = Field(default=None)
    ipinfo_db_path: Path | None = Field(default=Path("data/ipinfo/country_asn.mmdb"))

    enable_agent: bool = Field(default=False)
    agent_api_key: str | None = Field(default=None)
    agent_endpoint: str = Field(default="https://api.guard-core.com")
    agent_project_id: str | None = Field(default=None)
    agent_buffer_size: int = Field(default=100)
    agent_flush_interval: int = Field(default=30)
    agent_enable_events: bool = Field(default=True)
    agent_enable_metrics: bool = Field(default=True)
    agent_timeout: int = Field(default=30)
    agent_retry_attempts: int = Field(default=3)

    enable_dynamic_rules: bool = Field(default=False)
    dynamic_rule_interval: int = Field(default=300)

    emergency_mode: bool = Field(default=False)
    emergency_whitelist: list[str] = Field(default_factory=list)
    endpoint_rate_limits: dict[str, tuple[int, int]] = Field(default_factory=dict)

    detection_compiler_timeout: float = Field(default=2.0, ge=0.1, le=10.0)
    detection_max_scan_seconds: float = Field(default=10.0, ge=0.1, le=60.0)
    detection_max_content_length: int = Field(default=10000, ge=1000, le=100000)
    detection_max_body_inspect_bytes: int = Field(default=262144, ge=1024, le=10485760)
    detection_preserve_attack_patterns: bool = Field(default=True)
    detection_semantic_threshold: float = Field(default=0.7, ge=0.0, le=1.0)
    detection_anomaly_threshold: float = Field(default=3.0, ge=1.0, le=10.0)
    detection_slow_pattern_threshold: float = Field(default=0.1, ge=0.01, le=1.0)
    detection_monitor_history_size: int = Field(default=1000, ge=100, le=10000)
    detection_max_tracked_patterns: int = Field(default=1000, ge=100, le=5000)
    detection_threat_score_threshold: float = Field(default=1.0, ge=0.0, le=10.0)
    detection_scan_body: bool = Field(default=True)

    def to_agent_config(self) -> "AgentConfig | None":
        """
        Build an AgentConfig from this SecurityConfig, or None if the agent
        is not enabled or guard-agent is not installed.
        """
```

### Validators

| Validator | Fields | Purpose |
|-----------|--------|---------|
| `validate_ip_lists` | `whitelist`, `blacklist` | Validates IP addresses and CIDR ranges, returns `tuple[str, ...]`. Raises `ValueError` on an invalid entry. |
| `validate_trusted_proxies` | `trusted_proxies` | Validates proxy IP addresses and CIDR ranges, returns `tuple[str, ...]`. Raises `ValueError` on an invalid entry. |
| `validate_proxy_depth` | `trusted_proxy_depth` | Ensures depth is at least 1 |
| `coerce_country_set` | `whitelist_countries`, `blocked_countries` | Accepts list/tuple/set/frozenset, normalizes each entry to uppercase, returns `frozenset[str]`. |
| `validate_cloud_providers` | `block_cloud_providers` | Requires the part before an optional `:!region` suffix to be in `VALID_CLOUD_PROVIDERS` (AWS, GCP, Azure); a region carve-out like `"GCP:!us-central1"` is kept, not stripped to a bare name. Raises `ValueError` naming any entry that fails this check, rather than silently dropping it. Returns `frozenset[str]`. |
| `validate_optional_extras_installed` | model-level | Requires the `redis`/`cloud`/`geo` extra (checked via `importlib.util.find_spec`) when the corresponding feature is configured; raises `ValueError` naming the missing extra's install command. |
| `validate_geo_ip_handler_exists` | model-level | Requires `geo_ip_handler` when country filtering is configured (falls back to constructing `IPInfoManager` if `ipinfo_token` is set). Also re-run from `__setattr__`/`model_copy` when `blocked_countries`, `whitelist_countries`, `geo_ip_handler`, or `ipinfo_token` is reassigned after construction, so the same requirement holds at runtime, not only at construction. |
| `validate_agent_config` | model-level | Requires `agent_api_key` when `enable_agent=True`; requires `enable_agent=True` when `enable_dynamic_rules=True`. |
| `validate_global_return_pattern_body_scan` | `global_behavior_rules` | Rejects a `return_pattern` rule whose pattern is not `status:` when `behavior_scan_response_body=False`, since such a rule could never match. |
| `validate_muted_event_types` | `muted_event_types` | Rejects unknown values (must be a subset of `EVENT_TYPE_VALUES`). Returns `frozenset[str]`. |
| `validate_muted_metric_types` | `muted_metric_types` | Rejects unknown values (must be a subset of `METRIC_TYPE_VALUES`). Returns `frozenset[str]`. |
| `validate_muted_check_logs` | `muted_check_logs` | Rejects unknown values (must be a subset of `CHECK_NAME_VALUES`). Returns `frozenset[str]`. |
| `validate_enabled_detection_categories` | `enabled_detection_categories` | Rejects unknown labels (must be a subset of `ALL_DETECTION_CATEGORIES`). Returns `frozenset[str]`. |
| `validate_threat_ban_config` | `threat_ban_config` | Rejects unknown category keys. Coerces raw dict values to `ThreatBanConfig`. Returns `MappingProxyType[str, ThreatBanConfig]`. |
| `validate_log_sensitive_headers` | `log_sensitive_headers` | Rejects a bare `str`/`bytes` value (previously iterated character by character and silently redacted nothing). Returns `frozenset[str]`. |
| `validate_log_sensitive_params` | `log_sensitive_params` | Rejects a bare `str`/`bytes` value. Returns `frozenset[str]`. |
| `validate_log_sensitive_body_fields` | `log_sensitive_body_fields` | Rejects a bare `str`/`bytes` value. Returns `frozenset[str]`. |

Reassigning a field after construction, or overwriting one via `model_copy(update=...)`, re-runs the same coercion and validation that ran at construction. This now also covers every collection-typed field, including thirteen newly covered in 4.0.0: `exclude_paths`, `global_behavior_rules`, `custom_error_responses`, `security_headers`, `cors_allow_origins`, `cors_allow_methods`, `cors_allow_headers`, `cors_expose_headers`, `agent_sensitive_headers`, `otel_resource_attributes`, `excluded_detection_headers`, `excluded_detection_params`, and `excluded_detection_body_fields`.

### Detection Exclusion Fields

These fields opt specific request components out of penetration detection. The header exclusion set is merged with the hardcoded default header list: browser boilerplate (`host`, `user-agent`, `accept`, `sec-fetch-*`, `sec-ch-ua*`, and similar) plus the proxy identity headers whose values are addresses or hostnames set by infrastructure (`forwarded`, `x-forwarded-for`, `x-forwarded-host`, `x-forwarded-proto`, `x-real-ip`, `x-client-ip`, `x-cluster-client-ip`, `cf-connecting-ip`, `true-client-ip`, `fly-client-ip`, `x-envoy-external-address`). Excluded headers still receive the always-on command-injection check. `enabled_detection_categories` narrows the scan to a subset of the 18 known threat categories.

| Field                              | Type        | Default                          | Description                                                                |
|------------------------------------|-------------|----------------------------------|----------------------------------------------------------------------------|
| `excluded_detection_headers`       | `set[str]`  | `set()`                          | Headers exempted only from the categories known to false-positive on their typical values: identity and proxy headers such as `X-Forwarded-For`, `X-Real-IP`, `Host`, `Origin` and `Via` skip `ssrf` only, and every other category (sqli, xss, cmd_injection, template, Log4Shell) still scans them. A name outside the built-in identity set inherits the same rule when its value looks like an address chain, otherwise it gets no exclusion at all. Merged with the hardcoded default list. |
| `excluded_semantic_detection_headers` | `set[str]`  | `set()`                          | Opt-in. Header names (case-insensitive) whose values skip the semantic analyzer only; regex category scanning of these headers is unchanged, and `excluded_detection_headers` semantics are untouched. Use it when a header legitimately carries high-entropy encoded data, for example `cookie` or `authorization` for apps with JWT sessions, whose base64 segments score close to `detection_semantic_threshold`. Merged with the route-level set from `@security.detection_exclusion(semantic_headers=...)`. |
| `excluded_detection_params`        | `set[str]`  | `set()`                          | Query parameter names skipped by detection.                                |
| `excluded_detection_body_fields`   | `set[str]`  | `set()`                          | Top-level JSON body keys skipped by detection.                             |
| `enabled_detection_categories`     | `frozenset[str]`  | `frozenset(ALL_DETECTION_CATEGORIES)`  | Categories scanned for. Validator rejects unknown labels.                  |

`ALL_DETECTION_CATEGORIES` is defined in `guard_core.handlers.suspatterns_handler` and contains: `xss`, `sqli`, `dir_traversal`, `path_traversal`, `cmd_injection`, `file_inclusion`, `ldap`, `xml`, `ssrf`, `nosql`, `file_upload`, `template`, `http_split`, `sensitive_file`, `cms_probing`, `recon`, `proto_pollution`, `code_injection`. Custom user patterns carry the literal category `"custom"` and run regardless of `enabled_detection_categories` filtering.

### Per-Category Ban Configuration

`threat_ban_config` lets operators set per-category ban thresholds and durations. Categories not present in the dict fall back to the flat `auto_ban_threshold` / `auto_ban_duration`.

| Field                | Type                              | Default | Description                                          |
|----------------------|-----------------------------------|---------|------------------------------------------------------|
| `threat_ban_config`  | `MappingProxyType[str, ThreatBanConfig]`      | `mappingproxy({})`    | Per-category overrides. Validator rejects unknown keys. |

See [Ban Configuration](ban-config.md) for `ThreatBanConfig` details and examples.

### Global Behavior Rules

`global_behavior_rules` applies behavior rules to every route without requiring decorators. Useful for global 404 noise tracking or service-wide frequency rules.

| Field                                       | Type                          | Default    | Description                                  |
|-----------------------------------------------|-------------------------------|------------|----------------------------------------------|
| `global_behavior_rules`                        | `tuple[BehaviorRuleConfig, ...]` | `()`    | Behavior rules merged into every route. Immutable: append via whole-field reassignment (`config.global_behavior_rules = (*config.global_behavior_rules, new_rule)`), not `.append()`. |
| `behavior_scan_response_body`                  | `bool`                        | `False`    | Gates response-body reading for `return_pattern` rules whose pattern is not `status:`. |
| `behavior_max_response_body_inspect_bytes`     | `int`                         | `262144`   | Cap on bytes read/retained per response when `behavior_scan_response_body` is `True`. |
| `body_read_timeout`                            | `float`                       | `3.0`      | Seconds to wait on an adapter's `read_body_prefix`/`body` call before treating the body as unavailable. Bounds `BoundedBodyReader`, `BoundedResponseBodyReader`, and the plain `GuardRequest.body` read in `guard_core` (async) via `asyncio.wait_for`. In `guard_core.sync`, each read runs on its own daemon thread and this bounds how long the caller joins that thread; see `sync_body_read_max_concurrent` for the thread budget. |

See [Behavior Rules](behavior-rules.md) for `BehaviorRuleConfig` details, the return-pattern format table, and the detection-correlation example.

### IP Lifecycle Controls

These fields tune how guard-core bootstraps geo-IP and cloud-IP data. They are inert by default and only matter for cold-start tuning or horizontal-scale deployments.

| Field                | Type                                                          | Default | Description                                                      |
|----------------------|---------------------------------------------------------------|---------|------------------------------------------------------------------|
| `lazy_init`          | `bool`                                                        | `True`  | When `True` (default), cloud-IP HTTP fetches and IPInfo MMDB downloads run in a background task instead of being awaited inline, so the application does not block on multi-second network calls. This only takes effect when Redis is enabled (`enable_redis=True` with a `redis_handler` wired) **and** the adapter calls `initialize_redis_handlers()` from its own startup hook (e.g. fastapi-guard's lifespan integration) -- it is not triggered by app boot on its own. Without Redis, or without that hook wired, cloud/geo initialization instead happens through their on-demand paths and this flag has no effect. First requests may see partially-populated cloud-IP ranges until the background task completes (typically 1-3 seconds). Set to `False` to restore synchronous-init behavior. |
| `geo_ip_db_max_age`  | `int`                                                         | `86400` | Maximum age in seconds for IPInfo MMDB before re-download (3600 - 604800). |
| `cloud_ip_store`     | `CloudIpStoreProtocol \| CloudIpStoreFactory \| None`         | `None`  | Override for the cloud-IP backend. Accepts either a ready instance implementing `CloudIpStoreProtocol`, or a `CloudIpStoreFactory` callable `(RedisHandlerProtocol) -> CloudIpStoreProtocol` invoked once the Redis handler is built. When `None` (default), guard-core auto-constructs a `RedisCloudIpStore` if `enable_redis=True`, else falls back to `InMemoryCloudIpStore`. |

### Cloud Provider Constants

`guard_core.models` exports two related symbols for cloud-provider validation:

| Symbol                  | Type                       | Description                                                                 |
|-------------------------|----------------------------|-----------------------------------------------------------------------------|
| `CloudProvider`         | `Literal["AWS", "GCP", "Azure", "DigitalOcean", "Linode", "Vultr"]` | Type alias naming the six user-blockable providers. `block_cloud_providers` itself is typed `frozenset[str] \| None` (not `frozenset[CloudProvider]`), since a validated entry can carry a `:!region` carve-out suffix that isn't a bare `CloudProvider` value. |
| `VALID_CLOUD_PROVIDERS` | `frozenset[str]`           | Runtime guard set derived from `typing.get_args(CloudProvider)`. Used by `validate_cloud_providers`, `DynamicRules.blocked_cloud_providers` filtering, and the `@block_clouds` decorator. |

Adding a new provider is a one-line edit to the `CloudProvider` Literal, every consumer picks up the change automatically.

See [Cloud IP Store](cloud-ip-store.md) for the protocol contract and the in-memory / Redis implementations.

___

ThreatBanConfig
---------------

Per-category ban policy. Used as the value type in `SecurityConfig.threat_ban_config`.

```python
class ThreatBanConfig(BaseModel):
    threshold: int = Field(ge=1)
    duration: int = Field(ge=1)
```

| Field       | Type | Description                                       |
|-------------|------|---------------------------------------------------|
| `threshold` | `int` | Number of detections in this category before auto-ban. |
| `duration`  | `int` | Ban duration in seconds.                          |

___

BehaviorRuleConfig
------------------

Configuration shape for entries in `SecurityConfig.global_behavior_rules`. Mirrors the `BehaviorRule` decorator API but is serializable through Pydantic.

```python
class BehaviorRuleConfig(BaseModel):
    rule_type: Literal["usage", "return_pattern", "frequency"]
    threshold: int = Field(ge=1)
    window: int = Field(default=3600, ge=1)
    pattern: str | None = None
    action: Literal["ban", "log", "throttle", "alert"] = "log"
    ban_duration: int | None = Field(default=None, ge=1)
    correlate_with_detection: bool = False
```

| Field                       | Type                                          | Default  | Description                                                                 |
|-----------------------------|-----------------------------------------------|----------|-----------------------------------------------------------------------------|
| `rule_type`                 | `"usage" \| "return_pattern" \| "frequency"`  | required | Rule kind. `return_pattern` matches against response status / body content. |
| `threshold`                 | `int`                                         | required | Trigger count within `window`.                                              |
| `window`                    | `int`                                         | `3600`   | Window in seconds.                                                          |
| `pattern`                   | `str \| None`                                 | `None`   | Match expression for `return_pattern` rules (e.g. `"status:404"`, or `"json:"` / `"regex:"` / a bare substring against the response body). A body-reading pattern requires `SecurityConfig.behavior_scan_response_body=True`; construction raises `ValueError` otherwise. See [Behavior Rules](behavior-rules.md#return-pattern-formats). |
| `action`                    | `"ban" \| "log" \| "throttle" \| "alert"`     | `"log"`  | Action when threshold is exceeded.                                          |
| `ban_duration`              | `int \| None`                                 | `None`   | Ban duration in seconds when `action="ban"`. When `None`, falls back to a hardcoded 3600 seconds -- independent of `auto_ban_duration`, which only governs the unrelated flat penetration-detection ban path. |
| `correlate_with_detection`  | `bool`                                        | `False`  | Halve the threshold (floor 1) when the IP has any positive `suspicious_request_counts` entry. |

___

DynamicRules
------------

Model for rules pushed dynamically from the Guard Agent SaaS platform.

```python
class DynamicRules(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    rule_id: str = Field(description="Unique rule ID")
    version: int = Field(description="Rule version number")
    timestamp: datetime = Field(description="Rule creation/update timestamp")
    expires_at: datetime | None = Field(default=None)
    ttl: int = Field(default=300)

    ip_blacklist: list[str] = Field(default_factory=list)
    ip_whitelist: list[str] = Field(default_factory=list)
    ip_ban_duration: int = Field(default=3600)

    blocked_countries: list[str] = Field(default_factory=list)
    whitelist_countries: list[str] = Field(default_factory=list)

    global_rate_limit: int | None = Field(default=None)
    global_rate_window: int | None = Field(default=None)
    endpoint_rate_limits: dict[str, tuple[int, int]] = Field(default_factory=dict)

    blocked_cloud_providers: set[str] = Field(default_factory=set)
    blocked_user_agents: list[str] = Field(default_factory=list)
    suspicious_patterns: list[str] = Field(default_factory=list)

    enable_penetration_detection: bool | None = Field(default=None)
    enable_ip_banning: bool | None = Field(default=None)
    enable_rate_limiting: bool | None = Field(default=None)
    auto_ban_threshold: int | None = Field(default=None, ge=1)
    auto_ban_duration: int | None = Field(default=None, ge=1)
    enable_rate_limit_auto_ban: bool | None = Field(default=None)

    emergency_mode: bool = Field(default=False)
    emergency_whitelist: list[str] = Field(default_factory=list)
```

| Field                         | Type            | Default | Description                                                                 |
|-------------------------------|------------------|---------|-------------------------------------------------------------------------------|
| `expires_at`                  | `datetime \| None` | `None`  | Rule expiration time. `None` means the rule never expires (unchanged default). When set, see [Expiration](#expiration-expires_at) below. |
| `ttl`                         | `int`            | `300`   | Cache TTL in seconds for the agent-side fetch, unrelated to `expires_at`; it does not drive expiry. |
| `auto_ban_threshold`          | `int \| None`    | `None`  | Runtime override for `SecurityConfig.auto_ban_threshold` (`>= 1`). |
| `auto_ban_duration`           | `int \| None`    | `None`  | Runtime override for `SecurityConfig.auto_ban_duration` (`>= 1`). |
| `enable_rate_limit_auto_ban`  | `bool \| None`   | `None`  | Runtime override for `SecurityConfig.enable_rate_limit_auto_ban`. See [Rate-limit auto-ban](ban-config.md#rate-limit-auto-ban). |

### Runtime overrides

`enable_penetration_detection`, `enable_ip_banning`, `enable_rate_limiting`, `auto_ban_threshold`, `auto_ban_duration`, and `enable_rate_limit_auto_ban` are all applied by `DynamicRuleManager._apply_feature_toggles` on the same if-not-`None` convention: each field defaults to `None`, and a push only overwrites the matching `SecurityConfig` field when the pushed value is not `None`. A push that sets `auto_ban_threshold` mutates `SecurityConfig.auto_ban_threshold` directly, the same field the flat auto-ban fallback reads (see [Ban Configuration](ban-config.md)); there is no separate ban-engine tier for dynamic-rule overrides.

### Expiration (`expires_at`)

`expires_at` is live: `DynamicRuleManager._check_rule_expiry` evaluates it once per poll tick, under the apply lock, before the manager fetches a new rule. A naive `expires_at` (no `tzinfo`) is treated as UTC. Expiry is keyed on `expires_at` alone; `ttl` plays no part in it.

On the first no-rule-to-active-rule transition, `_apply_rules` captures a base snapshot of `DynamicRuleManager._SNAPSHOT_FIELDS` (the same `SecurityConfig` fields dynamic-rule overrides can touch: country, cloud-provider, user-agent, rate-limit, feature-toggle, and emergency-mode settings) and retains it across every superseding push while a rule stays active. When the active rule's `expires_at` passes, `_check_rule_expiry` restores that retained base snapshot, reverting to the original pre-any-rule config rather than to whatever an intermediate push left behind (this also undoes the auto-ban-threshold halving `_activate_emergency_mode` applies). After the revert, both the current rule and the retained snapshot are cleared, so the next fetched rule starts a fresh snapshot cycle.

This retained base snapshot is a distinct mechanism from the local rollback snapshot `_apply_rules` takes at the start of every individual apply: the rollback snapshot exists only to undo that one call if it raises, and is discarded once the call succeeds, except on the transition apply, where the same snapshot is promoted into the retained base snapshot instead of being discarded. From then on the two diverge: later applies (superseding pushes while a rule is already active) still take and discard their own per-call rollback snapshot, but leave the retained base snapshot untouched, so only expiry ever consumes it.

A rule whose `expires_at` is already past when `update_rules` receives it never activates: `_reject_if_already_expired` runs right after the fetch, before the version check, and rejects it outright rather than applying it and reverting on the next tick. This closes the gap where an agent that keeps serving the same already-expired rule caused a revert-then-reapply loop on every poll (config never settling at base, an event pair per tick, and a repeated `[EMERGENCY MODE]` log for a rule carrying `emergency_mode`). The rejection is silent to the caller, `update_rules` simply returns, but logs a warning naming the rule and version, once per distinct `(rule_id, version)`, so a stale agent polling with the same expired rule cannot spam the log. Expiry enforcement lives entirely in `DynamicRuleManager`; the `get_dynamic_rules` agent protocol places no obligation on the agent to withhold an expired rule, so this guard is what makes expiry hold regardless of agent behavior.
