# Telemetry

Guard Core emits security events and request metrics through a composable telemetry pipeline. Events can be muted, metrics can be muted, individual security-check logs can be muted, and exports to OpenTelemetry and Logfire are opt-in.

## Two-tier model

Guard Core ships telemetry in two tiers. Raw signal is free and speaks open standards. Enriched signal is guard-agent-gated and carries additional identity, threat-score, rule, and behavioural-correlation metadata that the SaaS dashboard (and your own tooling) can use to correlate attacks and prioritise investigation.

| Tier | Prerequisites | What every exporter sees |
|---|---|---|
| **Raw** | `enable_otel=True` and/or `enable_logfire=True` | All event types, all metrics, W3C `traceparent` / `tracestate` propagation, muting. No `guard.*` enrichment fields. |
| **Enriched** | `enable_agent=True` + `enable_enrichment=True` (agent optional for actual transport; enrichment itself runs client-side) | Everything in Raw, **plus** per-event `guard.project_id`, `guard.service.name`, `guard.deployment.environment`, `guard.threat_score`, `guard.rule.id` + `guard.rule.version`, `guard.behavior.correlation_key`, `guard.behavior.recent_event_count`. Metrics additionally inherit `guard.project_id`, `guard.service.name`, `guard.deployment.environment` as tags. |

Setting `enable_enrichment=True` without `enable_agent=True` raises `ValidationError`, enrichment is the guard-agent-gated tier by design.

## Config surface

Ten `SecurityConfig` fields control telemetry:

| Field | Type | Default | Purpose |
|---|---|---|---|
| `muted_event_types` | `set[str]` | `set()` | Suppress these event types from every exporter. |
| `muted_metric_types` | `set[str]` | `set()` | Suppress these metric types from every exporter. |
| `muted_check_logs` | `set[str]` | `set()` | Suppress in-check `log_activity()` output for these checks. |
| `enable_otel` | `bool` | `False` | Enable OpenTelemetry span/metric export (requires `[otel]` extra). |
| `otel_service_name` | `str` | `"guard-core"` | Service name for OpenTelemetry resource. |
| `otel_exporter_endpoint` | `str \| None` | `None` | OTLP/HTTP endpoint. `None` uses OTel's default (`localhost:4318`). |
| `otel_resource_attributes` | `dict[str, str]` | `{}` | Extra OpenTelemetry resource attributes (e.g. `deployment.environment`, `service.version`). |
| `enable_logfire` | `bool` | `False` | Enable Logfire export (requires `[logfire]` extra). |
| `logfire_service_name` | `str` | `"guard-core"` | Service name for Logfire. |
| `enable_enrichment` | `bool` | `False` | Populate `guard.*` metadata on every event and metric. **Requires `enable_agent=True`.** |

All three mute fields validate their contents at config time. Unknown values raise `ValidationError` and the error message lists the valid values.

Mute is applied globally inside `CompositeAgentHandler.send_event` / `.send_metric`. Every event emitted via `SecurityEventBus`, decorator-level `send_decorator_event`, or handler-level `agent_handler.send_event()` goes through the composite, so mute works uniformly regardless of emission site, as long as the adapter installs the composite through `HandlerInitializer.initialize_agent_integrations()`.

## Valid mute values

Drawn from constants in `guard_core.core.events.event_types`:

- `EVENT_TYPE_VALUES` (40 values): `access_denied`, `authentication_failed`, `behavioral_violation`, `cloud_blocked`, `content_filtered`, `country_blocked`, `csp_violation`, `custom_request_check`, `decoding_error`, `decorator_violation`, `detection_engine_callback_error`, `dynamic_rule_applied`, `dynamic_rule_updated`, `dynamic_rule_violation`, `emergency_mode_activated`, `emergency_mode_block`, `geo_lookup_failed`, `https_enforced`, `ip_ban_failed`, `ip_ban_refused`, `ip_banned`, `ip_blocked`, `ip_unbanned`, `path_excluded`, `pattern_added`, `pattern_anomaly_slow_execution`, `pattern_anomaly_statistical_anomaly`, `pattern_anomaly_timeout`, `pattern_detected`, `pattern_removed`, `penetration_attempt`, `rate_limit_script_reloaded`, `rate_limited`, `redis_connection`, `redis_error`, `route_unresolved`, `security_bypass`, `security_headers_applied`, `suspicious_request`, `user_agent_blocked`
- `METRIC_TYPE_VALUES`: `error_rate`, `request_count`, `response_time`
- `CHECK_NAME_VALUES`: `authentication`, `cloud_ip_refresh`, `cloud_provider`, `custom_request`, `custom_validators`, `emergency_mode`, `https_enforcement`, `ip_security`, `rate_limit`, `referrer`, `request_logging`, `request_size_content`, `required_headers`, `route_config`, `suspicious_activity`, `time_window`, `user_agent`

## Enrichment fields (guard-agent tier)

When `enable_enrichment=True` the `EventEnricher` runs inside `CompositeAgentHandler.send_event` / `.send_metric` before fan-out, populating the following keys on every event's `metadata` dict (and every metric's `tags` dict, for identity fields):

| Key | Type | Source | Applied to |
|---|---|---|---|
| `guard.project_id` | `str` | `SecurityConfig.agent_project_id` | events + metrics |
| `guard.service.name` | `str` | `SecurityConfig.otel_service_name` | events + metrics |
| `guard.deployment.environment` | `str` | `SecurityConfig.otel_resource_attributes["deployment.environment"]` | events + metrics |
| `guard.threat_score` | `int` (0-100) | `ThreatScorer.score_for(event_type)`, a deterministic `event_type` → score map in `guard_core.core.events.enricher` (penetration_attempt=90, ip_banned=70, medium events=50, rate_limited=20, default=20). guard-core-app stores the agent-supplied value as-is. | events only |
| `guard.rule.id` | `str` | `DynamicRuleManager.match_event(event)` when the cached rule's IP / country / event-type matched | events only |
| `guard.rule.version` | `int` | Same source as `guard.rule.id` | events only |
| `guard.behavior.correlation_key` | `str` (16-char hex) | SHA-256 prefix of `ip \| service \| floor(now/300)`, stable within a 5-minute window so multiple events from the same IP share a key | events only |
| `guard.behavior.recent_event_count` | `int` | `BehaviorTracker.count_recent_rule_hits(ip, 300)`: each `usage` or `frequency` behavior rule's hits from the IP that are still inside that rule's own window, summed across all endpoints (route and global rules), counting only hits in the last 300 seconds; one request on a route with two such rules adds 2. With Redis the same sum is read from the IP's rule keys, which every worker shares, and matches the in-memory value except where memory evicts at its caps (10,000 endpoint buckets and 10,000 clients per bucket, least recently used first) or an IP's Redis index reaches 10,000 rule keys. A custom tracker that only has the sync `get_recent_event_count(ip, window_seconds)` is still read through that method. | events only |

All fields are nullable and absent unless the corresponding context is available. When `enable_enrichment=False` the enricher is never constructed and none of these keys appear. OTel spans receive these as span attributes; Logfire spans receive them as log attributes via `**enrichment` unpacking.

Enrichment is **always client-side**. guard-core-app's SaaS backend stores them as structured fields for indexed queries, but no server-side component computes them, the full behaviour is deterministic from `SecurityConfig` + current dynamic rule + the behaviour tracker's rule-hit counters (Redis when enabled, in-memory otherwise).

## Muting events, metrics, and check logs

```python
from guard_core.models import SecurityConfig

config = SecurityConfig(
    muted_event_types={"penetration_attempt"},
    muted_metric_types={"response_time"},
    muted_check_logs={"rate_limit", "user_agent"},
)
```

- `muted_event_types` short-circuits `SecurityEventBus.send_middleware_event()` before the event reaches any exporter.
- `muted_metric_types` short-circuits `MetricsCollector.send_metric()` before the metric reaches any exporter.
- `muted_check_logs` suppresses the in-check `log_activity()` calls, each check passes the set into `log_if_allowed`. `SecurityCheckPipeline` *also* accepts a `muted_check_logs` set that gates its own block/error log entries, and `build_default_pipeline()` passes `config.muted_check_logs` into the pipeline, so pipeline-level entries are muted too for adapters that use the factory, an adapter that hand-builds `SecurityCheckPipeline(checks)` directly, without the factory, must pass `muted_check_logs` itself or those pipeline-level entries are not muted.

## Enabling OpenTelemetry

=== "uv"

    ```bash
    uv add "guard-core[otel]"
    ```

=== "poetry"

    ```bash
    poetry add "guard-core[otel]"
    ```

=== "pip"

    ```bash
    pip install "guard-core[otel]"
    ```

```python
config = SecurityConfig(
    enable_otel=True,
    otel_service_name="guard-prod",
    otel_exporter_endpoint="http://otel-collector.internal:4318",
    otel_resource_attributes={
        "deployment.environment": "prod",
        "service.version": "1.2.0",
    },
)
```

If `otel_resource_attributes` contains a `service.name` key it overrides `otel_service_name` (last-write-wins: the extra attributes dict is applied after the service-name key is set). Prefer setting service name via `otel_service_name` and use `otel_resource_attributes` only for environment/version/region tags.

Incoming W3C `traceparent` headers are continued automatically, guard spans become children of the caller's trace. `tracestate` headers are forwarded alongside when present.

`send_metric` emits three instruments when enabled:

- `guard.request.duration` (histogram, seconds)
- `guard.request.count` (counter)
- `guard.error.count` (counter)

Any other metric type produces a one-line warning and is dropped.

## Enabling Logfire

=== "uv"

    ```bash
    uv add "guard-core[logfire]"
    ```

=== "poetry"

    ```bash
    poetry add "guard-core[logfire]"
    ```

=== "pip"

    ```bash
    pip install "guard-core[logfire]"
    ```

```python
config = SecurityConfig(
    enable_logfire=True,
    logfire_service_name="guard-prod",
)
```

Events are emitted as `logfire.span("guard.event.<event_type>", ...)` and metrics as structured logs via `logfire.info("guard.metric.<metric_type>", value=..., endpoint=..., **tags)`. When both `enable_otel` and `enable_logfire` are set, Logfire also observes the OpenTelemetry instruments automatically via its OTel bridge.

Both OTel spans and Logfire spans receive enrichment fields (see **Enrichment fields** above) as attributes when `enable_enrichment=True`.

## Enabling enrichment

```python
config = SecurityConfig(
    enable_agent=True,
    agent_api_key="your-api-key",
    agent_project_id="proj-prod",
    enable_enrichment=True,
    enable_otel=True,  # optional, routes enrichment to OTel spans
    enable_logfire=True,  # optional, routes enrichment to Logfire spans
    otel_service_name="api",
    otel_resource_attributes={"deployment.environment": "prod"},
)
```

Setting `enable_enrichment=True` without `enable_agent=True` raises `ValidationError`, enrichment is the guard-agent-gated tier. Rationale: enrichment is what distinguishes the paid (guard-agent + SaaS dashboard) experience from the free (raw OTel/Logfire) experience; the free tier is a first-class standards-compliant telemetry path, and enrichment is the value-add on top that correlates events by rule/behaviour/identity.

Enrichment runs inside the `CompositeAgentHandler` before fan-out, so every handler, guard-agent, OTel, Logfire, receives the same enriched payload. `guard-agent` passes the fields through unchanged (via `SecurityEvent.metadata` which accepts arbitrary keys via `ConfigDict(extra="allow")`); `guard-core-app`'s ingestion promotes them into indexed columns for dashboard queries.

### Dynamic-rule correlation

`guard.rule.id` + `guard.rule.version` are populated when `enable_dynamic_rules=True` AND the currently-cached `DynamicRules` payload matches the event. Matching rules:

- event's `ip_address` appears in `rules.ip_blacklist` or `rules.ip_whitelist`
- event's `country` appears in `rules.blocked_countries`
- event's `event_type == "rate_limited"` and any rate limit is configured (global or per-endpoint)
- event's `event_type == "cloud_blocked"` and any provider is in `rules.blocked_cloud_providers`
- event's `event_type == "user_agent_blocked"` and any UA is in `rules.blocked_user_agents`

When none matches, the two keys stay absent.

### Behavioural correlation

`guard.behavior.correlation_key` is a stable 16-character hex identifier that groups multiple events from the same IP within a 5-minute rolling window. Dashboards that want to surface "attack chains" can group events by this key. The formula is:

```python
sha256(f"{ip}|{service}|{floor(now / 300)}".encode()).hexdigest()[:16]
```


`guard.behavior.recent_event_count` is the count of timestamps recorded by `BehaviorTracker` for the same IP across all endpoints in the last 5 minutes. Purely in-memory, a high count is signal that this IP is active, not a definitive threat, but useful for prioritising review.

## Adapter wiring

Framework adapters (fastapi-guard, flaskapi-guard, djapi-guard, tornadoapi-guard) build the event bus and metrics collector through the factory methods on `HandlerInitializer` so the composite handler and event filter are wired automatically:

```python
from guard_core.core.initialization.handler_initializer import HandlerInitializer

initializer = HandlerInitializer(
    config=config,
    redis_handler=redis_handler,
    agent_handler=agent_handler,
    geo_ip_handler=geo_handler,
    rate_limit_handler=rate_limit_handler,
    guard_decorator=decorator_handler,
)

await initializer.initialize_redis_handlers()
await initializer.initialize_agent_integrations()  # starts composite_handler

event_bus = initializer.build_event_bus(geo_ip_handler=geo_handler)
metrics_collector = initializer.build_metrics_collector()

# ... run the app ...

await initializer.shutdown_agent_integrations()  # stops composite_handler
```

`build_event_bus()` and `build_metrics_collector()` raise `RuntimeError` if called before `initialize_agent_integrations()`, the composite handler and event filter must exist first.

## Incoming `traceparent`

When `enable_otel=True` and the request carries a W3C `traceparent` header, `SecurityEventBus` copies it into the event's metadata. `OtelHandler.send_event()` extracts it with `TraceContextTextMapPropagator` and sets the resumed context as the parent of `guard.event.<event_type>` spans. This preserves the upstream trace across the guard layer.

## Troubleshooting

### Spans don't show up in your OTel backend

1. Verify `enable_otel=True` is set.
2. Check `python -c "import opentelemetry.sdk"`, if it raises `ImportError`, the handler logs `opentelemetry-sdk not installed, OTEL handler disabled` on startup.
3. Confirm `otel_exporter_endpoint` points to an OTLP/HTTP receiver on port `4318` (not `4317`, that's gRPC).
4. Confirm the adapter calls `initializer.build_event_bus()` and the middleware uses that bus (not a locally-constructed `SecurityEventBus`).

### Events aren't muted even though you set `muted_event_types`

The adapter may be constructing `SecurityEventBus(...)` directly and passing no `event_filter`. Switch it to `initializer.build_event_bus()`.

### `logfire.info()` warning: "No logs or spans will be created until `logfire.configure()` has been called"

Guard Core configures Logfire inside `LogfireHandler.start()`. This runs during `initialize_agent_integrations()`. If the warning appears after startup, the integration may not have been initialised, verify `enable_logfire=True` is set before `initialize_agent_integrations()` runs.

### Unknown check/event/metric in mute set raises `ValidationError`

The error message lists the valid values. Common typos: `"suspicious"` instead of `"suspicious_activity"`, `"latency"` instead of `"response_time"`.
