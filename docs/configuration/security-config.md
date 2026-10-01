---

title: SecurityConfig Reference
description: Complete reference for every SecurityConfig field in guard-core, grouped by category with types, defaults, and descriptions
keywords: security config, configuration, pydantic, guard-core
---

SecurityConfig Reference
========================

`SecurityConfig` is a Pydantic `BaseModel` that controls all guard-core behavior. Adapter developers should expose relevant fields to their users while keeping internal fields (agent, dynamic rules) as implementation details.

Core Settings
-------------

| Field                     | Type                        | Default  | Description                                            |
|---------------------------|-----------------------------|----------|--------------------------------------------------------|
| `passive_mode`            | `bool`                      | `False`  | Log-only mode. Logs and emits events but never blocks. |
| `fail_secure`             | `bool`                      | `True`   | Block the request with `500` when any security check raises an unexpected exception. `False` logs and falls through (fail-open); opt-in only for staging diagnostics. |
| `exclude_paths`           | `list[str]`                 | See below| Paths that skip detection and behavioral analysis; ban enforcement and rate limiting still apply. See [Ban Configuration](../api/ban-config.md#exclude_paths-enforces-bans-and-rate-limits-not-evidence-gathering). |
| `custom_error_responses`  | `dict[int, str]`            | `{}`     | Override error messages for specific HTTP status codes. |
| `enforce_https`           | `bool`                      | `False`  | Redirect HTTP requests to HTTPS globally.              |
| `custom_request_check`    | `Callable \| None`          | `None`   | Global async function for custom request validation.   |
| `auth_verifier`           | `Any`                       | `None`   | Global default verifier for `require_auth`/`api_key_auth` routes with no per-route `verifier=`: `verifier(request, credential) -> Principal \| None`. Sync or async in async deployments; sync-only under WSGI. |
| `custom_response_modifier`| `Callable \| None`          | `None`   | Global async function to modify responses.             |
| `route_resolution_strict` | `bool`                      | `False`  | Block with `500` when the adapter reports it could not resolve the route, instead of running the pipeline with no per-route config. Also turns requests to paths the app does not serve into `500`s rather than `404`s. See [Reporting a Failed Match](../adapters/decorators.md#reporting-a-failed-match). |
| `on_error`                | `Callable[[str, BaseException, dict], None] \| None` | `None` | Best-effort callback invoked when a middleware/agent step fails, receiving `(stage, exception, context)`. `stage` is one of `agent_init`, `geoip`, `transport_send`, `encryption`. Also forwarded to `AgentConfig.on_error` when the agent is enabled; see [Agent / Telemetry](#agent--telemetry). |
| `on_block`                | `Callable[[GuardRequest, dict[str, Any]], None] \| None` | `None` | Fired exactly once per block decision with `(request, payload)`; in passive mode fires at flag time with `status_code=None`. Payload keys: `check_name`, `reason`, `trigger_info`, `passive_mode`, `client_ip`, `path`, `method`, `status_code`. Not fired for `custom_request`/`custom_validators` (application-authored), the HTTPS redirect, or a Redis-unavailable response (use `on_error`). Sync or async under ASGI; sync-only under WSGI (async raises `TypeError`). A raising hook is logged, never propagated. |

**Default `exclude_paths`**: `["/docs", "/redoc", "/openapi.json", "/openapi.yaml", "/favicon.ico", "/static"]`

!!! tip "Adapter Exposure"
    All core settings should be exposed to end users. `passive_mode` is particularly useful for deployment rollouts.

___

Proxy Configuration
-------------------

| Field                     | Type         | Default  | Description                                            |
|---------------------------|-------------|----------|--------------------------------------------------------|
| `trusted_proxies`         | `tuple[str, ...]` | `()`     | Trusted proxy IPs or CIDR ranges for X-Forwarded-For.  |
| `trusted_proxy_depth`     | `int`       | `1`      | Number of proxies in the X-Forwarded-For chain.        |
| `trust_x_forwarded_proto` | `bool`      | `False`  | Trust X-Forwarded-Proto header for HTTPS detection.    |

**Validators**:

- `trusted_proxies`: Each entry is validated as a valid IP address or CIDR range, or the literal string `"unix"`, which marks a peer-less connection (no `request.client_host`, e.g. a Unix domain socket) as a trusted hop so `X-Forwarded-For` still resolves the real client. `whitelist` and `blacklist` do not accept `"unix"`.
- `trusted_proxies`: if any entry is a `/0` network (`0.0.0.0/0` or `::/0`), construction logs a `WARNING` naming the risk (every peer becomes trusted to set `X-Forwarded-For`); the literal `"unix"` token is exempt from this check.
- `trusted_proxy_depth`: Must be >= 1.

`trusted_proxy_depth` is the number of hops you vouch for, not a maximum: the connecting peer must itself be listed in `trusted_proxies`. A chain shorter than the configured depth, or a depth-selected entry that is itself a trusted proxy, now logs a one-time `WARNING`. A declared depth that over-counts the real hops -- an entry to the right of the depth-selected one is not itself a listed trusted proxy -- also logs a one-time `WARNING` and, unlike the first two, corrects the resolved identity: it walks the chain right to left and returns the first entry that is not a listed trusted proxy, instead of the plain (and, in that case, client-rotatable) depth-indexed entry. See [Unsatisfiable and Over-Counted Depth](../internals/ip-management.md#unsatisfiable-and-over-counted-depth).

!!! warning "Your app server must not pre-resolve the client itself"
    Leaving `trusted_proxies` unset only means "`X-Forwarded-For` is never trusted" if your ASGI/WSGI server isn't already applying that header before guard-core runs. uvicorn's default `proxy_headers=True` (and equivalent settings in Gunicorn/Hypercorn) does exactly that. See [Deployment Prerequisite](../internals/ip-management.md#deployment-prerequisite-disable-the-app-servers-own-forwarded-header-handling) for the fix.

___

IP Management
-------------

| Field                | Type              | Default           | Description                                    |
|----------------------|-------------------|-------------------|------------------------------------------------|
| `whitelist`          | `tuple[str, ...] \| None` | `None`          | Allowed IPs/CIDRs. `None` disables (allow all).|
| `blacklist`          | `tuple[str, ...]`       | `()`              | Blocked IPs/CIDRs.                             |
| `exempt_ips`         | `tuple[str, ...]`       | `()`              | IPs/CIDRs that skip rate limiting, the user-agent check and per-route `@block_clouds`, as a whitelist match does. Not restrictive: other IPs are checked as usual. The blacklist, dynamic bans, route IP rules, penetration detection and the global `block_cloud_providers` (enforced by the IP check, as for a whitelist match) still apply. |
| `whitelist_countries`| `frozenset[str]`       | `frozenset()`              | Allowed countries. Non-empty = only listed pass (unknown blocked). Overrides `blocked_countries`. |
| `blocked_countries`  | `frozenset[str]`       | `frozenset()`              | Country codes always blocked.                  |
| `blocked_user_agents`| `list[str]`       | `[]`              | Regex patterns for blocked user agents.        |
| `enable_ip_banning`  | `bool`            | `True`            | Enable automatic IP banning.                   |
| `auto_ban_threshold` | `int`             | `10`              | Suspicious requests before auto-ban (`>= 1`).  |
| `auto_ban_duration`  | `int`             | `3600`            | Ban duration in seconds (`>= 1`).              |

**Validators**:

- `whitelist` and `blacklist`: Each entry validated as a valid IP or CIDR range via `ipaddress.ip_address()` / `ip_network()`.
- `whitelist`: if any entry is a `/0` network (`0.0.0.0/0` or `::/0`), construction logs a `WARNING` naming the risk (every address becomes whitelisted, so `blacklist`, `blocked_countries` and IP bans cannot block anyone). Precedence is unchanged: a `/0` whitelist still allows every address, this is a signal only.

!!! warning "Whitelist Semantics"
    `whitelist=None` means "no whitelist" (all IPs pass). `whitelist=[]` means "empty whitelist" (no IPs pass). Adapter developers should document this distinction.

___

Per-Category Bans
-----------------

`threat_ban_config` lets each detection category carry its own threshold and duration. The pipeline tracks per-category counts in `suspicious_request_counts`, then walks the matched categories of the current detection. The first category whose own count reaches its `threshold` triggers a category-tagged ban; if no per-category entry matches, the flat `auto_ban_threshold` / `auto_ban_duration` fallback fires off the *total* count instead.

| Field                | Type                              | Default | Description                                          |
|----------------------|-----------------------------------|---------|------------------------------------------------------|
| `threat_ban_config`  | `MappingProxyType[str, ThreatBanConfig]`      | `mappingproxy({})`    | Per-category ban policy. Validator rejects unknown keys. |

When to use:

- You want SQL injection detections to be a single-strike ban for a week, but XSS detections to be a 3-strike ban for an hour.
- You want to keep the existing flat threshold for any category you do not name.
- You want the audit log reasons to disambiguate which category triggered the ban (`"penetration_attempt:sqli"` vs the flat `"penetration_attempt"`).

```python
from guard_core.models import SecurityConfig, ThreatBanConfig

config = SecurityConfig(
    auto_ban_threshold=10,
    auto_ban_duration=3600,
    threat_ban_config={
        "sqli": ThreatBanConfig(threshold=1, duration=604800),
        "xss": ThreatBanConfig(threshold=3, duration=86400),
    },
)
```

See [Ban Configuration](../api/ban-config.md) for the `ThreatBanConfig` model and the full fall-through rule.

___

Global Behavior Rules
---------------------

`global_behavior_rules` applies behavior rules to every route without requiring decorators. The merged rules are run alongside any decorator-specified rules. The most common use is service-wide 404-noise correlation, but the same shape supports `usage`, `frequency`, and `return_pattern` rules.

| Field                                        | Type                          | Default    | Description                                  |
|-----------------------------------------------|-------------------------------|------------|----------------------------------------------|
| `global_behavior_rules`                        | `tuple[BehaviorRuleConfig, ...]` | `()`    | Behavior rules merged into every route. Immutable: reassign the whole field to change it, `.append()` raises `AttributeError`. |
| `behavior_scan_response_body`                  | `bool`                        | `False`    | Read response bodies to evaluate `return_pattern` rules whose pattern is not `status:` (`json:`, `regex:`, or a bare substring). Off by default: no response body is ever read for pattern matching, and constructing a `return_pattern` rule with a non-`status:` pattern while this is `False` raises `ValueError` instead of silently accepting a rule that can never match. `status:` patterns match on `status_code` alone and are unaffected. |
| `behavior_max_response_body_inspect_bytes`     | `int`                         | `262144`   | Maximum bytes read from the start of a response body and held for `return_pattern` inspection when `behavior_scan_response_body` is `True`. Bounds what guard-core retains, not what the application produces; a streaming response stays streaming to the client. See [Protocols - BoundedResponseBodyReader](../api/protocols.md#boundedresponsebodyreader). |
| `body_read_timeout`                            | `float`                       | `3.0`      | Seconds to wait for an adapter's `read_body_prefix`/`body` call before giving up. Bounds the request-body detection read and the response-body behaviour-rule read against a stalled or misbehaving adapter/stream; on timeout the body is treated as unavailable, the same fail-closed outcome already used when the adapter raises. The async `guard_core` tree bounds the wait via `asyncio.wait_for`. The sync tree (`guard_core.sync`) cannot cancel a blocking call from the outside, so each read attempt runs on its own daemon thread and this value bounds how long the caller joins that thread instead; see `sync_body_read_max_concurrent` for the concurrent-thread budget. |
| `sync_body_read_max_concurrent`                | `int`                         | `64`       | Maximum daemon threads the sync (`guard_core.sync`) tree may have blocked at once inside an adapter's `read_body_prefix`/`body` call. Once that many threads are already blocked on a stalled read, further attempts queue for the same `body_read_timeout` budget and then give up, logging the exhaustion, instead of spawning without limit. |

When to use:

- You want a global "ban after 20 404s in 5 minutes" rule that does not require touching every route.
- You want detection-correlated thresholds, `correlate_with_detection=True` halves the threshold (floor 1) when the IP has any positive `suspicious_request_counts` entry, so probing that already triggered a regex hit gets banned faster.
- You want a service-wide frequency or usage cap for any caller, regardless of which route they hit.

```python
from guard_core.models import BehaviorRuleConfig, SecurityConfig

config = SecurityConfig(
    global_behavior_rules=[
        BehaviorRuleConfig(
            rule_type="return_pattern",
            threshold=20,
            window=300,
            pattern="status:404",
            action="ban",
            ban_duration=3600,
            correlate_with_detection=True,
        ),
    ],
)
```

A `json:`, `regex:`, or bare-substring pattern additionally requires `behavior_scan_response_body=True` and an adapter that implements `BoundedResponseBodyReader`; without both, construction rejects the rule outright rather than accepting one that can never match:

```python
config = SecurityConfig(
    behavior_scan_response_body=True,
    behavior_max_response_body_inspect_bytes=65536,
    global_behavior_rules=[
        BehaviorRuleConfig(
            rule_type="return_pattern",
            threshold=5,
            window=300,
            pattern="json:error.code==AUTH_FAIL",
            action="ban",
        ),
    ],
)
```

See [Behavior Rules](../api/behavior-rules.md) for the full field reference.

___

Detection Exclusions
--------------------

These fields opt request components out of penetration detection. The header set is merged with a hardcoded default that already excludes `host`, `user-agent`, `accept`, `accept-encoding`, `connection`, `origin`, `referer`, all `sec-fetch-*`, all `sec-ch-ua*`, and the proxy identity headers `forwarded`, `x-forwarded-for`, `x-forwarded-host`, `x-forwarded-proto`, `x-real-ip`, `x-client-ip`, `x-cluster-client-ip`, `cf-connecting-ip`, `true-client-ip`, `fly-client-ip`, and `x-envoy-external-address` (their values are addresses or hostnames set by infrastructure, not the client, so a private address like `192.168.65.1` never trips the SSRF pattern). An excluded header still gets the always-on command-injection check, so `X-Real-IP: $(id)` is still detected; client IP attribution is unaffected, since it never used pattern detection. `enabled_detection_categories` narrows the regex scan to a subset of the 18 known categories; custom user patterns always run regardless. An empty `enabled_detection_categories` while `enable_penetration_detection` is `True` logs a `WARNING` at construction: detection would run on every request but never match anything.

| Field                              | Type        | Default                          | Description                                                                |
|------------------------------------|-------------|----------------------------------|----------------------------------------------------------------------------|
| `excluded_detection_headers`       | `set[str]`  | `set()`                          | Headers exempted only from the categories known to false-positive on their typical values: identity and proxy headers such as `X-Forwarded-For`, `X-Real-IP`, `Host`, `Origin` and `Via` skip `ssrf` only, and every other category (sqli, xss, cmd_injection, template, Log4Shell) still scans them. A name outside the built-in identity set inherits the same rule when its value looks like an address chain, otherwise it gets no exclusion at all. Merged with the hardcoded default list. |
| `excluded_detection_params`        | `set[str]`  | `set()`                          | Query parameter names skipped by detection.                                |
| `excluded_detection_body_fields`   | `set[str]`  | `set()`                          | Top-level JSON body keys skipped by detection.                             |
| `enabled_detection_categories`     | `frozenset[str]`  | full `ALL_DETECTION_CATEGORIES`  | Categories scanned for. Validator rejects unknown labels.                  |

When to use:

- A first-party endpoint accepts JSON containing literals (Markdown source, code blobs, URL-shaped query params) that look like attacks but are not.
- A regression in one category's regex is producing false positives faster than you can write a fix, disable the category temporarily.
- A privacy-sensitive header value should not be scanned at all.
- You want different routes to have different opt-outs, pair this with `@security.detection_exclusion(...)` on the route.

```python
from guard_core.models import SecurityConfig

config = SecurityConfig(
    excluded_detection_params={"q", "search", "filter"},
    excluded_detection_body_fields={"description", "markdown"},
    enabled_detection_categories={"sqli", "xss", "cmd_injection", "ssrf"},
)
```

___

IP Lifecycle Controls
---------------------

These fields tune cold-start and horizontal-scale behaviour for the geo-IP and cloud-IP subsystems. They are inert by default, only adjust if you have a specific cold-start or scale-out problem.

| Field                | Type                            | Default | Description                                                                  |
|----------------------|---------------------------------|---------|------------------------------------------------------------------------------|
| `lazy_init`          | `bool`                          | `True`  | When `True` (default), run the IPInfo MMDB download and cloud-IP provider fetches as a background task during startup instead of awaiting them inline, so app boot never blocks on multi-second network calls. Cloud and geo layers are inert until the task completes. Set to `False` to await them inline for synchronous-init guarantees. |
| `geo_ip_db_max_age`  | `int`                           | `86400` | Maximum age in seconds for the IPInfo MMDB before re-download. Range 3600 - 604800. |
| `cloud_ip_store`     | `CloudIpStoreProtocol \| None`  | `None`  | Pluggable cloud-IP backend. `None` uses the in-memory default; auto-upgraded to Redis when Redis is enabled. |

When to use:

- `lazy_init=True` to keep startup non-blocking when IPInfo MMDB or cloud-IP provider fetches are slow. The background warmup runs concurrently with normal request handling; cloud-provider blocking and geo checks become active once the background task finishes. Rate limiting, IP banning, pattern detection, and other layers remain fully active throughout the warmup window. `lazy_init` only takes effect when Redis is enabled and the adapter calls `initialize_redis_handlers()` from its own startup hook (for example fastapi-guard's lifespan integration), see [Provider Status](#provider-status) below for the accessor that lets a Kubernetes/ALB warmup probe (or any health endpoint) tell when that window has closed.
- `geo_ip_db_max_age` to tighten or loosen the IPInfo refresh cadence, match it to your IPInfo plan's update frequency.
- `cloud_ip_store` to point multiple horizontally-scaled instances at a single pre-populated Redis namespace, skipping per-instance cloud-IP cold starts.

```python
from guard_core.handlers.cloud_ip_stores import RedisCloudIpStore
from guard_core.handlers.redis_handler import RedisManager
from guard_core.models import SecurityConfig

config = SecurityConfig(
    lazy_init=True,
    geo_ip_db_max_age=43200,
)

shared_store = RedisCloudIpStore(RedisManager(config))
config_with_shared_store = SecurityConfig(cloud_ip_store=shared_store)
```

### Provider Status

`cloud_handler.get_status()` (the module-level singleton) and your `IPInfoManager` instance's `get_status()` report per-provider readiness, the last successful refresh timestamp, and a cheap entry count. `HandlerInitializer` is adapter-internal, its `get_initialization_status()` combines both into one payload, and adapters expose that combined payload as their status surface (fastapi-guard: `SecurityMiddleware.get_initialization_status()`, or `add_status_route(app)` → `GET /_guard/status`).

Cloud-only status, callable anywhere:

```python
from guard_core.handlers.cloud_handler import cloud_handler

cloud_status = cloud_handler.get_status()
# {
#     "AWS": {"ready": True, "last_refreshed": datetime(...), "entries": 3421},
#     "GCP": {"ready": False, "last_refreshed": None, "entries": 0},
#     ...
# }
```

Geo-IP status, call `get_status()` on the `IPInfoManager` instance you passed in as `geo_ip_handler` (there is no module singleton: the manager is token-gated, so it is instantiated per app, not at import time):

```python
geo_status = ip_info_manager.get_status()
# {"ready": True, "last_refreshed": datetime(...), "entries": 494}
```

Combined cloud + geo-IP payload, for a warmup probe or health endpoint, read it through your adapter rather than reconstructing `HandlerInitializer` yourself (fastapi-guard):

```python
from guard.status import add_status_route

add_status_route(app, path="/_guard/status")  # GET /_guard/status -> combined payload
# or, in-process: security_middleware.get_initialization_status()
# {
#     "cloud_providers": { ...as above... },
#     "geo_ip": { ...as above... },
# }
```

`geo_ip` is `None` when no `geo_ip_handler` is configured. A custom `geo_ip_handler` that does not implement `get_status()` still reports `ready` (from the required `is_initialized` property) with `last_refreshed`/`entries` as placeholders. This is synchronous, dependency-free, and cheap enough to poll from a warmup probe or health endpoint, it is exactly what to wire up for the "cannot tolerate any inert window" case above.

See [Cloud IP Store](../api/cloud-ip-store.md) for the protocol contract and the Redis namespace migration note.

___

Geolocation
-----------

| Field              | Type              | Default | Description                                         |
|--------------------|-------------------|---------|-----------------------------------------------------|
| `geo_ip_handler`   | `GeoIPHandler \| None` | `None`  | Custom geolocation handler implementing the protocol.|
| `ipinfo_token`     | `str \| None`     | `None`  | IPInfo API token for IP geolocation.                |
| `ipinfo_db_path`   | `Path \| None`    | `data/ipinfo/country_asn.mmdb` | Path to the local IPInfo MMDB database file. |

**Model validator**: If `blocked_countries` or `whitelist_countries` are set, `geo_ip_handler` must be provided (or `ipinfo_token`, from which one is constructed automatically). Raises `ValueError` otherwise.

___

Rate Limiting
-------------

| Field                 | Type             | Default | Description                                        |
|-----------------------|------------------|---------|---------------------------------------------------|
| `enable_rate_limiting`| `bool`           | `True`  | Master switch for rate limiting.                   |
| `rate_limit`          | `int`            | `10`    | Maximum requests per window (global).              |
| `rate_limit_window`   | `int`            | `60`    | Window duration in seconds (global).               |
| `endpoint_rate_limits`| `dict[str, tuple[int, int]]` | `{}` | Per-endpoint overrides `{path: (limit, window)}`. |
| `enable_rate_limit_auto_ban` | `bool`     | `False` | Feed rate-limit violations into the same auto-ban engine penetration detection uses. Requires `enable_ip_banning` to actually ban; off by default, so this is zero behavior change unless enabled. |

`enable_rate_limit_auto_ban` reuses the [Per-Category Bans](#per-category-bans) machinery: each active-mode (non-passive) rate-limit violation increments the `rate_limit` category of `suspicious_request_counts` and runs the same threshold logic, `threat_ban_config["rate_limit"]` first if present, otherwise the flat `auto_ban_threshold` / `auto_ban_duration` policy, banning with `reason="rate_limit_exceeded"` (distinct from the `"penetration_attempt"` reason the detection path uses). See [Rate-limit auto-ban](../api/ban-config.md#rate-limit-auto-ban) for the full behavior. Like the rest of the auto-ban state, `suspicious_request_counts` is in-memory and per-process, so multi-replica deployments do not share rate-limit auto-ban counts across replicas.

___

Cloud Provider Blocking
-----------------------

| Field                      | Type             | Default | Description                              |
|----------------------------|------------------|---------|------------------------------------------|
| `block_cloud_providers`    | `frozenset[str] \| None` | `None`  | Providers to block: `"AWS"`, `"GCP"`, `"Azure"`, `"DigitalOcean"`, `"Linode"`, `"Vultr"`. A bare name blocks the whole provider; a region carve-out (`"GCP:!us-central1"`) blocks the provider except that region. Region metadata exists for AWS and GCP only, so a carve-out on the other four exempts nothing and the whole provider stays blocked. An unrecognized provider name raises `ValueError`. |
| `cloud_ip_refresh_interval`| `int`            | `3600`  | Seconds between IP range refreshes (60-86400). |

**Validator**: each entry is valid when the part before an optional `:!region` suffix is one of the six provider names; any invalid entry raises `ValueError` naming it (nothing is silently dropped).

___

Security Headers
----------------

| Field              | Type                   | Default      | Description                          |
|--------------------|------------------------|--------------|--------------------------------------|
| `security_headers` | `dict[str, Any] \| None` | See below  | Security headers configuration dict. |

**Default structure**:

```python
{
    "enabled": True,
    "hsts": {"max_age": 31536000, "include_subdomains": True, "preload": False},
    "csp": None,
    "frame_options": "SAMEORIGIN",
    "content_type_options": "nosniff",
    "xss_protection": "1; mode=block",
    "referrer_policy": "strict-origin-when-cross-origin",
    "permissions_policy": "geolocation=(), microphone=(), camera=()",
    "custom": None,
}
```

___

CORS
----

| Field                    | Type         | Default               | Description                            |
|--------------------------|-------------|----------------------|----------------------------------------|
| `enable_cors`            | `bool`      | `False`              | Enable CORS header injection.          |
| `cors_allow_origins`     | `list[str]` | `["*"]`              | Allowed origins.                       |
| `cors_allow_methods`     | `list[str]` | `["GET", "POST", ...]`| Allowed HTTP methods.                 |
| `cors_allow_headers`     | `list[str]` | `["*"]`              | Allowed request headers.               |
| `cors_allow_credentials` | `bool`      | `False`              | Allow credentials in CORS requests.    |
| `cors_expose_headers`    | `list[str]` | `[]`                 | Headers exposed in CORS responses.     |
| `cors_max_age`           | `int`       | `600`                | Preflight cache duration in seconds.   |

___

Redis
-----

| Field                            | Type          | Default                   | Description                                             |
|----------------------------------|---------------|---------------------------|----------------------------------------------------------|
| `enable_redis`                   | `bool`        | `True`                    | Master switch for Redis.                                |
| `redis_url`                      | `str \| None` | `"redis://localhost:6379"`| Redis connection URL.                                   |
| `redis_prefix`                   | `str`         | `"guard_core:"`           | Key prefix for namespace isolation.                      |
| `redis_socket_connect_timeout`   | `float \| None`| `2.0`                    | Seconds to wait establishing a TCP connection. Must be positive; `None` disables (blocks indefinitely on a partitioned Redis). |
| `redis_socket_timeout`           | `float \| None`| `2.0`                    | Seconds to wait on a read/write before raising. Must be positive; `None` means no timeout. |
| `redis_health_check_interval`    | `int`         | `30`                      | Seconds between pooled-connection health checks. `0` disables. |
| `redis_max_connections`          | `int \| None` | `None`                    | Cap on the connection pool size. `None` uses redis-py's default. |
| `redis_retries`                  | `int`         | `1`                       | Retries (with exponential backoff) on transient connection/timeout errors. `0` disables. |
| `redis_fail_open`                | `bool`        | `False`                   | On Redis outage, `fail_secure` governs by default. Set `True` to skip the failing check and let the request through, treating Redis outages as an availability concern distinct from other check failures. Covers Redis unavailability at startup, a `GuardRedisError` raised from any security check mid-request, and the rate limiter's Redis path: `True` falls back to an in-memory window with a one-time process warning (with several workers the effective limit becomes workers times `rate_limit`), `False` raises so `fail_secure` decides the outcome. |

___

Detection Engine
----------------

| Field                               | Type    | Default | Range         | Description                                  |
|-------------------------------------|---------|---------|---------------|----------------------------------------------|
| `enable_penetration_detection`      | `bool`  | `True`  | N/A           | Master switch for threat detection.          |
| `detection_compiler_timeout`        | `float` | `2.0`   | 0.1 - 10.0   | Timeout for pattern compilation/matching (s).|
| `detection_pattern_validation_cache_path` | `str \| None` | `None` | N/A | Opt-in disk cache for the empirical cost-verdict validation outcome, keyed by pattern, flags, and engine version; deterministic layers always re-run. |
| `detection_max_content_length`      | `int`   | `10000` | 1000 - 100000 | Maximum content length for detection.        |
| `detection_preserve_attack_patterns`| `bool`  | `True`  | N/A           | Preserve attack patterns during truncation.  |
| `detection_semantic_threshold`      | `float` | `0.7`   | 0.0 - 1.0    | Threshold for semantic attack detection.     |
| `detection_anomaly_threshold`       | `float` | `3.0`   | 1.0 - 10.0   | Std deviations slower than average to flag an anomaly (never faster). |
| `detection_anomaly_emission_cooldown` | `float` | `60.0` | 1.0 - 3600.0 | Minimum seconds between anomaly events for the same pattern. Raise to reduce noise on low-traffic apps. |
| `detection_min_samples_for_anomaly` | `int`   | `30`    | 10 - 1000     | Minimum samples recorded for a pattern before statistical-anomaly detection engages. Raise to reduce false fires on low-traffic apps. |
| `detection_slow_pattern_threshold`  | `float` | `0.1`   | 0.01 - 1.0   | Seconds to consider a pattern slow.          |
| `detection_monitor_history_size`    | `int`   | `1000`  | 100 - 10000   | Recent metrics to keep in history.           |
| `detection_max_tracked_patterns`    | `int`   | `1000`  | 100 - 5000    | Maximum patterns to track for performance.   |
| `detection_max_body_inspect_bytes`  | `int`   | `262144`| 1024 - 10485760 | Body size cap read/scanned for detection; distinct from `detection_max_content_length` and `max_request_size`. A body whose declared `Content-Length` exceeds this cap is read through the adapter's bounded reader (`read_body_prefix`) and only the first this-many bytes are scanned, if the adapter implements one; without a bounded reader the body is not read at all, the same skip as before this cap existed. Either way a one-time warning names the cap, the client, and which of the two happened. A signature that straddles the cap boundary is still caught: a small overlap (the longest compiled pattern length, up to 256 bytes) is read past the cap on every path, including a declared oversized `Content-Length`. |
| `detection_max_scan_values`         | `int`   | `512`   | 2 - 100000    | Maximum values (query params, headers, JSON keys/values, form/multipart fields) scanned per request; remaining values are skipped and a one-time warning logs the client IP once reached. Each named value costs two scan units (name, then value), so the minimum is 2. |
| `detection_max_scan_chars`          | `int`   | `65536` | 1024 - 262144 | Maximum total characters, across every value handed to the pattern engine per request (counted at the same point as `detection_max_scan_values`), before remaining values are skipped and a one-time warning logs the client IP. A value already in progress when the budget is checked is always scanned in full; only values that would start after the budget is spent are skipped, so a single large value is never silently dropped (GHSA-3hfx-8m47-5f9h residual). |
| `detection_max_json_depth`          | `int`   | `32`    | 1 - 1000      | Maximum nesting depth of a JSON request body walked structurally. A dict or list reached at this depth is not descended into: it is serialized back to text and scanned as one value instead, bounded by `detection_max_content_length`, so content hidden below the cap is still scanned as text rather than structurally. A one-time warning logs the client IP once reached (GHSA-f6cf-jjhc-qp85). |
| `detection_binary_min_run_length`   | `int`   | `16`    | 4 - 1024      | Minimum length a printable run inside a binary-dense multipart file-part payload must reach to be pattern-scanned. A part payload whose binary artifact characters make up at least a fifth of it is reduced to its printable runs before scanning; compressed bytes produce attack-shaped printable fragments at a rate that grows with file size, so shorter runs are skipped instead of matched. Text uploads and short or mostly-text payloads stay below the ratio and keep their full scan, whole-body fallback scans are never reduced (raw-body signature coverage stays intact), and text embedded in uploads (scripts inside PDFs, stored paths in archives) forms runs past the threshold and is scanned in full. File names, multipart field names, and part headers are scanned regardless (see `docs/configuration/detection-tuning.md`). |
| `detection_threat_score_threshold`  | `float` | `1.0`   | 0.0 - 10.0    | Anomaly/threat score required to flag a request. |
| `detection_scan_body`               | `bool`  | `True`  | N/A           | Scan the request body during detection; `False` restricts detection to path/query/headers. Body values are additionally filtered by the binary artifact density gate (see `docs/configuration/detection-tuning.md`): regex matches from registered noise-prone heuristic patterns inside strings dense in binary artifact characters are discarded, so text-decoded binary uploads no longer produce spurious blocks while signature patterns and pure text keep unchanged behavior. |

The detection engine follows one `SecurityConfig` per process: `detect_penetration_attempt(request, config)` configures the shared detection singleton from `config` the first time it is called, and reconfigures it whenever called with a different `SecurityConfig` object (compared by identity, so calling it repeatedly with the same object is a no-op). Alternating between two `SecurityConfig` objects on every other request reconfigures on every call, discarding the previously compiled pattern cache each time. The swap itself is a single attribute assignment: the new state is built completely before it replaces the old one, so a concurrent request always sees a fully-built state, never a half-constructed one. There is no lock around the swap.

___

Logging
-------

| Field                 | Type                                            | Default    | Description                              |
|-----------------------|-------------------------------------------------|------------|------------------------------------------|
| `log_suspicious_level`| `"INFO" \| "DEBUG" \| "WARNING" \| "ERROR" \| "CRITICAL" \| None` | `"WARNING"` | Log level for suspicious requests. `None` disables. |
| `log_request_level`   | Same as above                                   | `None`     | Log level for all requests. `None` disables. |
| `log_country_check_level` | Same as above (default `"INFO"`)            | `"INFO"`   | Log level for non-block country verdicts (whitelisted / not-affected). `None` disables. Blocked-country hits log at `log_suspicious_level` instead (default `WARNING`); no-rules / no-geolocation always log at `DEBUG`. |
| `muted_check_logs`      | `frozenset[str]`                              | `frozenset()` | Security check names to mute from pipeline logging entirely. Validator rejects unknown check names. |
| `log_sensitive_headers` | `frozenset[str]`                              | `frozenset()` | Header names redacted from guard log lines, matched case-insensitively. Merged with the hardcoded default set (`authorization`, `proxy-authorization`, `cookie`, `x-api-key`). Also redacts the value in the detection engine's per-header `Potential attack detected` line. |
| `log_sensitive_params` | `frozenset[str]`                              | `frozenset()` | Query-parameter names whose values are redacted from guard log lines, matched case-insensitively. Merged with the hardcoded default set (`access_token`, `refresh_token`, `api_key`, `apikey`, `token`, `password`, `secret`, `client_secret`, `signature`). Redacts the URL segment of `log_activity` lines and the value in the detection engine's per-parameter `Potential attack detected` line. |
| `log_sensitive_body_fields` | `frozenset[str]`                          | `frozenset()` | JSON key, form-field, and multipart text-part names whose values are redacted, matched case-insensitively. Merged with the same hardcoded default set as `log_sensitive_params`. Redacts only the value in the detection engine's per-field `Potential attack detected` line. |
| `log_format`          | `"text" \| "json"`                              | `"text"`   | Log output format.                       |
| `custom_log_file`     | `str \| None`                                   | `None`     | Path to a custom log file.               |

`setup_custom_logging()` (called by every adapter at middleware init with `log_format` and `custom_log_file`) always attaches its own console handler to the `guard_core` logger, but that handler's console output yields to the host's root handlers whenever they exist, whichever was configured first, so the event propagates to the host's own root handlers exactly once instead of printing twice. The `custom_log_file` handler is unaffected and is attached in every case. See [Logging Configuration](logging.md#avoiding-duplicate-log-lines) for detail.

___

Agent / Telemetry
-----------------

!!! note "Internal Configuration"
    Agent fields are typically not exposed to end users. They are used for Guard Agent SaaS integration.

| Field                             | Type                                        | Default                        | Description                         |
|-----------------------------------|----------------------------------------------|--------------------------------|--------------------------------------|
| `enable_agent`                    | `bool`                                       | `False`                        | Enable Guard Agent telemetry.       |
| `agent_api_key`                   | `str \| None`                                | `None`                          | API key for the SaaS platform.      |
| `agent_strict`                    | `bool`                                       | `False`                        | Raise at middleware init instead of degrading to agent-off when an enabled agent cannot be initialized. |
| `agent_endpoint`                  | `str`                                         | `"https://api.guard-core.com"` | Agent endpoint URL.                 |
| `agent_project_id`                | `str \| None`                                | `None`                          | Project identifier.                 |
| `agent_buffer_size`               | `int`                                         | `100`                           | Events to buffer before flush.      |
| `agent_flush_interval`            | `int`                                         | `30`                            | Seconds between automatic flushes.  |
| `agent_enable_events`             | `bool`                                       | `True`                          | Send security events.               |
| `agent_enable_metrics`            | `bool`                                       | `True`                          | Send performance metrics.           |
| `agent_timeout`                   | `int`                                         | `30`                            | HTTP request timeout in seconds.    |
| `agent_retry_attempts`            | `int`                                         | `3`                             | Retry attempts for failed requests. |
| `agent_project_encryption_key`    | `str \| None`                                | `None`                          | Per-project AES-256-GCM key that switches the agent to the encrypted events endpoint. Required for API keys with encryption enforced server-side. |
| `agent_guard_version`             | `str \| None`                                | `None`                          | Framework wrapper version (e.g. fastapi-guard's `__version__`) reported alongside agent telemetry. |
| `agent_status_interval`           | `int`                                         | `300`                           | Seconds between agent status reports to the SaaS. Must be between 60 and 86400. |
| `agent_high_watermark_ratio`      | `float \| None`                              | `None`                          | Buffer occupancy ratio that triggers an early flush. `None` defers to the agent's own default (`0.8`). |
| `agent_max_concurrent_flushes`    | `int \| None`                                | `None`                          | Maximum concurrent early-flush operations. `None` defers to the agent's own default (`1`). |
| `agent_buffer_overflow_policy`    | `Literal["drop", "block", "raise"] \| None`  | `None`                          | Behavior when the agent's in-memory buffer is full. `None` defers to the agent's own default (`"drop"`). |
| `agent_backoff_factor`            | `float \| None`                              | `None`                          | Backoff factor for agent HTTP retries. `None` defers to the agent's own default. |
| `agent_sensitive_headers`         | `list[str] \| None`                          | `None`                          | Header names excluded from telemetry payloads. `None` defers to the agent's own default. |
| `agent_max_payload_size`          | `int \| None`                                | `None`                          | Maximum payload size in bytes included in events. `None` defers to the agent's own default. |
| `agent_compression_enabled`       | `bool \| None`                               | `None`                          | Gzip-compress outgoing batch bodies above `agent_compression_threshold`. `None` defers to the agent's own default. |
| `agent_compression_threshold`     | `int \| None`                                | `None`                          | Minimum body size in bytes before gzip compression applies. `None` defers to the agent's own default. |
| `agent_install_id`                | `str \| None`                                | `None`                          | Override the agent install ID. `None` auto-generates one. |
| `agent_payload_signing_secret`    | `str \| None`                                | `None`                          | HMAC-SHA256 secret used to sign the `X-Payload-Signature` header. |
| `enable_enrichment`               | `bool`                                       | `False`                         | Populate `guard.*` metadata on every event and metric with project identity, deterministic threat score, matched dynamic rule, and per-IP behavioral correlation keys. Requires `enable_agent=True`. |
| `muted_event_types`               | `frozenset[str]`                             | `frozenset()`                   | Event types to mute from telemetry dispatch. Validator rejects unknown values. |
| `muted_metric_types`              | `frozenset[str]`                             | `frozenset()`                   | Metric types to mute from telemetry dispatch. Validator rejects unknown values. |
| `enable_otel`                     | `bool`                                       | `False`                         | Enable OpenTelemetry span/metric export. Requires the `otel` extra. |
| `otel_service_name`               | `str`                                         | `"guard-core"`                  | Service name reported on the OpenTelemetry resource. |
| `otel_exporter_endpoint`          | `str \| None`                                | `None`                          | OTLP HTTP endpoint for OpenTelemetry export. |
| `otel_resource_attributes`        | `dict[str, str]`                             | `{}`                            | Additional OpenTelemetry resource attributes (e.g. `deployment.environment`, `service.version`). |
| `enable_logfire`                  | `bool`                                       | `False`                         | Enable Logfire span/metric export. Requires the `logfire` extra. |
| `logfire_service_name`            | `str`                                         | `"guard-core"`                  | Service name reported to Logfire. |

**Validator**: `agent_api_key` is required when `enable_agent` is `True`. `agent_buffer_overflow_policy` rejects any value other than `"drop"`, `"block"`, or `"raise"` at construction time. `enable_enrichment=True` without `enable_agent=True` raises `ValueError`.

`SecurityConfig.on_error` (documented under [Core Settings](#core-settings) hooks) is also forwarded to `AgentConfig.on_error` when the agent is enabled, so the same callback receives agent-side `transport_send` and `encryption` failures in addition to guard-core's own `agent_init` and `geoip` failures.

All eleven fields above with a `None` default follow the same rule: `to_agent_config()` omits a field from the `AgentConfig` call entirely when it is `None`, so an unset field is controlled by `AgentConfig`'s own default rather than by a value duplicated into guard-core.

___

Dynamic Rules
-------------

| Field                   | Type   | Default | Description                                     |
|-------------------------|--------|---------|-------------------------------------------------|
| `enable_dynamic_rules`  | `bool` | `False` | Enable dynamic rule updates from SaaS platform. |
| `dynamic_rule_interval` | `int`  | `300`   | Seconds between rule update checks.             |
| `dynamic_rules_cache_path` | `Path \| None` | `None` | Optional local JSON file persisting the last-known dynamic rules snapshot so a restart during a SaaS outage restores the last applied rules instead of base config. Redis holds the primary snapshot whenever a redis_handler is present; the file is an additional opt-in fallback that is only written and read when this path is set. Neither store expires: the Redis key and the file persist until you remove them, even after you disable dynamic rules. |
| `emergency_mode`        | `bool` | `False` | Emergency lockdown mode (set by dynamic rules). |
| `emergency_whitelist`   | `list[str]` | `[]`| Emergency whitelist IPs (set by dynamic rules). |

**Validator**: `enable_agent` must be `True` when `enable_dynamic_rules` is `True`.

___

Validators
----------

`SecurityConfig` includes Pydantic validators that run on instantiation:

| Validator | Fields | Behavior |
|-----------|--------|----------|
| `validate_ip_lists` | `whitelist`, `blacklist` | Validates IP addresses and CIDR ranges. Raises `ValueError` on invalid entries. |
| `validate_trusted_proxies` | `trusted_proxies` | Validates proxy IPs and CIDR ranges, plus the literal `"unix"` token. Raises `ValueError` on invalid entries. |
| `warn_trusted_proxies_prefix_zero` | model-level | Logs a `WARNING` when `trusted_proxies` contains a `/0` network. Does not raise; construction still succeeds. |
| `warn_whitelist_prefix_zero` | model-level | Logs a `WARNING` when `whitelist` contains a `/0` network. Does not raise; construction still succeeds, and precedence is unchanged. |
| `warn_empty_enabled_detection_categories` | model-level | Logs a `WARNING` when `enabled_detection_categories` is empty while `enable_penetration_detection` is `True`. Does not raise; construction still succeeds. |
| `validate_proxy_depth` | `trusted_proxy_depth` | Must be >= 1. Raises `ValueError` otherwise. |
| `validate_cloud_providers` | `block_cloud_providers` | Requires the part before an optional `:!region` suffix to be `"AWS"`, `"GCP"`, or `"Azure"`. Raises `ValueError` naming any entry that fails this check. |
| `validate_geo_ip_handler_exists` | model-level | Requires `geo_ip_handler` when `blocked_countries` or `whitelist_countries` is set. Falls back to `IPInfoManager` if `ipinfo_token` is provided. Also re-run from `__setattr__`/`model_copy` when `blocked_countries`, `whitelist_countries`, `geo_ip_handler`, or `ipinfo_token` is reassigned after construction. As of 4.0.0, `__setattr__`/`model_copy` reassignment revalidation also covers every collection-typed field (`exclude_paths`, `global_behavior_rules`, `security_headers`, the CORS and OTel attribute fields, and the detection-exclusion sets among them), not only the geo-state fields. |
| `validate_agent_config` | model-level | Requires `agent_api_key` when `enable_agent` is `True`. Requires `enable_agent` when `enable_dynamic_rules` is `True`. |
| `validate_optional_extras_installed` | model-level | Requires the `redis` extra when `enable_redis` is `True`, the `cloud` extra (`aiohttp` or `requests`) when cloud blocking is enabled (`block_cloud_providers` or `enable_dynamic_rules`), and the `geo` extra (`maxminddb`) when country rules are configured with no custom `geo_ip_handler`. Raises `ValueError` naming the missing extra's install command, checked via `importlib.util.find_spec` (never a bare `import`). See [Installation](../installation.md#optional-dependency-extras). |
| `warn_unknown_fields` | model-level, `mode="before"` | Compares the constructor keyword arguments against `model_fields` (and any field's `alias`) and logs a `guard_core.models` warning naming each unknown key, since `SecurityConfig` still allows unknown keys through (`extra="ignore"`) rather than raising. Construction still succeeds and the unknown key is still dropped; only a log line is added, so a typo'd field name is no longer a silent no-op. `extra="forbid"` is the intended behavior at a future major release. |

!!! warning "Unknown provider names raise"
    `validate_cloud_providers` rejects a `block_cloud_providers` entry whose provider name (the part before an optional `:!region` suffix) is not `"AWS"`, `"GCP"`, or `"Azure"`. `{"AWS", "InvalidProvider"}` raises `ValueError` naming `InvalidProvider` instead of silently blocking only `"AWS"`.
