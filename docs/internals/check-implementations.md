---

title: Check Implementations
description: All 17 built-in security checks in guard-core, their execution order, blocking conditions, configuration, and the applies_to build-time elimination rules
keywords: security checks, implementations, execution order, guard-core, pipeline
---

Check Implementations
=====================

Guard-core ships with 17 security checks that execute in this fixed order inside the `SecurityCheckPipeline` when all 17 are built. Each check is a subclass of `SecurityCheck` located in `guard_core.core.checks.implementations`. A given deployment's pipeline is usually a subset of the 17: `build_default_pipeline` filters the catalogue through each check class's `applies_to(config, route_configs)` classmethod before instantiating anything, and only the checks that return `True` for the effective configuration and registered routes are built. The base implementation returns `True`, so a check that does not override it always runs; a predicate that is uncertain what the configuration can trigger must also return `True` -- elimination is strictly an optimization, never a security decision. See [Build-Time Elimination](../architecture/pipeline.md#build-time-elimination) for the full mechanism, including why `ip_security` can never be eliminated.

Execution Order
---------------

| #  | Check Name              | Class                     | Blocks? | Passive-Aware? | Eliminated when |
|----|-------------------------|---------------------------|---------|----------------|------------------|
| 1  | `route_config`          | `RouteConfigCheck`        | Strict  | Yes            | Never |
| 2  | `emergency_mode`        | `EmergencyModeCheck`      | Yes     | Yes            | `emergency_mode` is `False` and `enable_dynamic_rules` is `False` |
| 3  | `https_enforcement`     | `HttpsEnforcementCheck`   | Yes     | Yes            | `enforce_https` is `False` and no route requires HTTPS |
| 4  | `request_logging`       | `RequestLoggingCheck`     | Never   | N/A            | `log_request_level` is `None` |
| 5  | `request_size_content`  | `RequestSizeContentCheck` | Yes     | Yes            | No route sets `max_request_size` or `allowed_content_types` |
| 6  | `cloud_ip_refresh`      | `CloudIpRefreshCheck`     | Never   | N/A            | `block_cloud_providers` unset globally and per-route, and `enable_dynamic_rules` is `False` |
| 7  | `ip_security`           | `IpSecurityCheck`         | Yes     | Yes            | Never |
| 8  | `cloud_provider`        | `CloudProviderCheck`      | Yes     | Yes            | `block_cloud_providers` unset globally and per-route, and `enable_dynamic_rules` is `False` |
| 9  | `user_agent`            | `UserAgentCheck`          | Yes     | Yes            | `blocked_user_agents` empty globally and per-route, and `enable_dynamic_rules` is `False` |
| 10 | `rate_limit`            | `RateLimitCheck`          | Yes     | Yes            | `enable_rate_limiting` is `False`, `endpoint_rate_limits` unset, no route sets `rate_limit`/`geo_rate_limits`, and `enable_dynamic_rules` is `False` |
| 11 | `required_headers`      | `RequiredHeadersCheck`    | Yes     | Yes            | No route sets `required_headers` |
| 12 | `authentication`        | `AuthenticationCheck`     | Yes     | Yes            | No route sets `auth_required` |
| 13 | `referrer`              | `ReferrerCheck`           | Yes     | Yes            | No route sets `require_referrer` |
| 14 | `custom_validators`     | `CustomValidatorsCheck`   | Yes     | Yes            | No route sets `custom_validators` |
| 15 | `time_window`           | `TimeWindowCheck`         | Yes     | Yes            | No route sets `time_restrictions` |
| 16 | `suspicious_activity`   | `SuspiciousActivityCheck` | Yes     | Yes            | `enable_penetration_detection` is `False`, no route sets `enable_suspicious_detection`, and `enable_dynamic_rules` is `False` |
| 17 | `custom_request`        | `CustomRequestCheck`      | Yes     | Yes            | `custom_request_check` is `None` |

**Passive-Aware** means the check respects `SecurityConfig.passive_mode` -- it logs and emits events but does not return a blocking response.

**Strict** in the Blocks column means the check only blocks when a non-default setting turns it on; `route_config` blocks solely under `SecurityConfig.route_resolution_strict`.

**Eliminated when** describes the condition under which `applies_to` returns `False` and `build_default_pipeline` skips instantiating the check entirely. "No route sets X" only applies when the adapter can enumerate registered routes; when it cannot (`route_configs is None`), every route-driven check is kept. `enable_rate_limiting` and `enable_penetration_detection` both default to `True`, so `rate_limit` and `suspicious_activity` are built by default even with no other configuration. `route_config` and `ip_security` have no `applies_to` override and are never eliminated.

___

1. RouteConfigCheck
-------------------

**Purpose**: Populates `request.state` with route configuration and client IP for all subsequent checks.

**Blocks when**: `config.route_resolution_strict` is `True` and the adapter set `request.state.guard_route_unresolved`, meaning it could not match the request to a route. Off by default, in which case this check never blocks.

**Response**: `404` (no route serves the path), `405` (the path is served under another method) or `500` (a matched route whose config the decorator does not know, or a failing route lookup), all with the body `Route resolution failed` (a CORS preflight is not blocked when CORS is on), alongside a suspicious-activity log and a `route_unresolved` event. Under `passive_mode` the log and event still fire and the request proceeds. The `405` carries an `Allow` header listing the methods the adapter's optional `allowed_methods(path)` lookup reports for the path (RFC 9110 section 15.5.6); an adapter without that lookup sends the `405` without `Allow`.

**What it does**:

- Calls `middleware.route_resolver.get_route_config(request)` to resolve decorator-applied `RouteConfig`.
- Sets `request.state.route_config`, which is `None` both when no decorator is applied and when the adapter could not resolve the route. Only the adapter can tell those apart, which is why it reports the second case separately -- see [Reporting a Failed Match](../adapters/decorators.md#reporting-a-failed-match).
- Calls `extract_client_ip()` and sets `request.state.client_ip`.

!!! important "Must Run First"
    Every other check reads `request.state.route_config` and `request.state.client_ip`. Removing or reordering this check will break the pipeline.

___

2. EmergencyModeCheck
---------------------

**Purpose**: Lockdown mode that blocks all traffic except whitelisted IPs.

**Blocks when**: `config.emergency_mode` is `True` and `client_ip` is not in `config.emergency_whitelist`, on every path (the `exclude_paths` entries included) except the ones in `config.emergency_exempt_paths`. With `config.emergency_whitelist_only` set to `False`, IPs in `config.whitelist` or `config.exempt_ips` also get through; everyone else is still blocked.

**Response**: `503 Service temporarily unavailable`

**Configuration**:

| Field                 | Type         | Default  |
|-----------------------|-------------|----------|
| `emergency_mode`      | `bool`      | `False`  |
| `emergency_whitelist` | `list[str]` | `[]`     |
| `emergency_whitelist_only` | `bool` | `True` |
| `emergency_exempt_paths` | `list[str]` | `[]` |

___

3. HttpsEnforcementCheck
------------------------

**Purpose**: Redirects HTTP requests to HTTPS.

**Blocks when**: HTTPS is required (globally or per-route) and the request is not HTTPS.

**Response**: `307` redirect to the HTTPS URL (via `response_factory.create_https_redirect`).

**HTTPS detection logic**:

1. Checks `request.url_scheme == "https"`.
2. If `trust_x_forwarded_proto` is enabled and the connecting IP is a trusted proxy, also checks `X-Forwarded-Proto: https`.

**Configuration**:

| Field                     | Type    | Default |
|---------------------------|---------|---------|
| `enforce_https`           | `bool`  | `False` |
| `trust_x_forwarded_proto` | `bool`  | `False` |
| `trusted_proxies`         | `list[str]` | `[]` |

Per-route: `RouteConfig.require_https`.

___

4. RequestLoggingCheck
----------------------

**Purpose**: Logs every incoming request.

**Blocks**: Never.

**Configuration**: `config.log_request_level` controls the log level. Set to `None` to disable.

___

5. RequestSizeContentCheck
--------------------------

**Purpose**: Validates request size and content type against route-level limits.

**Blocks when**:

- `Content-Length` exceeds `RouteConfig.max_request_size` (returns `413`).
- `Content-Type` is not in `RouteConfig.allowed_content_types` (returns `415`).

**Configuration**: Set via decorators on `RouteConfig`.

___

6. CloudIpRefreshCheck
----------------------

**Purpose**: Periodically refreshes cloud provider IP ranges.

**Blocks**: Never. The refresh runs as a single-flight background task (via `cloud_handler.schedule_refresh`, which invokes the middleware's `refresh_cloud_ip_ranges()`), so the request that crosses the interval is never delayed by provider fetches.

**Triggers when**: `config.block_cloud_providers` is set and `cloud_ip_refresh_interval` seconds have elapsed since the last refresh. If scheduling fails, the debounce timestamp is restored so the next request retries.

___

7. IpSecurityCheck
------------------

**Purpose**: Enforces IP-based access control at multiple levels.

**Evaluation order**:

1. **Banned IP check**: Consults `IPBanManager`. Returns `403 IP address banned`.
2. **Route-level IP restrictions**: If a `RouteConfig` exists, evaluates its `ip_blacklist`, `ip_whitelist`, `blocked_countries`, and `whitelist_countries` first. Returns `403 Forbidden` if the route denies the request.
3. **Global IP restrictions**: Always evaluated afterward, even when the route-level check ran and passed. Evaluates `config.blacklist`, `config.whitelist`, `config.blocked_countries`, and `config.block_cloud_providers`. Returns `403 Forbidden`.

A route setting overrides the global gate only for the aspect it explicitly allows, and the IP and country aspects are evaluated independently: a route `ip_whitelist` match replaces the global whitelist but never lifts the global blacklist, and does not exempt the request from country enforcement, and only an actual `whitelist_countries` match for the resolved country suppresses the global country gate. A route-level deny (`ip_blacklist` / `blocked_countries`) is enforced at the route step and never, by itself, disables the global IP or country rules. Within the IP aspect, a route `ip_whitelist` match wins over that same route's own `ip_blacklist` (v3.2.0 precedence, unchanged).

Also sets `request.state.is_whitelisted`, `True` only for a **global** `config.whitelist` match and only while `whitelist_access_only` is off (it is on by default since 5.0.0; with the flag on it is always `False` and `request.state.whitelist_entry` names the matching entry, so the global whitelist has the same access-only meaning as a route `ip_whitelist`). A route-level `ip_whitelist` match grants access to that route but does not set `is_whitelisted`; it is access-only and still passes through rate limiting, user-agent filtering, cloud-provider blocking, and suspicious-activity detection.

___

8. CloudProviderCheck
---------------------

**Purpose**: Blocks requests originating from cloud provider IP ranges (AWS, GCP, Azure).

**Blocks when**: `client_ip` belongs to a blocked cloud provider's network and the check is not bypassed.

**Response**: `403 Cloud provider IP not allowed`

**Skips**: IPs whitelisted at the **global** level (`request.state.is_whitelisted`, never set while `whitelist_access_only` is on), a route-level `ip_whitelist` match alone does not set this, so it does not skip this check.

___

9. UserAgentCheck
-----------------

**Purpose**: Blocks requests from matching user agents.

**Blocks when**: The `User-Agent` header matches any pattern in `RouteConfig.blocked_user_agents` or `config.blocked_user_agents` (case-insensitive regex).

**Response**: `403 User-Agent not allowed`

**Skips**: Whitelisted IPs.

___

10. RateLimitCheck
------------------

**Purpose**: Enforces request rate limits using a sliding window algorithm.

**Tiers**, checked together in one call (the first that blocks decides the response):

1. **Endpoint-specific rate limits** from `config.endpoint_rate_limits` (set by dynamic rules).
2. **Route-level rate limits** from `RouteConfig.rate_limit` and `RouteConfig.rate_limit_window`.
3. **Geo-based rate limits** from `RouteConfig.geo_rate_limits`.
4. **Global rate limits** from `config.rate_limit` and `config.rate_limit_window`, only when `enable_rate_limiting` is on.

Each tier has its own bucket, and a request that any tier blocks is recorded in none of them. See [Rate Limiting](rate-limiting.md).

**Response**: `429 Too many requests` with a `Retry-After` header: the seconds until the blocking tier has room again, at least 1.

**Skips**: Whitelisted and exempt IPs, bypassed routes, excluded paths (`exclude_paths`) and CORS preflights (`OPTIONS` with `Access-Control-Request-Method`). Bans and the IP, country and cloud lists still apply to all of those, because `ip_security` runs first.

___

11. RequiredHeadersCheck
------------------------

**Purpose**: Validates that required headers are present, and where a specific value is configured, that they match it.

**Blocks when**: A header in `RouteConfig.required_headers` is missing from the request, or, when the configured value is not the sentinel `"required"`, present but not equal to that value.

**Response**: `400 Bad request`. The body never names the header or says whether a value was close; the specific reason (`Missing required header: {name}` or `Header 'X' does not match the required value`) goes to the log line and the event only. A configured value is compared with `hmac.compare_digest`. `api_key_auth` registers its header here as `"required"` (presence only); this check leaves that entry to the authentication check, which answers a missing key with 401. A literal value set for the same header is still enforced here.

!!! warning "Breaking Change"
    Before this fix, a configured value other than `"required"` was never enforced -- the check was a silent no-op for it, and neither a missing header nor a mismatched value blocked the request. A route relying on that no-op now has the value enforced.

___

12. AuthenticationCheck
-----------------------

**Purpose**: Validates every credential the route configures: the `Authorization` header for `require_auth` and the API key header for `api_key_auth`, each by its own verifier.

**Blocks when**: `RouteConfig.auth_required` or `RouteConfig.api_key_required` is set and a configured credential is missing, empty, in the wrong format (`"bearer"` expects `Bearer ...`, `"basic"` expects `Basic ...`, the scheme name is case-insensitive) or rejected by its verifier. A route that stacks `require_auth` and `api_key_auth` needs both to pass. A verifier that raises is logged at ERROR with its exception type and its traceback, with the credential (and for `basic` the decoded `user:password` and password) replaced by `[REDACTED]`, and the response is `503 Authentication service unavailable` without a challenge; it never counts toward a ban, writes no `Authentication failure` log line and sends no `decorator_violation` or `authentication_failed` event; it sends one `auth_verifier_error` event instead (`action_taken` `request_blocked`, or `logged_only` in passive mode, with `reason`, `auth_type` and `violation_type` in the metadata).

**Response**: `401 Authentication required` with a `WWW-Authenticate` challenge: `Bearer`, `Basic realm="Restricted"` or `ApiKey`.

!!! note "Token validation is the verifier's job"
    `require_auth` and `api_key_auth` run the route's `verifier=` (or `SecurityConfig.auth_verifier`) on the credential; without one, every request on the route gets 401. `require_authorization_header` checks presence and format only and does not authenticate.

___

13. ReferrerCheck
-----------------

**Purpose**: Validates the `Referer` header against allowed domains.

**Blocks when**: `RouteConfig.require_referrer` is set and either the header is missing or the domain is not in the allowed list.

**Response**: `403 Referrer required` or `403 Invalid referrer`

___

14. CustomValidatorsCheck
-------------------------

**Purpose**: Runs user-defined async validator functions.

**Blocks when**: Any validator in `RouteConfig.custom_validators` returns a non-`None` `GuardResponse`. A rejection from a validator listed in `RouteConfig.honeypot_validators` (registered by `honeypot_detection`) is handled as a honeypot hit: it counts one `honeypot` hit and bans the client IP, by default on the first hit, builds its 403 through `middleware.create_error_response` (so `custom_error_responses` apply), and fires the `on_block` hook with `check_name="honeypot"`. Every other validator keeps its own response and never fires the hook.

**Configuration**: Validators are `Callable[[GuardRequest], Awaitable[GuardResponse | None]]` functions registered via decorators.

___

15. TimeWindowCheck
-------------------

**Purpose**: Restricts access to specific time windows.

**Blocks when**: The current time falls outside the `start`/`end` range defined in `RouteConfig.time_restrictions`.

**Response**: `403 Access not allowed at this time`

**Time restriction format**:

```python
{
    "start": "09:00",
    "end": "17:00",
    "timezone": "US/Eastern",  # optional, defaults to UTC
}
```

Supports overnight ranges (e.g., `start: "22:00"`, `end: "06:00"`).

___

16. SuspiciousActivityCheck
---------------------------

**Purpose**: Detects penetration attempts (SQLi, XSS, command injection, path traversal, etc.).

**Blocks when**: `detect_penetration_patterns()` finds a threat in query parameters, URL path, headers, or request body.

**Behavior**:

- Increments `suspicious_request_counts[client_ip]`.
- When the count reaches `auto_ban_threshold`, bans the IP via `IPBanManager` for `auto_ban_duration` seconds.
- Returns `403 IP has been banned` if auto-banned, otherwise `400 Suspicious activity detected`.

**Skips**: Whitelisted IPs and routes with detection disabled via decorator.

___

17. CustomRequestCheck
----------------------

**Purpose**: Runs a global user-defined request check function.

**Blocks when**: `config.custom_request_check` returns a non-`None` `GuardResponse`.

**Configuration**: `SecurityConfig.custom_request_check` is an async or a sync callable taking the request (`Callable[[GuardRequest], Awaitable[GuardResponse | None]]` or `Callable[[GuardRequest], GuardResponse | None]`). The check classifies the callable once and again only when the field holds another object. In the async tree an async callable is awaited and a sync one runs inline on the event loop (it must not block). In the sync tree an async callable raises `guard_core.exceptions.CallableShapeError` (a `TypeError`) when the check is built, and a sync callable that returns an awaitable (a decorator around an async function, a lambda returning a coroutine) raises the same error on its first result.

___

Implementing a Custom Check
---------------------------

To add a new check, create a subclass of `SecurityCheck`:

```python
from guard_core.core.checks.base import SecurityCheck
from guard_core.protocols.request_protocol import GuardRequest
from guard_core.protocols.response_protocol import GuardResponse


class GeoFenceCheck(SecurityCheck):
    @property
    def check_name(self) -> str:
        return "geo_fence"

    async def check(self, request: GuardRequest) -> GuardResponse | None:
        client_ip = getattr(request.state, "client_ip", None)
        if not client_ip:
            return None

        if self._is_outside_fence(client_ip):
            if self.is_passive_mode():
                self.logger.warning(f"Geo-fence violation: {client_ip}")
                return None
            return await self.create_error_response(403, "Access denied")

        return None
```

Register it in the pipeline during middleware initialization:

```python
pipeline.insert_check(12, GeoFenceCheck(middleware))
```
