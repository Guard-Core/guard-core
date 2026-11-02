# Security Pipeline

`SecurityCheckPipeline` (`guard_core/core/checks/pipeline.py`) is a chain of responsibility. Checks run sequentially in insertion order; the first returning a non-`None` `GuardResponse` short-circuits and blocks.

## Pre-pipeline: missing client address

Before `SecurityCheckPipeline.execute` runs at all, `BypassHandler.handle_passthrough` (`guard_core/core/bypass/handler.py`) runs two gates in order:

1. **`exclude_paths` matching.** If the request path matches, `request.state.guard_exclusion_scoped = True` is set and the request proceeds into the pipeline (only `route_config`, `ip_security` and `emergency_mode` still run for it -- see "Which checks get built" below); this happens before the client address is resolved, so an excluded health/readiness endpoint is unaffected by the next gate.
2. **Missing client address.** If `request.client_host` is falsy, the handler resolves an identity via `extract_client_ip(request, config)`. When that resolves to `"unknown"` (`UNKNOWN_CLIENT_IDENTITY`, `guard_core/_utils/ip_extraction.py`), `fail_secure=True` (the default) makes `handle_passthrough` return a 403 `GuardResponse` directly, before any pipeline check runs; `fail_secure=False` lets the request continue into the pipeline with `request.state.client_ip` already set to `"unknown"`. Either outcome logs a one-time warning naming the fix (add the literal `"unix"` token to `trusted_proxies` for a Unix-socket deployment, so `X-Forwarded-For` can still resolve the real client instead of every request presenting as clientless).

The `"unknown"` identity is not automatically blocked once inside the pipeline: `IpSecurityCheck` (via `check_ip_access`/`check_route_ip_access`) allows it through unless a global `whitelist`, `whitelist_countries`, a route `ip_whitelist`, or a route `whitelist_countries` is configured, in which case it is blocked as if it failed that allowlist (`guard_core/_utils/access_control.py`, `guard_core/core/checks/helpers.py`).

## Execution semantics

* `check.check(request) -> GuardResponse | None`: `None` passes, a `GuardResponse` blocks.
* On a check exception, the pipeline catches it. `fail_secure=True` (default) blocks with HTTP 500 via `check.create_error_response(500, ...)` (a `GuardRedisError` answers its own 503 with `Retry-After: 5`); `fail_secure=False` continues to the next check.
* All checks returning `None` means the request is allowed (pipeline returns `None`).

## The check catalogue, in order

`DEFAULT_CHECK_CLASSES` (`guard_core/core/checks/factory.py`) names 18 checks. This is the full catalogue and its order is fixed; what a given deployment actually builds is a subset, decided at pipeline-build time (see "Which checks get built" below).

1. `route_config` - extract per-route config.
2. `emergency_mode` - block-all toggle.
3. `https_enforcement` - redirect/reject non-HTTPS.
4. `request_logging` - structured access logging.
5. `request_size_content` - size and content-type gates.
6. `cloud_ip_refresh` - refresh cloud IP ranges.
7. `ip_security` - whitelist/blacklist + country.
8. `cloud_provider` - block cloud provider source IPs.
9. `user_agent` - UA allow/block.
10. `cors_preflight` - answer CORS preflights an override turned on.
11. `rate_limit` - sliding window (memory or Redis).
12. `required_headers` - presence and exact-value checks.
13. `authentication` - auth gate.
14. `referrer` - referrer policy.
15. `custom_validators` - user-supplied sync/async validators.
16. `time_window` - time-of-day access windows.
17. `suspicious_activity` - detection engine integration.
18. `custom_request` - user-supplied request-level check.

`rate_limit`'s in-memory stores (`RateLimitManager.request_timestamps`, and the module-level `_by_ip_request_timestamps`/`_by_ip_autoban_counts` in `guard_core/handlers/ratelimit_handler.py`) are LRU-bounded at 10,000 tracked IPs (`_lru_pop_or_create`, `guard_core/_utils/lru_store.py`): once the bound is hit, adding a new IP evicts the least-recently-touched one. Every 429 response the check returns carries a `Retry-After` header set to the effective rate-limit window, whether the store is in-memory or Redis-backed.

`rate_limit` honors `redis_fail_open` on a Redis failure like every other check, instead of always falling back to the in-memory window regardless of the flag: `redis_fail_open=True` keeps the in-memory fallback (a `WARNING` logged once per process, not an `ERROR` per request); `redis_fail_open=False` (the default) raises `GuardRedisError` so `SecurityCheckPipeline._handle_check_error` applies `fail_secure` exactly as it does for any other check's Redis failure.

## Which checks get built

`SecurityCheck.applies_to(cls, config, route_configs) -> bool` (`guard_core/core/checks/base.py`) is a classmethod extension point: given the effective `SecurityConfig` and the collection of registered `RouteConfig`s (or `None` when they cannot be enumerated), it declares whether the check can ever fire. The base implementation always returns `True`, so a check that does not override it runs unconditionally; a check opts into elimination by overriding `applies_to` to return `False` under some condition. `build_default_pipeline(middleware)` (`guard_core/core/checks/factory.py`) filters `DEFAULT_CHECK_CLASSES` through `applies_to` before instantiating anything, so an eliminated check is never constructed, and for the checks that moved their handler import into `__init__` (`ip_security`, `suspicious_activity`, `cloud_provider`, `cloud_ip_refresh`), never imports its handler either.

Elimination is strictly an optimization, never a security decision: every `applies_to` implementation is written to return `True` on any uncertainty, and the one check that reads mutable ban state is pinned to always-keep (below). A default `SecurityConfig()` with no route decorators registered builds exactly five checks: `route_config`, `ip_security`, `cors_preflight`, `rate_limit`, `suspicious_activity`. A configuration that enables every feature builds all 18, in the order above.

Three rules govern the subsetting:

* **`enable_dynamic_rules=True` keeps every dynamically-mutable check regardless of other flags.** `DynamicRuleManager` can mutate `emergency_mode`, `block_cloud_providers`, `blocked_user_agents`, `enable_penetration_detection`, `enable_ip_banning`, and `enable_rate_limiting` at runtime (`guard_core/handlers/dynamic_rule_handler.py`), so `emergency_mode`, `cloud_ip_refresh`, `cloud_provider`, `user_agent`, `rate_limit`, and `suspicious_activity` all OR in `config.enable_dynamic_rules` inside their `applies_to`, and are kept whenever it is set even with every other relevant flag off.
* **Unknown route configuration means keep everything route-driven.** `_collect_route_configs` (`guard_core/core/checks/factory.py`) returns `None`, not an empty tuple, when the middleware has no `guard_decorator` to enumerate. `route_config_applies` (`guard_core/core/checks/helpers.py`) treats `None` as "keep the check" and an empty tuple as "no route declares this, drop it." A middleware that cannot expose its decorator handle loses the optimization on every route-driven check but never loses the protection.
* **`IpSecurityCheck` never overrides `applies_to`**, so it is always built. It fronts an unconditional ban lookup whose store (`ip_ban_manager`) is writable from behavior-rule bans and from other processes sharing the same Redis; no configuration can prove that store will stay empty, so it is never a candidate for elimination.

## Extending

Subclass `SecurityCheck` (`guard_core/core/checks/base.py`), implement `check_name` and `async check(request)`, and append via `pipeline.add_check(...)` or `insert_check(index, ...)`. You get `self.middleware`, `self.config`, `self.logger`, `send_event(...)`, `create_error_response(...)`, and `is_passive_mode()` for free. Do not mutate handlers directly; read/write through `self.config`. A subclass inherits the base `applies_to` (always `True`) unless it overrides it; only override it if the check should participate in `build_default_pipeline`'s elimination.

## Pipeline management

`add_check`, `insert_check`, `remove_check(check_name) -> bool`, `get_check_names() -> list[str]`, `__len__`. `build_default_pipeline` passes `config.muted_check_logs` into `SecurityCheckPipeline`, so both the pipeline-level block/error log lines and the in-check `log_activity()` calls honor `muted_check_logs`; only an adapter that hand-builds `SecurityCheckPipeline(checks)` without going through the factory would need to pass `muted_check_logs` itself.
