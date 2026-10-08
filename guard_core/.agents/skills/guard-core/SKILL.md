---
name: guard-core
description: Guard Core best practices and conventions for the framework-agnostic Python security engine. Use when working with guard-core, SecurityConfig, the security check pipeline, detection engine (SusPatternsManager, PatternCompiler, ContentPreprocessor, SemanticAnalyzer), telemetry/event bus (OTel, Logfire, guard-agent enrichment), or building a framework adapter via the GuardRequest/GuardResponse/GuardResponseFactory protocols. Covers setup, the config-derived security pipeline (17-check catalogue, only the checks a given config can trigger are actually built), the 19-category detection catalog, telemetry models, and known footguns
---

# Guard Core

Official guard-core skill to write code with best practices, keeping up to date with the real installed surface (introspect the package, do not rely on model memory of it).

Current as of guard-core 4.3.1.

guard-core is the framework-agnostic security engine powering the Guard ecosystem. Framework adapters (fastapi-guard, flaskapi-guard, djapi-guard, tornadoapi-guard) implement three protocols and get the full pipeline, detection engine, Redis state, and telemetry for free.

## Quick Reference

* Adapter authors: implement `GuardRequest`, `GuardResponse`, `GuardResponseFactory`; see [Adapters](#building-adapters) and [the adapters reference](references/adapters.md).
* All behavior is `SecurityConfig`; do not mutate handlers directly; see [SecurityConfig](#securityconfig) and [the config reference](references/config.md).
* Detection: `SusPatternsManager.detect()` over 19 categories; see [Detection Engine](#detection-engine) and [the detection reference](references/detection.md).
* Telemetry: two tiers (raw OTel/Logfire free, guard-agent enrichment gated); see [Telemetry](#telemetry) and [the telemetry reference](references/telemetry.md).
* Logfire + Pydantic: guard-core mutes guard-agent telemetry-model instrumentation the first time a config actually enables agent/OTel/Logfire, not at `import guard_core`; see [Footguns](#footguns).
* Sync mirror: `guard_core.sync.*` is unasync-generated from `guard_core.*`; never hand-edit it; see [Sync mirror](#sync-mirror).

## Installation

```bash
pip install guard-core
# feature extras: redis, aiohttp/requests and maxminddb are still base dependencies through the 3.x line, so these are additive, not required
pip install "guard-core[redis]"     # enable_redis
pip install "guard-core[cloud]"     # block_cloud_providers / cloud-provider blocking
pip install "guard-core[geo]"       # blocked_countries / whitelist_countries when no custom geo_ip_handler is supplied
# optional telemetry extras
pip install "guard-core[otel]"      # OpenTelemetry export
pip install "guard-core[logfire]"   # Logfire export
```

`import guard_core` no longer loads `aiohttp`, `maxminddb`, `redis`, `guard_agent`, or `cryptography`; a bare import costs roughly 2ms (measured via `python -X importtime`, Python 3.10.19). Handlers and third-party libraries load lazily, only when a check that needs them is actually built or a feature that needs them is actually configured. If a feature is configured without its extra installed, `SecurityConfig` raises a `ValueError` at construction time naming the missing extra's install command, instead of surfacing a raw `ImportError` mid-request. See [the config reference](references/config.md#optional-extras) for exactly which flags gate which extra.

`guard-agent` is an optional runtime dependency pulled in by adapters when `enable_agent=True`; it is not a hard dependency of guard-core.

## Setup

Working in this repository (not just consuming the package):

```bash
make install-dev           # uv sync with dev extras
uv run pre-commit install  # ruff, mypy, vulture, bandit, safety, radon, xenon, deptry
make local-test            # REDIS_URL=redis://localhost:6379 pytest with a 100% coverage gate
make sync                  # regenerate guard_core/sync/ (scripts/unasync.py); check-sync verifies
```

## SecurityConfig

All behavior is controlled through one Pydantic model. Construct it once and pass it to your adapter's middleware/initializer.

```python
from guard_core.models import SecurityConfig

config = SecurityConfig(
    whitelist=["192.168.1.0/24"],
    blacklist=["10.0.0.1"],
    blocked_user_agents=["curl", "wget"],
    auto_ban_threshold=5,
    auto_ban_duration=86400,
    rate_limit=100,
    rate_limit_window=60,
    enforce_https=True,
    block_cloud_providers={"AWS", "GCP", "Azure"},
    enable_redis=True,
    redis_url="redis://localhost:6379",
)
```

Field defaults are the source of truth. For an authoritative list of every field, type, default, and description, introspect the installed model rather than recalling from memory:

```python
python -c "from guard_core.models import SecurityConfig; \
import json; print(json.dumps({f: (SecurityConfig.model_fields[f].default, SecurityConfig.model_fields[f].description) for f in SecurityConfig.model_fields}, indent=2, default=str))"
```

Key defaults that bite:

* `on_block` (default `None`) is an optional callback fired exactly once per block decision, receiving `(request, payload)` where payload carries `check_name`, `reason`, `trigger_info`, `passive_mode`, `client_ip`, `path`, `method`, and `status_code`. In passive mode it fires at flag time with `status_code=None`, since no response is ever sent. It is deliberately not fired for `custom_request` or route `custom_validators` (application-authored, the app already knows), the HTTPS-enforcement redirect (a redirect is not a block), or an adapter's Redis-unavailable response (cover that with `on_error`). Under ASGI the hook may be sync or async; under WSGI it must be sync and an async hook raises `TypeError`. A hook that raises is caught and logged, never propagated into request handling.
* `dynamic_rules_cache_path` (default `None`) is the opt-in file layer for the last-known dynamic rules snapshot. With `enable_dynamic_rules=True`, every successfully applied `DynamicRules` payload is persisted as a versioned strict envelope (`LastKnownRulesSnapshot`, `guard_core/_dynamic_rules.py`): to Redis under the `dynamic_rules` namespace, key `last_known`, whenever a redis handler is present, and to this file when set (atomic `tempfile` + `os.replace`). `DynamicRuleManager.initialize_agent` hydrates once per process before the update loop starts, Redis first then the file, through the normal apply path, so a restart during a SaaS outage comes up with the last applied rules instead of base config, and the first successful fetch supersedes them through the usual version check. An expired, malformed, or newer-schema snapshot is discarded with an error logged and the next store is tried; nothing is applied in degraded form. Neither store expires on its own: remove the Redis key or the file yourself after disabling dynamic rules.
* `fail_secure` defaults to `True`. A check raising an unexpected exception blocks with HTTP 500 instead of falling through. Opt back into fail-open with `SecurityConfig(fail_secure=False)` only if you understand the risk.
* `enable_redis` defaults to `True` with `redis_url="redis://localhost:6379"`. If you have no Redis, set `enable_redis=False` or point at a real instance; do not leave the default running in a no-Redis environment.
* `passive_mode` defaults to `False`. Set `True` for log-only mode (no blocking, events still emit).
* `detection_max_scan_values` defaults to `512` (`ge=2`) and bounds the total query-parameter, header, JSON-key/value, form-field, and multipart-part values scanned per request, including JSON embedded within a single value; each named value costs two scan units (name and value), so the floor is `2`, not `1`. Once the cap is reached, remaining values in that request are not scanned and a one-time warning names the client IP.
* `detection_max_json_depth` defaults to `32` (`ge=1`, `le=1000`) and bounds how deep the structural JSON-body walk descends. A dict or list reached at that depth is serialized back to text and scanned as one value instead of being walked further, and a one-time warning names the client IP.

See [the config reference](references/config.md) for the full field surface and the telemetry/detection-tuning fields.

## Building Adapters

Implement three protocols to bridge your framework into the pipeline. Everything else (the check catalogue, detection engine, Redis state, event telemetry) works out of the box; expose `guard_decorator` on your middleware so guard-core can enumerate registered routes and build a smaller, config-derived pipeline instead of keeping every route-driven check (see [Security Pipeline](#security-pipeline)).

```python
from guard_core.protocols import GuardRequest, GuardResponse, GuardResponseFactory
```

`GuardRequest` exposes: `url_path`, `url_scheme`, `url_full`, `url_replace_scheme(scheme)`, `method`, `client_host`, `headers`, `query_params`, `async body()`, `state`, `scope`.

`GuardResponse` exposes: `status_code`, `headers`, `body`.

`GuardResponseFactory` exposes: `create_response(content, status_code)`, `create_redirect_response(url, status_code)`.

See [the adapters reference](references/adapters.md) for a complete wrapper example and the middleware-wiring checklist.

## Security Pipeline

`SecurityCheckPipeline` runs, per request, whichever checks the effective configuration can actually trigger, in the fixed catalogue order below. `build_default_pipeline` filters the 17-check catalogue through each check's `applies_to(config, route_configs)` classmethod before instantiating anything; the base `SecurityCheck.applies_to` returns `True`, so a check that does not override it always runs, and elimination is strictly an optimization, never a security decision. The catalogue and its order are unchanged; only the subset a given deployment builds varies.

1. route_config
2. emergency_mode
3. https_enforcement
4. request_logging
5. request_size_content
6. required_headers
7. authentication
8. referrer
9. custom_validators
10. time_window
11. cloud_ip_refresh
12. ip_security
13. cloud_provider
14. user_agent
15. rate_limit
16. suspicious_activity
17. custom_request

A default `SecurityConfig()` with no route decorators registered builds only `route_config`, `ip_security`, `rate_limit`, and `suspicious_activity`; a configuration that enables every feature builds all 17. `enable_dynamic_rules=True` keeps `emergency_mode`, `cloud_ip_refresh`, `cloud_provider`, `user_agent`, `rate_limit`, and `suspicious_activity` regardless of every other flag, because `DynamicRuleManager` can mutate the flags those checks key off at runtime. `ip_security` never overrides `applies_to`, so it always builds: it fronts a ban lookup whose store is writable from behavior-rule bans and from other processes sharing the same Redis, so no configuration can prove it unreachable. When the registered route configuration cannot be enumerated (`route_configs is None`), every route-driven check is kept rather than dropped, so an adapter that cannot expose `guard_decorator` loses the build-time optimization but never loses the protection. The first check returning a non-`None` `GuardResponse` short-circuits and blocks; order matters, since earlier checks set up state later checks depend on. A check returning `None` means pass. On a check exception, `fail_secure` decides block-with-500 vs continue. See [the pipeline reference](references/pipeline.md).

## Detection Engine

`guard_core.detection_engine` exposes four components, orchestrated by `SusPatternsManager` (in `guard_core.handlers.suspatterns_handler`).

```python
from guard_core.detection_engine import (
    PatternCompiler,
    ContentPreprocessor,
    SemanticAnalyzer,
    PerformanceMonitor,
)
from guard_core.handlers.suspatterns_handler import SusPatternsManager
from guard_core.detection_result import DetectionResult
```

`SusPatternsManager.detect(content, ip_address, context="unknown", correlation_id=None, enabled_categories=None) -> dict[str, Any]` is the primary entry point. It preprocesses (up to 16 decode iterations: URL, HTML entities, base64, hex, Unicode escapes; then a final SQL-comment strip and null-byte strip), matches 148 regex patterns across 19 categories with context filtering, runs a multi-metric semantic score, and returns a threat dict. Detection also scans query-parameter, header, and JSON-key/form-field/multipart-part *names*, not only values, up to `detection_max_scan_values` values per request.

The 19 detection categories (`ALL_DETECTION_CATEGORIES`): `xss`, `sqli`, `dir_traversal`, `path_traversal`, `cmd_injection`, `file_inclusion`, `ldap`, `xml`, `ssrf`, `nosql`, `file_upload`, `template`, `http_split`, `sensitive_file`, `cms_probing`, `recon`, `proto_pollution`, `code_injection`, `deserialization`.

ReDoS protection: `validate_pattern_safety` rejects patterns whose probes exceed 50ms or hit known dangerous constructs. Built-in (compile-time-vetted) patterns match directly with no per-match timeout; only custom patterns added via `add_pattern(..., custom=True)` run through the shared thread-pool safe-matcher with a timeout. Four consecutive timeouts recycle the pool.

See [the detection reference](references/detection.md) for the detect return shape, `DetectionResult`, semantic scoring, and tuning knobs.

## Telemetry

Two tiers. Raw is free and standards-based; enriched is guard-agent-gated.

| Tier | Gate | What exporters see |
|---|---|---|
| Raw | `enable_otel=True` and/or `enable_logfire=True` | All event types, all metrics, W3C traceparent continuation, muting. No `guard.*` enrichment. |
| Enriched | `enable_agent=True` + `enable_enrichment=True` | Raw plus `guard.project_id`, `guard.service.name`, `guard.deployment.environment`, `guard.threat_score`, `guard.rule.id`/`version`, `guard.behavior.correlation_key`/`recent_event_count`. |

`enable_enrichment=True` without `enable_agent=True` raises `ValidationError`.

Mute via `muted_event_types`, `muted_metric_types`, `muted_check_logs` (validated sets; unknown values raise `ValidationError` listing valid values). Valid values: `EVENT_TYPE_VALUES` (34), `METRIC_TYPE_VALUES` (3: `error_rate`, `request_count`, `response_time`), `CHECK_NAME_VALUES` (17, matching the pipeline order above).

See [the telemetry reference](references/telemetry.md) for the full config surface, enrichment field sources, and exporter wiring.

## Footguns

* **Logfire + Pydantic instrumentation is muted once telemetry is actually enabled, not at import.** A host app calling `logfire.instrument_pydantic()` would otherwise emit one span per `SecurityEvent`/`SecurityMetric` validation and one per `EventBatch` re-validation on every flush (hundreds of thousands of spans/day under real traffic). `guard_core._pydantic_plugin_mute.get_telemetry_model()` is the supported way to reach a guard-agent telemetry model class: it mutes first and returns the class second. Three repository checks back that up, and only the third proves the property that matters. An AST scan rejects the known shapes -- a plain import, an aliased import, a submodule import followed by attribute access, and the `importlib.import_module`/`__import__` indirection builtins -- from any module outside a two-file allowlist (`_pydantic_plugin_mute.py` itself, and `models.py` for `AgentConfig` alone, which is not a telemetry model), but only at edit time, only for a literal module name, and only over source that exists on disk. A `sys.meta_path` finder installed for the whole test session records the caller of every `guard_agent` import the interpreter actually resolves and fails the session if one outside that same allowlist ever ran -- but `sys.meta_path` is consulted only on a `sys.modules` cache miss, and the allowlisted mute module is normally the first thing in a session to import `guard_agent` legitimately, so in practice the finder only ever gets a chance to catch the *first* importer; every import after that, dynamic or not, is served from the cache and invisible to it, 100% coverage notwithstanding. What actually holds is a `pytest_sessionfinish` assertion in `tests/conftest.py`: if `guard_agent` is in `sys.modules` at session end, `SecurityEvent`/`SecurityMetric`/`EventBatch` must each carry `plugin_settings == {"logfire": {"record": "off"}}`, read straight out of `sys.modules` so the check cannot cause the import it is testing for. That property does not care how the import happened, only whether it ended up muted; with the suite at 100% coverage that is a real claim about this run, not a universal guarantee. `SecurityConfig.to_agent_config()` (the `enable_agent=True` path) and `HandlerInitializer.initialize_agent_integrations()` (the `enable_otel`/`enable_logfire`/`enable_enrichment` path, which can wire a telemetry-capable handler with no agent at all) both call the underlying idempotent mute directly too, since they are the points a configuration first needs `guard_agent` at all: the mute lands there rather than at `import guard_core`, and a configuration with all of `enable_agent`/`enable_otel`/`enable_logfire`/`enable_enrichment` off never pays the `guard-agent`/`cryptography` import cost. **Caveat:** a host application that constructs `SecurityEvent`/`SecurityMetric`/`EventBatch` through its own path outside guard-core is not covered by any of guard-core's three checks, but it is not left unmuted either: guard-agent 2.8.0 and later apply the identical mute from their own `__init__`, so importing `guard_agent` at all covers that path. Only a host pinning guard-agent below 2.8.0 and building those models outside guard-core has to mute them itself. See [the telemetry reference](references/telemetry.md) for the postmortem detail.
* **`fail_secure=True` by default.** A buggy check surfaces as 500s, not silent bypasses. Keep the default and fix the check; do not flip to fail-open without reason.
* **Redis defaults to on.** `enable_redis=True` with `redis://localhost:6379`. Set `enable_redis=False` if there is no Redis, or every stateful check will try to connect.
* **`enable_enrichment=True` requires `enable_agent=True`.** Mismatch raises `ValidationError` at config time.
* **`guard_agent` is optional.** `import guard_agent` failures are swallowed; the mute function and the agent handler no-op gracefully. Do not assume guard-agent is present.
* **A missing client address is rejected, not silently let through.** When `request.client_host` is `None`, `BypassHandler.handle_passthrough` (`guard_core/core/bypass/handler.py`) resolves an identity via `extract_client_ip`; if that resolves to `"unknown"` (`UNKNOWN_CLIENT_IDENTITY`, `guard_core/_utils/ip_extraction.py`), `fail_secure=True` (the default) returns 403 before the security pipeline runs at all, and `fail_secure=False` continues with identity `"unknown"`. Excluded paths still pass through first, unaffected. A deployment behind a Unix domain socket needs the literal `"unix"` token in `trusted_proxies` so `X-Forwarded-For` still resolves the real client instead of every request being treated as clientless; without it, `extract_client_ip` returns `"unknown"` outright. Both outcomes log a one-time warning. The `"unknown"` identity is allowed through global IP/country and route-level IP/country checks unless a global `whitelist`, `whitelist_countries`, a route `ip_whitelist`, or a route `whitelist_countries` is configured (`guard_core/_utils/access_control.py`, `guard_core/core/checks/helpers.py`).
* **`PerformanceMonitor.get_summary_stats`, `get_slow_patterns`, and `get_problematic_patterns` are coroutines in the async tree.** A caller must `await` them (`guard_core/detection_engine/monitor.py`); the `guard_core.sync` mirror keeps all three as plain synchronous methods.
* **`ban_ip` refuses to ban loopback or a configured trusted-proxy address.** It logs a warning and returns instead of banning, since banning either would self-DoS the deployment; there is no opt-out (`guard_core/handlers/_ipban_bans.py`). Banning a private, non-loopback address (e.g. `10.0.0.5`) that is *not* listed in `trusted_proxies` still bans it, but logs a loud, separate warning that the address may be a reverse proxy and the ban could block every user, since an unset `trusted_proxies` behind a real reverse proxy is the likely cause. `ban_ip`, `is_ip_banned`, and `unban_ip` all canonicalise the address before storing, querying, or deleting it (`_canonicalize_ip`, `guard_core/handlers/_ipban_bans.py:149`, `guard_core/handlers/_ipban_queries.py:43,66`), so banning and unbanning the same address under a different spelling (compressed vs expanded IPv6, an IPv4-mapped IPv6 form) hits the same key.
* **Three previously-silent misconfigurations now warn at construction.** A `trusted_proxies` entry that is a `/0` network (`0.0.0.0/0`, `::/0`) trusts every peer to set `X-Forwarded-For`; a `whitelist` entry that is a `/0` network whitelists every address, so `blacklist`, `blocked_countries` and IP bans can never block anyone (precedence is unchanged, a `/0` whitelist still allows everyone, this is a signal only); an empty `enabled_detection_categories` with `enable_penetration_detection=True` runs detection that can never match anything. All three still succeed, but now log a `WARNING` on the `guard_core.models` logger (`guard_core/_security_config_validators.py`, wired into `SecurityConfig` in `guard_core/models.py`).
* **`require_auth`/`api_key_auth` need a resolvable verifier.** Supply one per route (`verifier=`) or globally (`SecurityConfig.auth_verifier`); without one, every request on that route 401s fail-closed (`guard_core/core/checks/implementations/authentication.py`). The verifier contract is `verifier(request, credential) -> Principal | None`; a raising verifier is also treated as a failed authentication. `require_authorization_header(scheme=...)` (`guard_core/decorators/authentication.py`) is a separate, presence/scheme-only decorator that does NOT authenticate and cannot be combined with `require_auth`/`api_key_auth` on the same route.
* **`@bypass` filters unknown check names instead of silently storing them.** `bypass()` accepts only the tokens `should_bypass_check` actually recognizes (`VALID_BYPASS_CHECKS`, exported from `guard_core.models`: `"all"`, `"ip_ban"`, `"ip"`, `"clouds"`, `"rate_limit"`, `"penetration"`); anything else is dropped with a warning. Before 3.15.1 a typo like `@bypass(["rate_limit", "geo_check"])` silently stored the bad token where it had no effect, so the intended check stayed fully enforced while looking disabled. The `security_bypass` middleware event's `bypassed_checks` payload therefore reports only recognized tokens; a caller who passed extra labels for bookkeeping no longer sees them there.
* **The JSON-body walk is bounded by depth, and a `RecursionError` from the detection engine now fails secure instead of falling back.** `detection_max_json_depth` (default `32`) caps how deep `_scan_json_value` (`guard_core/_utils/body_content_scan.py`) descends into a nested JSON body; the walk itself is an explicit-stack iteration with no Python recursion, so it cannot raise `RecursionError` regardless of body depth. `_check_value_enhanced` (`guard_core/_utils/detection_scan.py`) now re-raises a `RecursionError` surfaced from the detection engine instead of catching it in the same broad `except Exception` used for every other detection failure, so it reaches the pipeline's `fail_secure` handling rather than ever being treated as a clean scan (GHSA-f6cf-jjhc-qp85, CWE-674).
* **A deeply-braced query param, header, or form value cannot crash embedded-JSON detection.** The embedded-JSON bridge `_check_embedded_json` (`guard_core/_utils/embedded_json_scan.py`) looks for a JSON object or array embedded inside a single non-body value and hands it to the body walker `_scan_json_value` (`guard_core/_utils/body_json_scan.py`); it catches `RecursionError` from `json.loads` the same way it catches `json.JSONDecodeError`, treats the value as not-embedded-JSON, and falls through to the ordinary raw-value pattern scan instead of letting the exception escape `detect_penetration_attempt`. This is the former `_check_json_fields`/`_try_check_json_value` pair (`guard_core/_utils/detection_scan.py`), replaced in 4.0.0 by the current bridge when the module split removed both with no alias.
* **The rate limiter now honors `redis_fail_open` on a Redis failure instead of always falling back silently.** `_redis_request_count` (`guard_core/handlers/ratelimit_handler.py`, both `check_rate_limit` and `check_rate_limit_by_ip`) used to catch every Redis error itself and fall back to the in-memory window no matter what `redis_fail_open` said, so a Redis outage silently turned a shared, cross-worker rate limit into a per-process one (N workers effectively multiplying `rate_limit` by N). `redis_fail_open=True` still falls back, but now logs a `WARNING` once per process instead of an `ERROR` on every request; `redis_fail_open=False` (the default) raises `GuardRedisError`, which `SecurityCheckPipeline._handle_check_error` turns into the same `fail_secure` decision as any other check's Redis failure.
* **A `trusted_proxy_depth` that over-counts the real proxy hops no longer lets a client rotate its resolved identity.** `extract_client_ip` (`guard_core/_utils/ip_extraction.py`) selects `ips[-trusted_proxy_depth]` from `X-Forwarded-For`; when `trusted_proxies` is non-empty it now also verifies every entry to the right of that selection is itself a listed trusted proxy (canonicalised, so an IPv4-mapped or bracketed IPv6 spelling of a trusted proxy is recognised). If a chain has fewer real proxy hops than the declared depth, a client supplying extra entries used to control which one landed at the selected position, rotating freely with no warning, because the selected entry is an ordinary public address, not itself a trusted proxy (the two 3.14.0 chain warnings do not cover this). guard-core now logs one warning per process naming `trusted_proxy_depth`, the count of untrusted entries, and the fix, and resolves the client by walking the chain right to left, returning the first entry that is not a listed trusted proxy. Nothing changes when `trusted_proxies` is empty, when the chain is shorter than the declared depth, or when every entry to the right of the selection is already trusted (GHSA-8xvm-856x-7hwp, claim 1 residual).
* **An `X-Forwarded-For` entry carrying a port is no longer discarded.** `1.2.3.4:5678` and `[2001:db8::1]:5678` used to fail `ip_address()` parsing outright, silently falling back to the connecting peer for the whole header; `_strip_forwarded_entry_port` (`guard_core/_utils/ip_extraction.py`) now strips a trailing port from each comma-separated entry before parsing, resolving to `1.2.3.4` and `2001:db8::1` respectively. The strip only fires for a bracketed `[v6]:port` shape or an entry with exactly one colon, so a bare IPv6 address (always two or more colons) is never mistaken for `host:port`; an entry that looks like `host:port` but has a non-numeric or missing port is left untouched and still fails parsing through the existing malformed-entry path.
* **`detect_penetration_attempt(request, config)` auto-configures the detection singleton, and a body over `detection_max_body_inspect_bytes` is scanned through a bounded reader when the adapter has one, instead of always being skipped.** A direct caller that never called `sus_patterns_handler.configure(config)` first used to run the legacy per-pattern thread-pool dispatch, an order of magnitude slower than the enhanced path and with different detection results on some payloads; `detect_penetration_attempt` now configures the singleton from `config` itself whenever it is unconfigured or was last configured from a different config object (compared by identity, cheap once already configured), so a direct caller (guard-core-mcp's `check_payload`, a PoC script, a test) measures and detects the same thing production does. Separately, `_read_capped_body` (`guard_core/_utils/body_reader.py`) no longer unconditionally returns `None` (skipping the body entirely) when the declared `Content-Length` exceeds `detection_max_body_inspect_bytes`: when the request implements the bounded reader (`read_body_prefix`), it reads only the first `detection_max_body_inspect_bytes` bytes through it and scans that prefix, keeping the single-memory-bound guarantee; when the request has no bounded reader, the body is still not read at all, since reading it any other way would mean buffering the whole oversized body first. Either way a one-time warning names the cap, the client, and which of the two happened. A new `SecurityConfig.detection_max_scan_chars` (default `65536`) bounds total scanned characters per request as a leaky bucket: a value already in progress when checked is always scanned in full, so this cap alone cannot cause a silent skip of an in-progress value -- only a value starting after the budget is already spent is skipped, with a one-time warning (GHSA-3hfx-8m47-5f9h residual).

## Sync mirror

`guard_core.sync.*` is generated from `guard_core.*` via unasync (`make sync` in the repo). Never hand-edit files under `guard_core/sync/`; edit the async source and regenerate. If you are reading behavior, read the async tree and trust the sync mirror to match.

## Tooling

The repo uses uv, Ruff, mypy, pytest (with `pytest-asyncio`, `asyncio_mode="auto"`), and a 100% coverage gate (`make local-test`). Run the full suite before claiming green; subset runs have shipped cross-file contract bugs. Integration tests are marked `integration` and skipped by default.

## Related Projects

* [fastapi-guard](https://github.com/Guard-Core/fastapi-guard): ASGI middleware adapter for FastAPI.
* [flaskapi-guard](https://github.com/Guard-Core/flaskapi-guard): Flask extension adapter over the sync mirror.
* [djapi-guard](https://github.com/Guard-Core/djapi-guard): Django middleware adapter over the sync mirror.
* [tornadoapi-guard](https://github.com/Guard-Core/tornadoapi-guard): Tornado handler/middleware adapter.
* [guard-agent](https://github.com/Guard-Core/guard-agent): Telemetry and monitoring agent the adapters ship events with.
* [guard-core-mcp](https://github.com/Guard-Core/guard-core-mcp): MCP server answering Guard questions from the installed libraries.
* [guard-core-app](https://github.com/Guard-Core/guard-core-app): SaaS platform the agent reports to (API, dashboard, playground).
