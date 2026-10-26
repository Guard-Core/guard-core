---

title: Security Pipeline - Guard Core
description: Deep dive into the SecurityCheckPipeline chain of responsibility, the applies_to build-time elimination mechanism, all 17 security checks in catalogue order, the SecurityCheck base class, and extending the pipeline
keywords: guard-core, security pipeline, chain of responsibility, security checks, SecurityCheck, SecurityCheckPipeline
---

Security Pipeline
=================

The security pipeline is the heart of guard-core. It implements the **chain of responsibility** pattern: an ordered list of `SecurityCheck` instances, executed sequentially for every request. The first check that returns a non-`None` response short-circuits the pipeline and blocks the request.

___

SecurityCheckPipeline
---------------------

**Location**: `guard_core/core/checks/pipeline.py`

```python
class SecurityCheckPipeline:
    def __init__(
        self,
        checks: list[SecurityCheck],
        muted_check_logs: set[str] | None = None,
        *,
        config: SecurityConfig | None = None,
        rebuild_checks: Callable[[], list[SecurityCheck]] | None = None,
        watched_container_fields: tuple[str, ...] | None = None,
        route_config_revision: Callable[[], int | None] | None = None,
    ) -> None:
        self.checks = checks
        self.muted_check_logs = muted_check_logs or set()
        self.logger = logging.getLogger(__name__)
        self._config = config
        self._rebuild_checks = rebuild_checks
        self._watched_container_fields = watched_container_fields or ()
        self._route_config_revision = route_config_revision
        self._rebuild_lock = threading.Lock()
        self._built_revision = config.revision if config is not None else None
        self._built_signature = (
            self._container_signature(config) if config is not None else ()
        )
        self._built_route_config_revision = self._current_route_config_revision()

    async def execute(self, request: GuardRequest) -> GuardResponse | None:
        try:
            self._rebuild_if_stale()
        except Exception as e:
            response = await self._handle_rebuild_error(request, e)
            if response is not None:
                return response

        for check in self.checks:
            try:
                response = await check.check(request)
                if response is not None:
                    if check.check_name not in self.muted_check_logs:
                        self.logger.debug(
                            f"Request blocked by {check.check_name}",
                            extra={
                                "check": check.check_name,
                                "path": request.url_path,
                                "method": request.method,
                            },
                        )
                    return response

            except Exception as e:
                error_response = await self._handle_check_error(check, request, e)
                if error_response is not None:
                    return error_response

        return None
```

`_handle_check_error` logs the exception (unless the check is in `muted_check_logs`), skips the check and returns `None` when it is a `GuardRedisError` and `config.redis_fail_open` is `True`, and otherwise blocks when `config.fail_secure` is `True`, with a 503 and `Retry-After: 5` for a `GuardRedisError` and a 500 for any other error -- the same fail-secure decision shown in [Fail-Open vs Fail-Secure](#fail-open-vs-fail-secure) below, just factored into its own method. The generic `"Request blocked by {check.check_name}"` summary line logs at `DEBUG`, not `INFO`: every check that can block already logs its own detailed, configurable-level line before returning, so this line is a secondary trace, not the primary block-decision log.

### Config-Revision Rebuild

`SecurityConfig` bumps a private, monotonically increasing revision counter on every attribute assignment (an overridden `__setattr__`; the counter itself is a Pydantic `PrivateAttr`, so it never appears in `model_fields`, `model_dump()`, equality, or the constructor). `build_default_pipeline` passes the pipeline the `SecurityConfig` it built from, a closure that reruns `applies_to` over `DEFAULT_CHECK_CLASSES`, and `factory.WATCHED_CONTAINER_FIELDS`. `execute()` calls `_rebuild_if_stale()` first, which compares the config's current revision against the revision the pipeline was last built at; if the revision moved, it rebuilds outright without looking any further. If it did not move, it computes a size signature -- `len()` on each watched container, with `None` counted as `0` and no allocation -- and compares that against the signature recorded at the last build, rebuilding only if that moved too. When neither has moved this is one integer comparison plus a handful of `len()` calls, not a config fingerprint. When either has moved, it calls the closure, reassigns `self.checks` to the freshly filtered list it returns, and records the new revision and signature, so a config mutated -- by whole-value assignment or by mutating one of the watched containers in place -- after the pipeline was built takes effect on the next request instead of staying silently stale.

The watched fields are `blocked_user_agents`, `block_cloud_providers`, and `endpoint_rate_limits` -- every mutable container any `applies_to` predicate reads, and nothing else needs watching: `blocked_countries`/`whitelist_countries` are `frozenset`, every feature flag is a `bool`, and every predicate reads these three containers as `bool(...)` alone, never by content, so a predicate's answer can only change when a container crosses between empty and non-empty, which is exactly what a size signature catches. `blacklist` and `whitelist` are also mutable containers on `SecurityConfig`, but no `applies_to` reads either one -- `IpSecurityCheck` never overrides `applies_to` and is therefore always built regardless of their contents -- so they are correctly absent from the watched set. That set is not a second hardcoded list: `SecurityCheck.container_fields: ClassVar[tuple[str, ...]]` is a class attribute each check declares next to its own `applies_to` (empty by default), and `factory.WATCHED_CONTAINER_FIELDS` is the union of `container_fields` across `DEFAULT_CHECK_CLASSES`, computed once at import time. A predicate that starts reading a new mutable container is watched the moment its check class says so; nothing elsewhere has to change.

The rebuild always constructs a brand-new list and swaps it into `self.checks` with a single attribute assignment rather than mutating the existing list in place, and `execute()`'s `for check in self.checks` loop captures that list reference once, at the start of the call. A request already in flight therefore keeps running against the snapshot it started with even if a concurrent request or the dynamic-rules background task bumps the revision and triggers a rebuild mid-flight.

`_rebuild_if_stale()` captures the revision, the container signature, and `muted_check_logs` from `config` *before* calling the rebuild closure, then publishes all four together with the rebuilt checks under a `threading.Lock` scoped to the publish alone -- never to the closure call itself, so a rebuild storm never serializes the request path. Two callers can still both rebuild redundantly from a similarly-stale read; that costs CPU, not correctness, since whichever caller's publish lands last stamps *its own* captured revision and signature, not whatever the live config has moved to by the time its build finished. A caller that built from stale state can therefore only ever record that it built from stale state -- it can never publish a check list and then stamp it with a revision/signature that makes the pipeline believe it is current when it is not -- so the next call to `_rebuild_if_stale()` sees the mismatch and rebuilds again. Before this guarantee existed, the revision and signature were read from the live `config` *after* the rebuild closure returned rather than captured before it started; that ordering is safe in the async tree, where `_rebuild_if_stale()` contains no `await` and always completes within a single, uninterruptible coroutine turn, but it was a genuine lost-update race in the generated sync tree, whose `DynamicRuleManager` mutates the watched config fields from a real background `threading.Thread`. The steady-state comparison in `_is_stale()` never takes the lock, so the cost of a request that finds nothing stale is unchanged.

A pipeline constructed directly as `SecurityCheckPipeline(checks)` -- the form every adapter and [the testing guide](../adapters/testing.md) use -- has no `config`/`rebuild_checks` reference and so never rebuilds, exactly as it did before this mechanism existed.

### Route-Config Revision Rebuild

`BaseSecurityDecorator` holds a `RouteConfigRevision` counter -- its own mutable cell, independent of `SecurityConfig._revision` -- that starts at zero for every decorator instance. `RouteConfig.__setattr__` bumps that counter on every attribute assignment except during `__init__` itself, gated behind a private `_initialized` flag that only flips `True` after the constructor's own ~25 field assignments finish, so decorating a fresh route touches the counter zero times for its own defaults, the same way `SecurityConfig`'s Pydantic-populated `__init__` never touches its overridden `__setattr__`. `_ensure_route_config` is the single insertion point for `_route_configs`; the counter is also bumped there explicitly, the moment a route id is first seen, so a route decorated after the pipeline was already built is observable on its own, independent of whatever attribute assignment the calling decorator makes next. `build_default_pipeline` reads `middleware.guard_decorator.route_config_revision` through a `route_config_revision` callable it hands the pipeline alongside `config` and `watched_container_fields`; `_is_stale()` compares that against the value recorded at the last build as one more integer comparison after the existing two, so the hot path stays O(1) in the number of watched fields and never touches `_route_configs` itself -- comparing container sizes across every route config on every request would make the steady-state cost proportional to route count, which the counter design avoids entirely. When `middleware.guard_decorator` is `None` the callable returns `None` on both sides of the comparison, so a middleware with no decorator handle behaves exactly as before this mechanism existed.

In-place mutation of a container *inside* a `RouteConfig` -- `route_config.custom_validators.append(...)`, `route_config.required_headers["X-Api-Key"] = "required"` -- does not go through `RouteConfig.__setattr__` any more than `config.blocked_user_agents.append(...)` goes through `SecurityConfig.__setattr__`. Ten checks read a `RouteConfig` field as `bool(...)` or `is not None`: six purely route-driven (`authentication`, `custom_validators`, `referrer`, `request_size_content`, `required_headers`, `time_window`) and four whose predicate also has a `SecurityConfig`-level or `enable_dynamic_rules` escape hatch (`cloud_provider`, `cloud_ip_refresh`, `rate_limit`, `user_agent`) -- all ten read the same truthiness-only pattern the `SecurityConfig` side relies on, so the fix takes the same shape but a different form for every one of them: recomputing a length signature across every route config on every request would scale with route count, which the hot-path constraint rules out, so instead `RouteConfig.__setattr__` wraps values assigned to every mutable-container field any of the ten reads -- `custom_validators`, `require_referrer`, `allowed_content_types`, `blocked_user_agents` (lists), `required_headers`, `time_restrictions`, `geo_rate_limits` (dicts), and `block_cloud_providers` (a `set`) -- in a `list`/`dict`/`set` subclass whose mutating methods bump the same shared counter directly, in the method call itself, rather than being detected by scanning afterward: `append`, `extend`, `insert`, `remove`, `pop`, `clear`, `sort`, `reverse`, `__setitem__`, `__delitem__`, `__iadd__`, `__imul__` for the list subclass; `__setitem__`, `__delitem__`, `update`, `setdefault`, `pop`, `popitem`, `clear`, `__ior__` for the dict subclass; `add`, `discard`, `remove`, `pop`, `clear`, `update`, `intersection_update`, `difference_update`, `symmetric_difference_update`, `__ior__`, `__iand__`, `__isub__`, `__ixor__` for the set subclass. The non-augmented counterparts (`__add__`/`__mul__` on the list subclass, `__or__` on the dict subclass, `__or__`/`__and__`/`__sub__`/`__xor__` on the set subclass) each return a new, untracked object without touching `self`, exactly like the builtin they wrap, and correctly leave the counter alone. Wrapping happens unconditionally, including for the empty `[]`/`{}`/`set()` the constructor assigns, so the very first container object a decorator gets back from `_ensure_route_config` is already tracked -- deferring wrapping until after `_initialized` would leave that first container, the one most decorators mutate in place, permanently unobserved. `max_request_size` and `auth_required` are read by the same predicates but are `int | None` and `str | None`; both are immutable, so whole-value assignment -- already covered -- is the only way either changes. `block_cloud_providers`, `geo_rate_limits`, and `blocked_user_agents` having an additional `SecurityConfig`-level or dynamic-rules escape hatch only means a route config with all three empty can still keep the check for a reason unrelated to that route; it does not change how `route_config.block_cloud_providers.add("AWS")` behaves, since the predicate still consults the route config's own field by truthiness like the other seven.

### Execution Semantics

1. Checks run **sequentially** in insertion order
2. A check returning `None` means "pass -- continue to next check"
3. A check returning a `GuardResponse` means "block -- stop pipeline and return this response"
4. If a check raises an exception, the pipeline catches it and either continues (fail-open) or blocks (fail-secure)
5. If all checks return `None`, the pipeline returns `None`, meaning the request is allowed

### Pipeline Management Methods

| Method | Signature | Description |
|---|---|---|
| `execute` | `async (request: GuardRequest) -> GuardResponse \| None` | Run all checks against the request |
| `add_check` | `(check: SecurityCheck) -> None` | Append a check to the end of the pipeline |
| `insert_check` | `(index: int, check: SecurityCheck) -> None` | Insert a check at a specific position |
| `remove_check` | `(check_name: str) -> bool` | Remove a check by name. Returns `True` if found |
| `get_check_names` | `() -> list[str]` | List all check names in execution order |
| `__len__` | `() -> int` | Number of checks in the pipeline |

___

SecurityCheck Base Class
------------------------

**Location**: `guard_core/core/checks/base.py`

Every security check extends this abstract base class:

```python
class SecurityCheck(ABC):
    requires: ClassVar[tuple[str, ...]] = ()
    container_fields: ClassVar[tuple[str, ...]] = ()

    def __init__(self, middleware: "GuardMiddlewareProtocol") -> None:
        self.middleware = middleware
        self.config = middleware.config
        self.logger = middleware.logger

    @classmethod
    def applies_to(
        cls,
        config: "SecurityConfig",
        route_configs: "Collection[RouteConfig] | None",
    ) -> bool:
        return True

    @abstractmethod
    async def check(self, request: GuardRequest) -> GuardResponse | None:
        pass

    @property
    @abstractmethod
    def check_name(self) -> str:
        pass

    async def send_event(
        self,
        event_type: str,
        request: GuardRequest,
        action_taken: str,
        reason: str,
        **kwargs: Any,
    ) -> None:
        await self.middleware.event_bus.send_middleware_event(
            event_type=event_type,
            request=request,
            action_taken=action_taken,
            reason=reason,
            **kwargs,
        )

    async def create_error_response(
        self, status_code: int, default_message: str
    ) -> GuardResponse:
        return await self.middleware.create_error_response(status_code, default_message)

    def is_passive_mode(self) -> bool:
        return self.config.passive_mode
```

### What a Check Must Implement

| Member | Type | Description |
|---|---|---|
| `check_name` | `@property -> str` | A unique identifier for the check (e.g. `"ip_security"`, `"rate_limit"`) |
| `check(request)` | `async -> GuardResponse \| None` | The check logic. Return `None` to pass, or a `GuardResponse` to block |

### What a Check May Override

| Member | Type | Default | Description |
|---|---|---|---|
| `applies_to(config, route_configs)` | `@classmethod -> bool` | Returns `True` unconditionally | Declares, at pipeline-build time, whether the effective configuration can ever make this check fire. See [Build-Time Elimination](#build-time-elimination) below. |
| `requires` | `ClassVar[tuple[str, ...]]` | `()` | Names the packaging extra(s) the check's handler needs (for example `("cloud",)` on `CloudProviderCheck`). |
| `container_fields` | `ClassVar[tuple[str, ...]]` | `()` | Names the mutable `SecurityConfig` container field(s) this check's `applies_to` reads (for example `("endpoint_rate_limits",)` on `RateLimitCheck`). `factory.WATCHED_CONTAINER_FIELDS` is the union of this attribute across `DEFAULT_CHECK_CLASSES`; see [Config-Revision Rebuild](#config-revision-rebuild) above. |

A check that does not override `applies_to` always runs, because the base implementation returns `True`.

### What a Check Gets for Free

| Method | Description |
|---|---|
| `self.middleware` | Access to the `GuardMiddlewareProtocol` instance (event bus, route resolver, handlers) |
| `self.config` | Direct access to `SecurityConfig` |
| `self.logger` | The middleware's logger |
| `send_event(...)` | Shortcut for `self.middleware.event_bus.send_middleware_event(...)` |
| `create_error_response(status_code, message)` | Shortcut for `self.middleware.create_error_response(...)` |
| `is_passive_mode()` | Whether the engine is in passive (log-only) mode |

___

Build-Time Elimination
-----------------------

**Location**: `guard_core/core/checks/factory.py`

`build_default_pipeline` filters the 17-check catalogue (`DEFAULT_CHECK_CLASSES`) through each check class's `applies_to(config, route_configs)` classmethod before instantiating anything, so a deployment only builds and runs the checks its configuration can actually trigger:

```python
def _build_checks(
    middleware: "GuardMiddlewareProtocol",
) -> list[SecurityCheck]:
    config = middleware.config
    route_configs = _collect_route_configs(middleware)
    return [
        cls(middleware)
        for cls in DEFAULT_CHECK_CLASSES
        if cls.applies_to(config, route_configs)
    ]


def build_default_pipeline(
    middleware: "GuardMiddlewareProtocol",
) -> SecurityCheckPipeline:
    config = middleware.config
    return SecurityCheckPipeline(
        _build_checks(middleware),
        muted_check_logs=config.muted_check_logs,
        config=config,
        rebuild_checks=lambda: _build_checks(middleware),
    )


def _collect_route_configs(
    middleware: "GuardMiddlewareProtocol",
) -> Collection[RouteConfig] | None:
    decorator = getattr(middleware, "guard_decorator", None)
    if decorator is None:
        return None
    return tuple(decorator._route_configs.values())
```

This filtering happens once, when the pipeline is built (lazily, on the first request, after route registration completes). It does not re-run on every single call to `execute()`: a check's presence in the pipeline reflects the configuration as of the last build, not necessarily the configuration at this exact instant. But it does re-run the moment `execute()` notices the config has moved since that build -- see [Config-Revision Rebuild](#config-revision-rebuild) above -- so mutating `SecurityConfig` after the pipeline exists now does add or remove checks from that pipeline, on the next request through it. `enable_dynamic_rules=True` (see below) remains the way to keep every dynamically-relevant check present regardless of what the rest of the config says; it is not the only way to get a runtime change to take effect, but the revision-triggered rebuild does not replace its narrower guarantee of "these seven checks are always here" with a broader one -- an app that relies on that guarantee for cloud/user-agent/rate-limit checks it might toggle via `DynamicRuleManager` should keep using it.

### The safety rule

Elimination is strictly an optimization, never a security decision. The base `applies_to` implementation returns `True`, so any check that does not override it always runs unconditionally. Every real `applies_to` override in the codebase returns `True` on any uncertainty about the effective configuration or the registered routes -- an unknown state is always treated as "keep the check."

### Unknown route configuration means keep everything

`_collect_route_configs` returns `None`, not an empty tuple, when `middleware.guard_decorator` is `None`, meaning the adapter has no decorator handle to enumerate registered routes from. `None` means "unknown"; an empty tuple means "known to be empty, no route carries a decorator." Every route-driven predicate goes through `route_config_applies()` (`guard_core/core/checks/helpers.py`), which returns `True` immediately when `route_configs is None`:

```python
def route_config_applies(
    route_configs: Collection[RouteConfig] | None,
    predicate: Callable[[RouteConfig], bool],
) -> bool:
    if route_configs is None:
        return True
    for route_config in route_configs:
        if predicate(route_config):
            return True
    return False
```

An adapter that cannot enumerate its routes at pipeline-build time therefore loses the elimination optimization for route-driven checks, never the protection those checks provide.

### `enable_dynamic_rules` keeps every dynamically-mutable check

`DynamicRuleManager` can flip `enable_penetration_detection`, `enable_ip_banning`, `enable_rate_limiting`, `emergency_mode`, `endpoint_rate_limits`, `block_cloud_providers`, and `blocked_user_agents` on a live `SecurityConfig`. Setting `config.enable_dynamic_rules = True` keeps every check whose predicate depends on one of those flags, regardless of every other setting: `emergency_mode`, `cloud_ip_refresh`, `cloud_provider`, `user_agent`, `rate_limit`, and `suspicious_activity` each OR `config.enable_dynamic_rules` directly into their predicate. `ip_security` does not need to, because it is never eliminated at all, for the reason below -- so all seven checks a running deployment might turn on through dynamic rules stay in the pipeline once `enable_dynamic_rules=True` is set, whatever the rest of the configuration says.

### `IpSecurityCheck` is never eliminated

`IpSecurityCheck` has no `applies_to` override, so it inherits the base's unconditional `True`. This is deliberate, not an oversight. `check()` calls `_check_banned_ip` first, which calls `ip_ban_manager.is_ip_banned()` unconditionally, gated only by a per-route `should_bypass_check("ip_ban", route_config)` decorator, never by `SecurityConfig.enable_ip_banning`. IPs reach that ban store from `BehaviorTracker._execute_ban_action`, which bans through `ip_ban_manager.ban_ip()` regardless of `enable_ip_banning`, and from any other process sharing the same Redis-backed ban store. No `SecurityConfig` can prove the check unreachable, so it is always built.

### Per-check predicates

| Check | Kept when | Default verdict |
|---|---|---|
| `route_config` | Always (no override; produces `client_ip`, `route_config`) | keep |
| `emergency_mode` | `config.emergency_mode` or `enable_dynamic_rules` | drop |
| `https_enforcement` | `config.enforce_https` or any route requires HTTPS | drop |
| `request_logging` | `config.log_request_level is not None` | drop |
| `request_size_content` | Any route sets `max_request_size` or `allowed_content_types` | drop |
| `cloud_ip_refresh` | `config.block_cloud_providers` is set, any route sets `block_cloud_providers`, or `enable_dynamic_rules` | drop |
| `ip_security` | Always (no override, see above) | keep |
| `cloud_provider` | `config.block_cloud_providers` is set, any route sets `block_cloud_providers`, or `enable_dynamic_rules` | drop |
| `user_agent` | `config.blocked_user_agents` is non-empty, any route sets `blocked_user_agents`, or `enable_dynamic_rules` | drop |
| `rate_limit` | `config.enable_rate_limiting`, `config.endpoint_rate_limits` is set, any route sets `rate_limit`/`geo_rate_limits`, or `enable_dynamic_rules` | keep (`enable_rate_limiting` defaults to `True`) |
| `required_headers` | Any route sets `required_headers` | drop |
| `authentication` | Any route sets `auth_required` | drop |
| `referrer` | Any route sets `require_referrer` | drop |
| `custom_validators` | Any route sets `custom_validators` | drop |
| `time_window` | Any route sets `time_restrictions` | drop |
| `suspicious_activity` | `config.enable_penetration_detection`, any route sets `enable_suspicious_detection`, or `enable_dynamic_rules` | keep (`enable_penetration_detection` defaults to `True`) |
| `custom_request` | `config.custom_request_check is not None` | drop |

"Any route sets X" is `False` when `route_configs` is a known-empty tuple and always `True` when `route_configs is None` (unknown, see above). A default `SecurityConfig()` with no route decorators builds exactly four checks: `route_config`, `ip_security`, `rate_limit`, `suspicious_activity`. Configuring every feature and providing a fully-populated route decorator builds all 17, in the order shown below.

___

All 17 Checks in Execution Order
---------------------------------

The checks are listed here in the fixed order the catalogue defines. This order matters -- earlier checks set up state that later checks depend on. The identity checks (`required_headers`, `authentication`, `referrer`, `custom_validators`, `time_window`) run after `ip_security`, `cloud_provider`, `user_agent` and `rate_limit`, so a banned, blocked or rate-limited client is answered before any verifier or validator runs. A given deployment's pipeline is a subset of this list, filtered by `applies_to` as described above, but the checks that do build always run in this relative order.

### 1. RouteConfigCheck

| | |
|---|---|
| **check_name** | `route_config` |
| **Module** | `guard_core.core.checks.implementations.route_config` |
| **Purpose** | Resolves the route-level decorator configuration and extracts the client IP |
| **Blocks?** | Only under `route_resolution_strict`, when the adapter reports it could not resolve the route -- `404` or `405` (or `500` for a matched route the decorator does not know), body `Route resolution failed` |
| **Side Effects** | Sets `request.state.route_config` and `request.state.client_ip` |

This check runs first because all subsequent checks depend on `request.state.client_ip` and `request.state.route_config`.

### 2. EmergencyModeCheck

| | |
|---|---|
| **check_name** | `emergency_mode` |
| **Module** | `guard_core.core.checks.implementations.emergency_mode` |
| **Purpose** | Blocks all requests, on excluded paths too except those in `config.emergency_exempt_paths`, when `config.emergency_mode = True`, except IPs in `config.emergency_whitelist` (plus `config.whitelist`, `config.exempt_ips` and the `ip_whitelist` entries of the active dynamic rule when `config.emergency_whitelist_only = False`) |
| **Blocks?** | Returns 503 for non-whitelisted IPs (unless passive mode) |

### 3. HttpsEnforcementCheck

| | |
|---|---|
| **check_name** | `https_enforcement` |
| **Module** | `guard_core.core.checks.implementations.https_enforcement` |
| **Purpose** | Redirects HTTP requests to HTTPS when `config.enforce_https = True` or route requires HTTPS |
| **Blocks?** | Returns a redirect to the HTTPS URL: 301 for GET and HEAD, 308 for every other method so the method and body survive |

### 4. RequestLoggingCheck

| | |
|---|---|
| **check_name** | `request_logging` |
| **Module** | `guard_core.core.checks.implementations.request_logging` |
| **Purpose** | Logs the incoming request if `config.log_request_level` is set |
| **Blocks?** | Never. Always returns `None` |

### 5. RequestSizeContentCheck

| | |
|---|---|
| **check_name** | `request_size_content` |
| **Module** | `guard_core.core.checks.implementations.request_size_content` |
| **Purpose** | Validates request body size and content type against route-level `max_request_size` and `allowed_content_types` |
| **Blocks?** | Returns 413 (payload too large) or 415 (unsupported media type) |

### 6. CloudIpRefreshCheck

| | |
|---|---|
| **check_name** | `cloud_ip_refresh` |
| **Module** | `guard_core.core.checks.implementations.cloud_ip_refresh` |
| **Purpose** | Periodically refreshes cloud provider IP ranges based on `config.cloud_ip_refresh_interval` |
| **Blocks?** | Never. Always returns `None` |
| **Side Effects** | Schedules a single-flight background refresh (running `middleware.refresh_cloud_ip_ranges()` off the request path) when the interval has elapsed |

### 7. IpSecurityCheck

| | |
|---|---|
| **check_name** | `ip_security` |
| **Module** | `guard_core.core.checks.implementations.ip_security` |
| **Purpose** | IP ban checks, route-level IP whitelist/blacklist, country-based filtering, and global IP allowlist/blocklist |
| **Blocks?** | Returns 403 (forbidden) |
| **Side Effects** | Sets `request.state.is_whitelisted` (always `False` when `whitelist_access_only` is on, the default since 5.0.0, with `request.state.whitelist_entry` naming the matching entry) |

### 8. CloudProviderCheck

| | |
|---|---|
| **check_name** | `cloud_provider` |
| **Module** | `guard_core.core.checks.implementations.cloud_provider` |
| **Purpose** | Blocks requests originating from cloud provider IP ranges (AWS, GCP, Azure) |
| **Blocks?** | Returns 403 (forbidden) |

### 9. UserAgentCheck

| | |
|---|---|
| **check_name** | `user_agent` |
| **Module** | `guard_core.core.checks.implementations.user_agent` |
| **Purpose** | Filters requests by user agent string against route-level and global blocklists |
| **Blocks?** | Returns 403 (forbidden) |

### 10. RateLimitCheck

| | |
|---|---|
| **check_name** | `rate_limit` |
| **Module** | `guard_core.core.checks.implementations.rate_limit` |
| **Purpose** | Enforces rate limits at four levels: endpoint-specific, route-level, geo-based, and global |
| **Blocks?** | Returns 429 (too many requests) |

!!! note "Rate limit evaluation order"
    The rate limit check evaluates in this priority: endpoint rate limits (from dynamic rules) > route rate limits (from decorators) > geo rate limits (from decorators) > global rate limit (from config). The first limit that is exceeded blocks the request.

### 11. RequiredHeadersCheck

| | |
|---|---|
| **check_name** | `required_headers` |
| **Module** | `guard_core.core.checks.implementations.required_headers` |
| **Purpose** | Validates that required headers are present with expected values (from route config) |
| **Blocks?** | Returns 400 (bad request) |

### 12. AuthenticationCheck

| | |
|---|---|
| **check_name** | `authentication` |
| **Module** | `guard_core.core.checks.implementations.authentication` |
| **Purpose** | Validates authentication headers (Bearer, Basic, custom) based on route config |
| **Blocks?** | Returns 401 (unauthorized) |

### 13. ReferrerCheck

| | |
|---|---|
| **check_name** | `referrer` |
| **Module** | `guard_core.core.checks.implementations.referrer` |
| **Purpose** | Validates the `Referer` header against route-level allowed domains |
| **Blocks?** | Returns 403 (forbidden) |

### 14. CustomValidatorsCheck

| | |
|---|---|
| **check_name** | `custom_validators` |
| **Module** | `guard_core.core.checks.implementations.custom_validators` |
| **Purpose** | Executes route-level custom validator callables |
| **Blocks?** | Returns whatever the custom validator returns |

### 15. TimeWindowCheck

| | |
|---|---|
| **check_name** | `time_window` |
| **Module** | `guard_core.core.checks.implementations.time_window` |
| **Purpose** | Enforces time-of-day access restrictions from route config |
| **Blocks?** | Returns 403 (forbidden) |

### 16. SuspiciousActivityCheck

| | |
|---|---|
| **check_name** | `suspicious_activity` |
| **Module** | `guard_core.core.checks.implementations.suspicious_activity` |
| **Purpose** | Runs penetration attempt detection against the request URL, headers, query params, and body. Tracks suspicious request counts for auto-ban |
| **Blocks?** | Returns 403 (forbidden) |

### 17. CustomRequestCheck

| | |
|---|---|
| **check_name** | `custom_request` |
| **Module** | `guard_core.core.checks.implementations.custom_request` |
| **Purpose** | Executes the `config.custom_request_check` callable if provided |
| **Blocks?** | Returns whatever the custom check callable returns |

___

Fail-Open vs Fail-Secure
-------------------------

By default, the pipeline is **fail-secure**: if a security check raises an unhandled exception, the pipeline logs the error and blocks the request with an HTTP 500 response so check bugs surface instead of silently passing requests through.

```python
except Exception as e:
    self.logger.error(...)

    if check.config.fail_secure:
        return await check.create_error_response(
            status_code=500,
            default_message="Security check failed",
        )

    continue
```

`fail_secure` is a standard field on the `SecurityConfig` model (`fail_secure: bool = Field(default=True)`). When `True` (the default), any check exception results in a 500 response, blocking the request. Setting `fail_secure = False` opts into fail-open behavior: the pipeline logs the error and falls through to the next check.

A `GuardRedisError` (a Redis outage at request time) answers with the error'"'"'s own 503 status and a `Retry-After: 5` header instead of the 500, so a load balancer or client retries instead of treating the app as broken. Excluded paths still run the ban lookup, so a probe on one sees the 503 during an outage under `fail_secure`; `redis_fail_open=True` is the switch that admits it. Passive mode and `fail_secure=False` admit the request.

!!! tip "Choosing a failure mode"
    Keep fail-secure (the default) in production so check bugs surface as 500s rather than letting unchecked requests through. Set `fail_secure = False` to opt into fail-open behavior, intended only for staging diagnostics where availability is preferred over blocking on a check error.

### Rebuild Failures

`execute()` now wraps the call to `_rebuild_if_stale()` in its own `try`/`except`, ahead of and separate from the one already wrapping each check, so a raising rebuild closure -- a check constructor failing during initialization, for instance -- is routed through the same `fail_secure` decision a check exception gets, not left to propagate out of `execute()` uncaught. Under `fail_secure=True` (the default), a rebuild failure blocks the request with the same 500 `Security check failed` response a failing check produces, built through the still-valid last-known-good `self.checks[0]`'s middleware; a pipeline that has no known-good check at all to build a response through re-raises the original exception instead of silently falling open. `build_default_pipeline` cannot produce that empty pipeline, because `IpSecurityCheck` is never eliminated, but the public `remove_check()` can drain any pipeline down to no checks, so the path is reachable in principle rather than only by hand-constructing an empty one. It still fails closed in practice: an exception escaping `execute()` becomes a 500 in every shipping adapter. Under `fail_secure=False`, the error is logged and the request continues against the last known-good `self.checks` -- the check list the pipeline already knew to be correct before the failed rebuild attempt, not a partially-rebuilt or truncated one, since `self.checks` is only ever reassigned after the rebuild closure returns successfully. Neither path updates the revision/signature bookkeeping on failure, so a transient rebuild failure -- a check constructor that fails once and then succeeds, for example -- is retried, and recovers, on the very next request instead of wedging the pipeline into raising (or silently degrading) forever.

___

Passive Mode
------------

When `SecurityConfig.passive_mode = True`, checks still evaluate fully and log violations, but they return `None` instead of a blocking `GuardResponse`. This is implemented at the individual check level:

```python
if not self.config.passive_mode:
    return await self.middleware.create_error_response(
        status_code=403,
        default_message="Forbidden",
    )

return None
```

Each check is responsible for honoring passive mode. The base class provides `is_passive_mode()` as a convenience method.

___

Adding a Custom Security Check
-------------------------------

To add a new check, create a class extending `SecurityCheck`, then register it in the pipeline.

### Step 1: Create the Check

```python
from guard_core.core.checks.base import SecurityCheck
from guard_core.protocols.request_protocol import GuardRequest
from guard_core.protocols.response_protocol import GuardResponse


class ApiKeyCheck(SecurityCheck):
    @property
    def check_name(self) -> str:
        return "api_key"

    async def check(self, request: GuardRequest) -> GuardResponse | None:
        api_key = request.headers.get("X-API-Key")
        if not api_key:
            await self.send_event(
                event_type="authentication_failed",
                request=request,
                action_taken="request_blocked"
                if not self.is_passive_mode()
                else "logged_only",
                reason="Missing API key",
            )

            if not self.is_passive_mode():
                return await self.create_error_response(
                    status_code=401,
                    default_message="API key required",
                )

        return None
```

### Step 2: Register in the Pipeline

In your adapter's middleware, after building the default pipeline, add the check:

```python
from guard_core.core.checks import build_default_pipeline

pipeline = build_default_pipeline(middleware)

pipeline.add_check(ApiKeyCheck(middleware))

pipeline.insert_check(7, ApiKeyCheck(middleware))
```

### Step 3: (Optional) Make It Removable

Other code can remove your check by name:

```python
pipeline.remove_check("api_key")
```

### Guidelines

- Always honor `self.is_passive_mode()` in your blocking logic
- Use `self.send_event(...)` to emit telemetry for agent integration
- Use `self.create_error_response(...)` instead of constructing responses directly -- this applies custom error messages, security headers, and response modifiers
- Access shared state through `self.middleware` (e.g. `self.middleware.rate_limit_handler`, `self.middleware.geo_ip_handler`)
- Read per-request state from `request.state` (e.g. `request.state.client_ip`, `request.state.route_config`)
