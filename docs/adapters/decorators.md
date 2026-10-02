---

title: Decorator System
description: How guard-core's decorator system provides per-route security configuration, and how adapters expose it to their users.
keywords: guard-core, decorators, RouteConfig, SecurityDecorator, per-route security, access control, rate limiting, behavioral rules
---

Decorator System
================

Overview
--------

Guard-core's decorator system allows users to apply per-route security settings using Python decorators. The system is built on three layers:

1. **`RouteConfig`** -- a data class holding all per-route security settings.
2. **`BaseSecurityDecorator`** -- manages route config storage, route ID generation, and event dispatching.
3. **Mixin classes** -- provide decorator methods grouped by concern (access control, rate limiting, authentication, etc.).
4. **`SecurityDecorator`** -- the final class combining all mixins, ready for use.

RouteConfig
-----------

Defined in `guard_core/decorators/base.py`, `RouteConfig` holds every per-route override:

```python
class RouteConfig:
    def __init__(self, revision: "RouteConfigRevision | None" = None) -> None:
        object.__setattr__(self, "_revision", revision)
        object.__setattr__(self, "_initialized", False)
        self.rate_limit: int | None = None
        self.rate_limit_window: int | None = None
        self.ip_whitelist: list[str] | None = None
        self.ip_blacklist: list[str] | None = None
        self.blocked_countries: list[str] | None = None
        self.whitelist_countries: list[str] | None = None
        self.bypassed_checks: set[str] = set()
        self.require_https: bool = False
        self.auth_required: str | None = None
        self.custom_validators: list[Callable] = []
        self.blocked_user_agents: list[str] = []
        self.required_headers: dict[str, str] = {}
        self.behavior_rules: list[BehaviorRule] = []
        self.block_cloud_providers: set[str] = set()
        self.max_request_size: int | None = None
        self.allowed_content_types: list[str] | None = None
        self.time_restrictions: dict[str, str] | None = None
        self.enable_suspicious_detection: bool = True
        self.require_referrer: list[str] | None = None
        self.api_key_required: bool = False
        self.geo_rate_limits: dict[str, tuple[int, int]] | None = None
        self.excluded_detection_headers: set[str] | None = None
        self.excluded_detection_params: set[str] | None = None
        self.excluded_detection_body_fields: set[str] | None = None
        self.enabled_detection_categories: set[str] | None = None
        self.detection_scan_body: bool | None = None
        object.__setattr__(self, "_initialized", True)

    def __setattr__(self, name: str, value: Any) -> None:
        # Tracked-container fields get wrapped in a list/dict/set subclass
        # whose mutating methods bump `revision` directly (in-place mutation,
        # not just whole-value assignment, triggers a pipeline rebuild).
        object.__setattr__(self, name, value)
        if self._initialized and name not in ("_revision", "_initialized"):
            if self._revision is not None:
                self._revision.bump()
```

`block_cloud_providers` is `set[str]`, not `set[CloudProvider]`: a route-level entry can carry a `":!region"` carve-out suffix the same way `SecurityConfig.block_cloud_providers` can.

When a decorator is applied to a route function, it creates or updates a `RouteConfig` and associates it with that function's route ID. `RouteConfig` is not a passive data holder: its `__setattr__` bumps a `RouteConfigRevision` counter owned by `BaseSecurityDecorator` on every attribute assignment made after construction (the `_initialized` flag keeps the constructor's own ~25 field defaults from bumping it), and wraps every mutable-container field a pipeline predicate reads (`custom_validators`, `require_referrer`, `allowed_content_types`, `blocked_user_agents`, `required_headers`, `time_restrictions`, `geo_rate_limits`, `block_cloud_providers`) in a tracked subclass so in-place mutation (`route_config.custom_validators.append(...)`) bumps the counter too. `SecurityCheckPipeline` compares this counter to detect when a route's configuration changed since the pipeline was last built, and rebuilds; see [Config-Revision Rebuild](../architecture/pipeline.md#config-revision-rebuild).

BaseSecurityDecorator
---------------------

The base class manages the decorator lifecycle:

```python
class BaseSecurityDecorator:
    def __init__(self, config: SecurityConfig) -> None:
        self.config = config
        self._route_configs: dict[str, RouteConfig] = {}
        self._route_config_revision = RouteConfigRevision()
        self.behavior_tracker = BehaviorTracker(config)
        self.agent_handler: Any = None

    @property
    def route_config_revision(self) -> int:
        return self._route_config_revision.value

    def get_route_config(self, route_id: str) -> RouteConfig | None:
        return self._route_configs.get(route_id)

    def _get_route_id(self, func: Callable[..., Any]) -> str:
        route_id = getattr(func, "_guard_route_id", None)
        if isinstance(route_id, str):
            return route_id
        route_id = base_id = f"{func.__module__}.{func.__qualname__}"
        suffix = 1
        while route_id in self._route_configs:
            suffix += 1
            route_id = f"{base_id}#{suffix}"
        return route_id

    def _ensure_route_config(self, func: Callable[..., Any]) -> RouteConfig:
        route_id = self._get_route_id(func)
        if route_id not in self._route_configs:
            config = RouteConfig(self._route_config_revision)
            config.enable_suspicious_detection = (
                self.config.enable_penetration_detection
            )
            self._route_configs[route_id] = config
            self._route_config_revision.bump()
        cast(Any, func)._guard_route_id = route_id
        return self._route_configs[route_id]

    def _apply_route_config(self, func: Callable[..., Any]) -> DecoratedFunction:
        route_id = self._get_route_id(func)
        cast(Any, func)._guard_route_id = route_id
        return cast(DecoratedFunction, func)
```

`_route_config_revision` is a separate counter from `SecurityConfig`'s own revision; `build_default_pipeline` reads `guard_decorator.route_config_revision` to know when a route was registered or reconfigured after the pipeline was built. `_ensure_route_config` bumps it explicitly the moment a route id is first seen, in addition to `RouteConfig.__setattr__` bumping it for every field assignment after that.

Key points:

- **Route ID** is `"{module}.{qualname}"` of the decorated function. Functions made by one factory or shared wrapper have the same qualname, so a function whose `"{module}.{qualname}"` already belongs to another function gets the next free `"{module}.{qualname}#2"`, `#3` and so on, and keeps its own `RouteConfig`.
- **`_guard_route_id`** is stamped onto the function object by the first decorator. The routing system uses this attribute to look up the `RouteConfig` at request time.
- **`_ensure_route_config`** creates a `RouteConfig` on first access and reuses it for stacked decorators on the same function. A wrapper made with `functools.wraps` copies `_guard_route_id`, so guard decorators applied above it join the config of the function it wraps.

Mixin Classes
-------------

Guard-core provides six mixin classes, each adding a category of decorators:

| Mixin | Decorators Provided |
|---|---|
| `AccessControlMixin` | `require_ip()`, `block_countries()`, `allow_countries()`, `block_clouds()`, `bypass()` |
| `RateLimitingMixin` | `rate_limit()`, `geo_rate_limit()` |
| `AuthenticationMixin` | `require_https()`, `require_auth()`, `api_key_auth()`, `require_headers()` |
| `ContentFilteringMixin` | `block_user_agents()`, `content_type_filter()`, `max_request_size()`, `require_referrer()`, `custom_validation()`, `detection_exclusion()` |
| `BehavioralMixin` | `usage_monitor()`, `return_monitor()`, `behavior_analysis()`, `suspicious_frequency()` |
| `AdvancedMixin` | `time_window()`, `suspicious_detection()`, `honeypot_detection()` |

Each mixin follows the same pattern. For example, `AccessControlMixin.require_ip()`:

```python
class AccessControlMixin(BaseSecurityMixin):
    def require_ip(
        self,
        whitelist: list[str] | None = None,
        blacklist: list[str] | None = None,
    ) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
            route_config = self._ensure_route_config(func)
            if whitelist:
                route_config.ip_whitelist = whitelist
            if blacklist:
                route_config.ip_blacklist = blacklist
            return self._apply_route_config(func)

        return decorator
```

SecurityDecorator
-----------------

The final class combines everything via multiple inheritance:

```python
class SecurityDecorator(
    BaseSecurityDecorator,
    AccessControlMixin,
    RateLimitingMixin,
    BehavioralMixin,
    AuthenticationMixin,
    ContentFilteringMixin,
    AdvancedMixin,
):
    pass
```

How Adapters Expose Decorators
------------------------------

Your adapter creates a `SecurityDecorator` instance and makes it available to users. The typical pattern:

### 1. Create the Instance

```python
from guard_core.decorators import SecurityDecorator
from guard_core.models import SecurityConfig

config = SecurityConfig(...)
guard = SecurityDecorator(config)
```

### 2. Register It with the Middleware

The middleware needs access to the decorator handler to resolve route configs. Store it on the app's state and pass it to the middleware:

```python
app.state.guard_decorator = guard
security_middleware.set_decorator_handler(guard)
```

The `RouteConfigResolver` resolves the decorator from its routing context first, falling back to `request.state.guard_decorator`:

```python
def get_route_config(self, request: GuardRequest) -> RouteConfig | None:
    guard_decorator = self.context.guard_decorator
    if not guard_decorator:
        guard_decorator = getattr(request.state, "guard_decorator", None)
    if not guard_decorator:
        return None
    ...
```

The adapter is responsible for copying `app.state.guard_decorator` onto `request.state.guard_decorator` before the resolver runs (see [Adapter Responsibility](#adapter-responsibility) below). The resolver itself never touches `app.state`.

### 3. Users Apply Decorators

```python
@app.get("/admin")
@guard.require_ip(whitelist=["10.0.0.0/8"])
@guard.rate_limit(requests=5, window=60)
@guard.require_https()
async def admin_panel():
    return {"status": "ok"}
```

Multiple decorators stack. Each one calls `_ensure_route_config()` which returns the same `RouteConfig` instance for the function, so all settings accumulate.

Route Resolution at Request Time
--------------------------------

When a request arrives, the pipeline needs to find the `RouteConfig` for the matched route. This happens in two places:

### RouteConfigResolver (Middleware Level)

Used by `BypassHandler` and the dispatch method. It reads everything it needs from `request.state` -- it does **not** inspect the ASGI scope or iterate the app's route table:

```python
def get_route_config(self, request: GuardRequest) -> RouteConfig | None:
    guard_decorator = self.context.guard_decorator
    if not guard_decorator:
        guard_decorator = getattr(request.state, "guard_decorator", None)
    if not guard_decorator:
        return None

    route_id = getattr(request.state, "guard_route_id", None)
    if not route_id:
        return None

    return guard_decorator.get_route_config(route_id)
```

The decorator comes from the resolver's routing context (or `request.state.guard_decorator` as a fallback), and the route ID comes from `request.state.guard_route_id`. Matching the request to a route and populating those state values is the adapter's job, not the resolver's (see [Adapter Responsibility](#adapter-responsibility)).

### get_route_decorator_config (Check Level)

Used inside individual security checks via `guard_core/decorators/base.py`:

```python
def get_route_decorator_config(
    request: GuardRequest, decorator_handler: BaseSecurityDecorator
) -> RouteConfig | None:
    route_id = getattr(request.state, "guard_route_id", None)
    if route_id:
        return decorator_handler.get_route_config(route_id)
    return None
```

This function reads `request.state.guard_route_id` directly. As with the resolver, that value must already have been set by the adapter -- guard-core never reads `request.scope["route"]` itself.

### Adapter Responsibility

Guard-core resolves route config purely from `request.state`. It never inspects the ASGI scope, the app's route table, or `app.state`. So before the security pipeline runs, your adapter must populate `request.state`:

1. Copy `app.state.guard_decorator` (the `SecurityDecorator` registered in your bootstrap) onto `request.state.guard_decorator`.
2. Match the incoming request to its route and copy that endpoint's `_guard_route_id` onto `request.state.guard_route_id`.

The Starlette/FastAPI adapter does this in its middleware. `_resolve_route()` takes `scope["route"]` when the framework already populated it, otherwise walks `scope["app"].routes` matching on `path`, `methods`, and `hasattr(endpoint, ...)`. `_populate_guard_state()` then copies the decorator and the route's `_guard_route_id` onto `request.state`:

```python
def _populate_guard_state(self, guard_request, request) -> None:
    app_obj = request.scope.get("app")
    if app_obj and hasattr(app_obj, "state"):
        app_decorator = getattr(app_obj.state, "guard_decorator", None)
        if app_decorator:
            guard_request.state.guard_decorator = app_decorator

    route = self._resolve_route(request)
    if not route or not hasattr(route, "endpoint"):
        return

    ep = route.endpoint
    if hasattr(ep, "_guard_route_id"):
        guard_request.state.guard_route_id = ep._guard_route_id
```

This is **not** automatic -- even on ASGI frameworks the adapter has to read the scope and write these state values itself. WSGI/non-ASGI adapters do the same, sourcing the route from whatever their framework exposes.

### Reporting a Failed Match

A missing `guard_route_id` is ambiguous on its own: it means either "this route carries no decorators" or "matching failed and the decorators on this route will not be applied". The first is normal and every per-route check correctly skips itself. The second silently disables those checks, which is how [GHSA-f2vm-w8gq-h378](https://github.com/rennf93/fastapi-guard/security/advisories/GHSA-f2vm-w8gq-h378) turned a route-matching bug into an authentication bypass.

Adapters disambiguate by setting `request.state.guard_route_unresolved = True` on the branch where matching itself failed, and leaving it unset once a route was matched -- decorated or not:

```python
route = self._resolve_route(request)
if not route or not hasattr(route, "endpoint"):
    guard_request.state.guard_route_unresolved = True
    return
```

`RouteConfigCheck` reads that flag. By default nothing changes, because a failed match is indistinguishable from a request the app simply does not route. When `SecurityConfig.route_resolution_strict` is `True` it logs the failure, emits a `route_unresolved` event, and blocks the request with `500` unless `passive_mode` is on. Adapters that never set the flag keep their current behaviour under either setting.

Strict mode is a deliberate trade: because that ambiguity is unresolvable from inside guard-core, turning it on also rejects requests to paths the app does not serve, so a `404` becomes a `500`. Enable it where every reachable path is a known route and an unattributable request is worth refusing.

The send_decorator_event Mechanism
----------------------------------

When a security check blocks a request due to a decorator setting, it can emit an event through the decorator's event system. `BaseSecurityDecorator` provides several event methods:

```python
async def send_decorator_event(
    self,
    event_type: str,
    request: GuardRequest,
    action_taken: str,
    reason: str,
    decorator_type: str,
    **kwargs: Any,
) -> None:
    if not self.agent_handler:
        return
    # ... builds SecurityEvent and sends to agent_handler
```

Convenience methods built on top:

- `send_access_denied_event()` -- blocked by access control rules
- `send_authentication_failed_event()` -- auth check failure
- `send_rate_limit_event()` -- rate limit exceeded
- `send_decorator_violation_event()` -- generic decorator violation

These events flow to the Guard Agent platform when `enable_agent` is `True`. The event bus at the middleware level (`SecurityEventBus`) handles middleware-level events, while `BaseSecurityDecorator` handles decorator-level events. Both ultimately send to the same agent handler.

Extending the Decorator System
------------------------------

If your framework needs additional decorator methods, create a new mixin and combine it:

```python
from guard_core.decorators import SecurityDecorator
from guard_core.decorators.base import BaseSecurityMixin


class MyFrameworkMixin(BaseSecurityMixin):
    def require_session(self, session_key: str):
        def decorator(func):
            route_config = self._ensure_route_config(func)
            route_config.session_quota = {session_key: 1}
            return self._apply_route_config(func)

        return decorator


class MyFrameworkDecorator(SecurityDecorator, MyFrameworkMixin):
    pass
```

Then use `MyFrameworkDecorator` instead of `SecurityDecorator` in your adapter.

Initializing the Decorator
--------------------------

The decorator needs async initialization for behavior tracking and agent integration. Call these during your middleware's `initialize()`:

```python
async def initialize(self) -> None:
    if self.guard_decorator:
        if self.redis_handler:
            await self.guard_decorator.initialize_behavior_tracking(self.redis_handler)
        if self.agent_handler:
            await self.guard_decorator.initialize_agent(self.agent_handler)
```

`HandlerInitializer.initialize_agent_integrations()` handles the agent part automatically if you pass the decorator to it:

```python
self.handler_initializer = HandlerInitializer(
    config=self.config,
    redis_handler=self.redis_handler,
    agent_handler=self.agent_handler,
    guard_decorator=self.guard_decorator,
    # ...
)
```
