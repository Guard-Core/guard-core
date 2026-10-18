---

title: Middleware Integration
description: How to wire guard-core's security pipeline into your framework's middleware system, including initialization, dispatch, and CORS handling.
keywords: guard-core, middleware, dispatch, initialization, SecurityCheckPipeline, HandlerInitializer, CORS, adapter
---

Middleware Integration
======================

The Dispatch Pattern
--------------------

Every adapter follows the same dispatch lifecycle:

1. **Passthrough check** -- an excluded path is marked exclusion-scoped and falls through to the pipeline unchanged (where only ban enforcement and the IP, country and cloud lists still run), before any identity resolution runs. A non-excluded request with no connecting peer then resolves its identity (falling back to `X-Forwarded-For` when `"unix"` is in `trusted_proxies`, for Unix-socket deployments) and is rejected with 403 when identity cannot be resolved and `fail_secure=True` (the default), or continues with identity `"unknown"` when `fail_secure=False`: `IpSecurityCheck` allows the request unless a whitelist or a country allow-list is configured, whether the global `whitelist`/`whitelist_countries` or a decorated route's `ip_whitelist`/`whitelist_countries` (blacklist, `blocked_countries`, and cloud-provider checks, global or route-level, are skipped since none can match without an address), and detection and a shared `"unknown"` rate-limit bucket still apply.
2. **Route resolution** -- resolve the matched route's `RouteConfig` (decorator settings).
3. **Security bypass check** -- if the route bypasses all checks, forward immediately.
4. **Security pipeline execution** -- run the security check pipeline, built to just the checks the configuration and registered routes can trigger out of the 17-check catalogue.
5. **Behavioral usage rules** -- track endpoint usage for behavioral rules.
6. **Call next** -- forward to the application handler and measure response time.
7. **Response processing** -- apply behavioral return rules, collect metrics, add security headers.

Guard-core provides all the building blocks. Your middleware class orchestrates them.

Reference: fastapi-guard Middleware
-----------------------------------

The production `fastapi-guard` adapter demonstrates the complete pattern. Study this as a blueprint for your own adapter.

### Constructor

```python
class SecurityMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: ASGIApp, *, config: SecurityConfig) -> None:
        super().__init__(app)
        self.app = app
        self.config = config
        self.logger = setup_custom_logging(
            config.custom_log_file, log_format=config.log_format
        )
        self.last_cloud_ip_refresh = 0
        self.suspicious_request_counts: dict[str, dict[str, int]] = {}
        self.rate_limit_handler = RateLimitManager(config)
        self.guard_decorator: BaseSecurityDecorator | None = None

        self._configure_security_headers(config)

        self.geo_ip_handler = None
        if config.whitelist_countries or config.blocked_countries:
            self.geo_ip_handler = config.geo_ip_handler

        self.redis_handler = None
        if config.enable_redis:
            from guard_core.handlers.redis_handler import RedisManager

            self.redis_handler = RedisManager(config)

        self.agent_handler = None
        if config.enable_agent:
            agent_config = config.to_agent_config()
            if agent_config:
                try:
                    from guard_agent import guard_agent

                    self.agent_handler = guard_agent(agent_config)
                except ImportError:
                    self.logger.warning(
                        "Agent enabled but guard_agent package not installed."
                    )

        self.security_pipeline: SecurityCheckPipeline | None = None

        self.event_bus = SecurityEventBus(
            self.agent_handler, self.config, self.geo_ip_handler
        )
        self.metrics_collector = MetricsCollector(self.agent_handler, self.config)

        self.handler_initializer = HandlerInitializer(
            config=self.config,
            redis_handler=self.redis_handler,
            agent_handler=self.agent_handler,
            geo_ip_handler=self.geo_ip_handler,
            rate_limit_handler=self.rate_limit_handler,
            guard_decorator=self.guard_decorator,
        )

        response_context = ResponseContext(
            config=self.config,
            logger=self.logger,
            metrics_collector=self.metrics_collector,
            agent_handler=self.agent_handler,
            guard_decorator=self.guard_decorator,
        )
        self.response_factory = ErrorResponseFactory(response_context)

        routing_context = RoutingContext(
            config=self.config,
            logger=self.logger,
            guard_decorator=self.guard_decorator,
        )
        self.route_resolver = RouteConfigResolver(routing_context)

        validation_context = ValidationContext(
            config=self.config,
            logger=self.logger,
            event_bus=self.event_bus,
        )
        self.validator = RequestValidator(validation_context)

        bypass_context = BypassContext(
            config=self.config,
            logger=self.logger,
            event_bus=self.event_bus,
            route_resolver=self.route_resolver,
            response_factory=self.response_factory,
            validator=self.validator,
        )
        self.bypass_handler = BypassHandler(bypass_context)

        behavioral_context = BehavioralContext(
            config=self.config,
            logger=self.logger,
            event_bus=self.event_bus,
            guard_decorator=self.guard_decorator,
        )
        self.behavioral_processor = BehavioralProcessor(behavioral_context)
```

### Dispatch Method

```python
async def dispatch(
    self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
) -> Response:
    passthrough = await self.bypass_handler.handle_passthrough(request, call_next)
    if passthrough:
        return passthrough

    client_ip = await extract_client_ip(request, self.config, self.agent_handler)
    route_config = self.route_resolver.get_route_config(request)

    if bypass := await self.bypass_handler.handle_security_bypass(
        request, call_next, route_config
    ):
        return bypass

    if not self.security_pipeline:
        self._build_security_pipeline()
    assert self.security_pipeline is not None

    if blocking := await self.security_pipeline.execute(request):
        return blocking

    if route_config and route_config.behavior_rules and client_ip:
        await self.behavioral_processor.process_usage_rules(
            request, client_ip, route_config
        )

    start_time = time.time()
    response = await call_next(request)
    response_time = time.time() - start_time

    return await self.response_factory.process_response(
        request,
        response,
        response_time,
        route_config,
        process_behavioral_rules=self.behavioral_processor.process_return_rules,
    )
```

### Initialize Method

```python
async def initialize(self) -> None:
    self._build_security_pipeline()
    self.handler_initializer.guard_decorator = self.guard_decorator
    await self.handler_initializer.initialize_redis_handlers()
    await self.handler_initializer.initialize_agent_integrations()
```

Building Your Own Middleware
----------------------------

### Step 1: Create the Middleware Class

Extend your framework's middleware base class. The middleware must satisfy `GuardMiddlewareProtocol`:

```python
from guard_core.protocols.middleware_protocol import GuardMiddlewareProtocol
```

The protocol requires:

| Attribute / Method | Type | Purpose |
|---|---|---|
| `config` | `SecurityConfig` | Configuration object |
| `logger` | `logging.Logger` | Logger instance |
| `last_cloud_ip_refresh` | `int` | Unix timestamp of last cloud IP refresh |
| `suspicious_request_counts` | `dict[str, dict[str, int]]` | Per-IP, per-category counters (IP -> category -> count). Read the total via `sum(values())`. |
| `event_bus` | `SecurityEventBus` | Event dispatching |
| `route_resolver` | `RouteConfigResolver` | Route config resolution |
| `response_factory` | `ErrorResponseFactory` | Error response creation |
| `rate_limit_handler` | `RateLimitManager` | Rate limiting |
| `agent_handler` | Agent instance or `None` | Telemetry agent |
| `geo_ip_handler` | GeoIP instance or `None` | IP geolocation |
| `guard_response_factory` | `GuardResponseFactory` | Framework response factory |
| `create_error_response()` | `async (int, str) -> GuardResponse` | Create error response |
| `refresh_cloud_ip_ranges()` | `async () -> None` | Refresh cloud IPs |

### Step 2: Initialize Core Modules

In your constructor, initialize the guard-core modules with their context objects. The context objects use dependency injection to keep modules decoupled:

```python
from guard_core.core.behavioral import BehavioralContext, BehavioralProcessor
from guard_core.core.bypass import BypassContext, BypassHandler
from guard_core.core.events import MetricsCollector, SecurityEventBus
from guard_core.core.initialization import HandlerInitializer
from guard_core.core.responses import ErrorResponseFactory, ResponseContext
from guard_core.core.routing import RouteConfigResolver, RoutingContext
from guard_core.core.validation import RequestValidator, ValidationContext
```

Each context is a `@dataclass` with explicit dependencies:

- **`ResponseContext`** -- `config`, `logger`, `metrics_collector`, `agent_handler`, `guard_decorator`, `response_factory` (your `GuardResponseFactory`)
- **`RoutingContext`** -- `config`, `logger`, `guard_decorator`
- **`ValidationContext`** -- `config`, `logger`, `event_bus`
- **`BypassContext`** -- `config`, `logger`, `event_bus`, `route_resolver`, `response_factory`, `validator`
- **`BehavioralContext`** -- `config`, `logger`, `event_bus`, `guard_decorator`

### Step 3: Build the Security Pipeline

Build the pipeline with `build_default_pipeline`, then add any custom checks. It filters the 17-check catalogue through each check class's `applies_to(config, route_configs)` classmethod and instantiates only the checks that return `True` for your middleware's config and registered routes, so most deployments run fewer than 17:

```python
from guard_core.core.checks import build_default_pipeline


def _build_security_pipeline(self) -> None:
    self.security_pipeline = build_default_pipeline(self)
```

Each check receives `self` (your middleware instance) and accesses everything it needs through the `GuardMiddlewareProtocol` interface. Add custom checks with `self.security_pipeline.add_check(...)`.

#### Build-Time Elimination

`build_default_pipeline` reads registered per-route decorator configuration through `middleware.guard_decorator`, specifically `guard_decorator._route_configs`, to decide which route-driven checks (required headers, authentication, referrer, time windows, and similar) are reachable. If `guard_decorator` is `None` when the pipeline is built, the route configuration is treated as unknown and every route-driven check is kept, so an adapter that cannot expose a populated `guard_decorator` at build time only loses the elimination optimization; it never loses the protection those checks provide. `IpSecurityCheck` is never eliminated by any configuration: it fronts an unconditional ban lookup whose store is writable from behavioral-rule bans and from any other process sharing the same Redis, so no configuration can prove it unreachable. See [Security Pipeline](../architecture/pipeline.md#build-time-elimination) for the full mechanism.

### Step 4: Use HandlerInitializer

`HandlerInitializer` centralizes the async initialization of Redis, Agent, and handler subsystems:

```python
from guard_core.core.initialization import HandlerInitializer

self.handler_initializer = HandlerInitializer(
    config=self.config,
    redis_handler=self.redis_handler,
    agent_handler=self.agent_handler,
    geo_ip_handler=self.geo_ip_handler,
    rate_limit_handler=self.rate_limit_handler,
    guard_decorator=self.guard_decorator,
)
```

Call these in your `initialize()` method:

```python
async def initialize(self) -> None:
    self._build_security_pipeline()
    self.handler_initializer.guard_decorator = self.guard_decorator
    await self.handler_initializer.initialize_redis_handlers()
    await self.handler_initializer.initialize_agent_integrations()
```

`initialize_redis_handlers()` performs:

- `redis_handler.initialize()`
- `cloud_handler.initialize_redis()` (if cloud providers configured)
- `ip_ban_manager.initialize_redis()`
- `geo_ip_handler.initialize_redis()` (if present)
- `rate_limit_handler.initialize_redis()` (if present)
- `sus_patterns_handler.initialize_redis()`

`initialize_agent_integrations()` performs:

- `agent_handler.start()`
- Cross-initialization between agent and Redis handlers
- Agent initialization for IP ban, rate limit, suspicious patterns, cloud, and geo handlers
- Decorator agent initialization
- Dynamic rule manager initialization (if enabled)

### Step 5: Wire the Dispatch

Your framework's middleware entry point must:

1. Wrap the incoming request into a `GuardRequest` (if not already protocol-compatible).
2. Call `bypass_handler.handle_passthrough()`.
3. Extract client IP and resolve route config.
4. Call `bypass_handler.handle_security_bypass()`.
5. Call `security_pipeline.execute()`.
6. Process behavioral usage rules.
7. Forward to the next handler.
8. Call `response_factory.process_response()` on the result.

### Step 6: Implement `create_error_response`

Your middleware must expose this method, as individual security checks call it through the `GuardMiddlewareProtocol`:

```python
async def create_error_response(
    self, status_code: int, default_message: str
) -> GuardResponse:
    return await self.response_factory.create_error_response(
        status_code, default_message
    )
```

### Step 7: Implement `refresh_cloud_ip_ranges`

Required by `CloudIpRefreshCheck`:

```python
async def refresh_cloud_ip_ranges(self) -> None:
    if not self.config.block_cloud_providers:
        return

    from guard_core.handlers.cloud_handler import cloud_handler

    if self.config.enable_redis and self.redis_handler:
        await cloud_handler.refresh_async(
            self.config.block_cloud_providers,
            ttl=self.config.cloud_ip_refresh_interval,
        )
    else:
        cloud_handler.refresh(self.config.block_cloud_providers)
    self.last_cloud_ip_refresh = int(time.time())
```

CORS Handling
-------------

Guard-core does not manage CORS middleware registration. CORS is framework-specific and must be handled at the adapter level. The fastapi-guard adapter provides a static helper:

```python
from fastapi.middleware.cors import CORSMiddleware


@staticmethod
def configure_cors(app: FastAPI, config: SecurityConfig) -> bool:
    if config.enable_cors:
        cors_params: dict[str, Any] = {
            "allow_origins": config.cors_allow_origins,
            "allow_methods": config.cors_allow_methods,
            "allow_headers": config.cors_allow_headers,
            "allow_credentials": config.cors_allow_credentials,
            "max_age": config.cors_max_age,
        }
        if config.cors_expose_headers:
            cors_params["expose_headers"] = config.cors_expose_headers
        app.add_middleware(CORSMiddleware, **cors_params)
        return True
    return False
```

Guard-core **does** handle CORS **headers** on individual responses through `ErrorResponseFactory.apply_cors_headers()`. When a request includes an `Origin` header, the response processing stage adds the appropriate CORS headers via `security_headers_manager.get_cors_headers()`. But the framework's CORS middleware (which handles preflight `OPTIONS` requests) must be registered by your adapter.

For Flask, use `flask-cors`. For Django, use `django-cors-headers`. Read the CORS-related fields from `SecurityConfig`:

- `enable_cors`
- `cors_allow_origins`
- `cors_allow_methods`
- `cors_allow_headers`
- `cors_allow_credentials`
- `cors_expose_headers`
- `cors_max_age`

Framework-Specific Middleware Patterns
--------------------------------------

### FastAPI / Starlette

Extend `BaseHTTPMiddleware`. Override `dispatch(self, request, call_next)`. The `call_next` callable forwards to the next middleware or route handler.

### Flask

Use `app.before_request` and `app.after_request` hooks. Since Flask is synchronous, you need `asyncio.run()` or an async-compatible Flask extension (like Quart) to call guard-core's async methods:

```python
import asyncio


@app.before_request
def guard_before_request():
    loop = asyncio.new_event_loop()
    try:
        wrapped = FlaskGuardRequest(request, app)
        result = loop.run_until_complete(run_security_pipeline(wrapped))
        if result is not None:
            return unwrap_response(result)
    finally:
        loop.close()
```

For production Flask adapters, consider using Quart (async Flask) to avoid the overhead of creating event loops per request.

### Django

Use Django middleware classes with `__call__` or `process_request`/`process_response` hooks. For async Django (3.1+), use `async def __call__`:

```python
class GuardMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
        self.security_middleware = None

    async def __call__(self, request):
        if self.security_middleware is None:
            await self._initialize()

        wrapped = DjangoGuardRequest(request)

        passthrough = await self.bypass_handler.handle_passthrough(
            wrapped, self._call_next
        )
        if passthrough:
            return unwrap_response(passthrough)

        blocking = await self.security_pipeline.execute(wrapped)
        if blocking:
            return unwrap_response(blocking)

        response = await self.get_response(request)
        return response
```

Initialization Timing
---------------------

The `initialize()` method is async and must be called after the middleware is instantiated. In FastAPI, use a startup event:

```python
@app.on_event("startup")
async def startup():
    await security_middleware.initialize()
```

In Django, call it in `AppConfig.ready()` or the first request. In Flask, use `app.before_first_request` or call it during app factory setup.
