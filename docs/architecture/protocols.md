---

title: Protocol Reference - Guard Core
description: Complete reference for GuardRequest, GuardResponse, GuardResponseFactory, and GuardMiddlewareProtocol -- the contracts adapter developers must implement
keywords: guard-core, protocols, GuardRequest, GuardResponse, GuardResponseFactory, adapter contract, python protocol
---

Protocol Reference
==================

guard-core defines its boundaries through `typing.Protocol` classes. Adapter developers must provide concrete implementations of these protocols to bridge their framework's native types into the guard-core engine.

The top-level protocols are decorated with `@runtime_checkable`, meaning you can verify conformance at runtime with `isinstance()`. `RequestState`, `GuardRequestHeaders`, `GuardResponseHeaders` and the middleware sub-protocols are plain `Protocol` classes for static typing.

This page is a summary. The full member list of every protocol, including the optional capability protocols (`BoundedBodyReader`, `IdleBoundedBodyReader`, `BoundedResponseBodyReader`, `MaterializedBodyResponse`), `GuardRequestHeaders`, `GuardResponseHeaders`, `DynamicRulesProtocol`, `CloudIpStoreProtocol` and `RouteIdentity`, is in [Protocols](../api/protocols.md).

___

GuardRequest
------------

**Location**: `guard_core/protocols/request_protocol.py`

The abstraction over any HTTP request object. Every security check receives a `GuardRequest`.

```python
from collections.abc import Mapping
from typing import Protocol, runtime_checkable


@runtime_checkable
class GuardRequest(Protocol):
    @property
    def url_path(self) -> str: ...
    @property
    def url_scheme(self) -> str: ...
    @property
    def url_full(self) -> str: ...
    def url_replace_scheme(self, scheme: str) -> str: ...
    @property
    def method(self) -> str: ...
    @property
    def client_host(self) -> str | None: ...
    @property
    def headers(self) -> GuardRequestHeaders: ...
    @property
    def query_params(self) -> Mapping[str, str]: ...
    async def body(self) -> bytes: ...
    @property
    def state(self) -> RequestState: ...
    @property
    def scope(self) -> dict[str, object]: ...
```

### Property Reference

| Property | Type | Description |
|---|---|---|
| `url_path` | `str` | The path component of the URL (e.g. `/api/users`) |
| `url_scheme` | `str` | The URL scheme (`"http"` or `"https"`) |
| `url_full` | `str` | The complete URL including scheme, host, path, and query string |
| `url_replace_scheme(scheme)` | `str` | Returns the full URL with the scheme replaced (used for HTTPS redirects) |
| `method` | `str` | The HTTP method (`"GET"`, `"POST"`, etc.) |
| `client_host` | `str \| None` | The connecting client's IP address. `None` when unavailable (e.g. Unix sockets) |
| `headers` | `GuardRequestHeaders` | HTTP headers as a read-only container (`__getitem__`, `__contains__`, `get`, `keys()`, `items()`; not required to be a `Mapping`). Header names are case-insensitive in HTTP but the container's implementation determines lookup behavior |
| `query_params` | `Mapping[str, str]` | URL query parameters as a read-only mapping |
| `body()` | `async -> bytes` | The raw request body. This is an async method because some frameworks read the body lazily |
| `state` | `RequestState` | A mutable state object for attaching per-request data. guard-core stores `client_ip`, `route_config`, `is_whitelisted` and, with `whitelist_access_only`, `whitelist_entry` here |
| `scope` | `dict[str, object]` | ASGI-style scope dict for adapters needing lower-level access. guard-core never reads it, so an empty dict satisfies the protocol |

### Framework Mapping

This table shows what each property maps to in common frameworks:

| GuardRequest | FastAPI/Starlette | Flask | Django |
|---|---|---|---|
| `url_path` | `request.url.path` | `request.path` | `request.path` |
| `url_scheme` | `request.url.scheme` | `request.scheme` | `request.scheme` |
| `url_full` | `str(request.url)` | `request.url` | `request.build_absolute_uri()` |
| `url_replace_scheme(s)` | `str(request.url.replace(scheme=s))` | manual construction | manual construction |
| `method` | `request.method` | `request.method` | `request.method` |
| `client_host` | `request.client.host` | `request.remote_addr` | `request.META['REMOTE_ADDR']` |
| `headers` | `request.headers` | `request.headers` | `request.headers` (Django 2.2+) |
| `query_params` | `request.query_params` | `request.args` | `request.GET` |
| `body()` | `await request.body()` | `request.get_data()` | `request.body` |
| `state` | `request.state` | custom attribute bag | custom attribute bag |
| `scope` | `request.scope` | synthetic dict | synthetic dict |

!!! warning "The `state` object"
    guard-core writes to `request.state` during pipeline execution. The following attributes are set by built-in checks:

    - `state.client_ip` -- set by `RouteConfigCheck` (check #1)
    - `state.route_config` -- set by `RouteConfigCheck` (check #1)
    - `state.is_whitelisted` -- set by `IpSecurityCheck` (check #12): `True` for a global `whitelist` match, or always `False` when `whitelist_access_only` is on, the default since 5.0.0 (the matching entry is then in `state.whitelist_entry`)

    Your adapter's `GuardRequest.state` implementation must support arbitrary attribute assignment.

!!! warning "The `scope` dict"
    guard-core itself never reads `request.scope`, so an empty dict satisfies the protocol. An adapter that resolves routes from it (ASGI `scope["app"]` and `scope["route"]`) does that work before the pipeline runs and records the result on `request.state` (`guard_decorator`, `guard_route_id`, `guard_endpoint_id`, `guard_route_unresolved`). For frameworks with no ASGI scope, synthesize whatever your own route resolution needs.

___

GuardResponse
-------------

**Location**: `guard_core/protocols/response_protocol.py`

The abstraction over any HTTP response object.

```python
from typing import Protocol, runtime_checkable


@runtime_checkable
class GuardResponse(Protocol):
    @property
    def status_code(self) -> int: ...
    @property
    def headers(self) -> GuardResponseHeaders: ...
    @property
    def body(self) -> bytes | None: ...
```

### Property Reference

| Property | Type | Description |
|---|---|---|
| `status_code` | `int` | HTTP status code (e.g. `403`, `429`, `503`) |
| `headers` | `GuardResponseHeaders` | Response headers. **Must be mutable** -- guard-core writes security headers, CORS headers, and HSTS headers into this container. Members: `__getitem__`, `__setitem__`, `__delitem__`, `__contains__`, `get`, `keys()`, `items()` |
| `body` | `bytes \| None` | The response body, or `None` if no body |

### Framework Mapping

| GuardResponse | FastAPI/Starlette | Flask | Django |
|---|---|---|---|
| `status_code` | `response.status_code` | `response.status_code` | `response.status_code` |
| `headers` | `response.headers` | `response.headers` | `response.headers` (Django `HttpResponse`) |
| `body` | `response.body` | `response.get_data()` | `response.content` |

!!! important "GuardResponseHeaders requirement"
    The `headers` property must return a `GuardResponseHeaders`, which is not required to be a `MutableMapping` (Werkzeug `Headers` is not one). guard-core's `ErrorResponseFactory` writes security headers directly into `response.headers[header_name] = header_value`. If your framework's response headers are immutable, you must wrap them.

___

GuardResponseFactory
--------------------

**Location**: `guard_core/protocols/response_protocol.py`

A factory protocol for creating response objects. The adapter provides this so guard-core can create error responses and redirects without knowing the framework's response class.

```python
@runtime_checkable
class GuardResponseFactory(Protocol):
    def create_response(self, content: str, status_code: int) -> GuardResponse: ...
    def create_redirect_response(self, url: str, status_code: int) -> GuardResponse: ...
```

### Method Reference

| Method | Parameters | Returns | Purpose |
|---|---|---|---|
| `create_response` | `content: str`, `status_code: int` | `GuardResponse` | Creates a plain-text or JSON error response |
| `create_redirect_response` | `url: str`, `status_code: int` | `GuardResponse` | Creates an HTTP redirect response (used for HTTPS enforcement) |

### Example Implementation (FastAPI/Starlette)

```python
from starlette.responses import JSONResponse, RedirectResponse

from guard_core.protocols.response_protocol import GuardResponse, GuardResponseFactory


class StarletteResponseFactory:
    def create_response(self, content: str, status_code: int) -> GuardResponse:
        return JSONResponse(
            content={"detail": content},
            status_code=status_code,
        )

    def create_redirect_response(self, url: str, status_code: int) -> GuardResponse:
        return RedirectResponse(url=url, status_code=status_code)
```

The factory instance is passed to `ResponseContext.response_factory` and used by `ErrorResponseFactory` internally.

___

GuardMiddlewareProtocol
-----------------------

**Location**: `guard_core/protocols/middleware_protocol.py`

Defines what the middleware instance must expose so that security checks can access shared state and services. Your adapter's middleware class must satisfy this protocol.

```python
from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from guard_core.models import SecurityConfig


@runtime_checkable
class GuardMiddlewareProtocol(Protocol):
    config: SecurityConfig
    logger: logging.Logger
    last_cloud_ip_refresh: int
    suspicious_request_counts: dict[str, dict[str, int]]

    @property
    def guard_decorator(self) -> RouteDecoratorRegistryProtocol | None: ...
    @property
    def event_bus(self) -> SecurityEventBusProtocol: ...
    @property
    def route_resolver(self) -> RouteResolverProtocol: ...
    @property
    def response_factory(self) -> ResponseFactoryProtocol | None: ...
    @property
    def rate_limit_handler(self) -> RateLimitHandlerProtocol | None: ...
    @property
    def agent_handler(self) -> AgentHandlerProtocol | None: ...
    @property
    def geo_ip_handler(self) -> GeoIPHandlerOfThisTree | None: ...
    @property
    def guard_response_factory(self) -> GuardResponseFactory | None: ...

    async def create_error_response(
        self, status_code: int, default_message: str
    ) -> GuardResponse: ...

    async def refresh_cloud_ip_ranges(self) -> None: ...
```

### Attribute Reference

| Attribute | Type | Description |
|---|---|---|
| `config` | `SecurityConfig` | The security configuration object |
| `logger` | `logging.Logger` | Logger instance used by all checks |
| `last_cloud_ip_refresh` | `int` | Unix timestamp of the last cloud IP range refresh |
| `suspicious_request_counts` | `dict[str, dict[str, int]]` | Per-IP, per-category suspicious request counters (IP -> category -> count). Read the total via `sum(values())`. |

### Property Reference

| Property | Typical Type | Description |
|---|---|---|
| `event_bus` | `SecurityEventBus` (satisfies `SecurityEventBusProtocol`) | Dispatches security events to the agent |
| `route_resolver` | `RouteConfigResolver` (satisfies `RouteResolverProtocol`) | Resolves route-level decorator configurations |
| `response_factory` | `ErrorResponseFactory \| None` (satisfies `ResponseFactoryProtocol`) | Creates error responses and applies security headers; `None` for a host that builds none |
| `rate_limit_handler` | `RateLimitManager \| None` (satisfies `RateLimitHandlerProtocol`) | Checks and enforces rate limits |
| `agent_handler` | `AgentHandlerProtocol \| None` | Guard agent telemetry client (or `None` if disabled) |
| `geo_ip_handler` | `GeoIPHandlerOfThisTree \| None` (the `GeoIPHandler` of this tree) | GeoIP lookup handler (or `None` if not configured) |
| `guard_response_factory` | `GuardResponseFactory \| None` | The adapter-provided response factory |
| `guard_decorator` | `RouteDecoratorRegistryProtocol \| None` | The route-decorator registry the engine reads for per-route configs and their revision; `None` or an absent attribute means no route configs |

### Method Reference

| Method | Description |
|---|---|
| `create_error_response(status_code, default_message)` | Delegates to `ErrorResponseFactory.create_error_response()`. Applies custom error messages, security headers, and response modifiers |
| `refresh_cloud_ip_ranges()` | Triggers a refresh of cloud provider IP ranges from upstream sources |

!!! note "Security checks access the middleware"
    Every `SecurityCheck` subclass receives a `GuardMiddlewareProtocol` reference in its constructor. Checks use `self.middleware.event_bus`, `self.middleware.route_resolver`, `self.middleware.rate_limit_handler`, etc. to access shared services.

___

Additional Protocols
--------------------

### GeoIPHandler

**Location**: `guard_core/protocols/geo_ip_protocol.py`

```python
@runtime_checkable
class GeoIPHandler(Protocol):
    @property
    def is_initialized(self) -> bool: ...
    async def initialize(self) -> None: ...
    async def initialize_redis(self, redis_handler: RedisHandlerProtocol) -> None: ...
    async def initialize_agent(self, agent_handler: AgentHandlerProtocol) -> None: ...
    def get_country(self, ip: str) -> str | None: ...
    async def refresh(self) -> None: ...
    def close(self) -> None: ...
```

guard-core ships with `IPInfoManager` as a default implementation. Adapters can provide custom implementations for other GeoIP providers.

### RedisHandlerProtocol

**Location**: `guard_core/protocols/redis_protocol.py`

```python
@runtime_checkable
class RedisHandlerProtocol(Protocol):
    config: SecurityConfig

    async def get_key(self, namespace: str, key: str) -> str | None: ...
    async def get_many(self, pairs: Sequence[tuple[str, str]]) -> list[str | None]: ...
    async def set_key(
        self, namespace: str, key: str, value: RedisValue, ttl: int | None = None
    ) -> bool | None: ...
    async def delete(self, namespace: str, key: str) -> int | None: ...
    async def keys(self, pattern: str) -> list[str] | None: ...
    async def initialize(self) -> None: ...
    def get_connection(self) -> AsyncContextManager[Redis]: ...

    # ... and 18 more: set_key_if_absent, incr, write_atomically, delete_pattern,
    # the ban, sliding-window and detection-strike methods, initialize_agent and
    # is_connected. The full list is in docs/api/protocols.md.
```

This excerpt names only some members. The complete list, with every signature, is in [Protocols](../api/protocols.md#redishandlerprotocol).

guard-core ships with `RedisManager` as the default implementation using the `redis` Python package.

### AgentHandlerProtocol

**Location**: `guard_core/protocols/agent_protocol.py`

```python
@runtime_checkable
class AgentHandlerProtocol(Protocol):
    async def initialize_redis(self, redis_handler: RedisHandlerProtocol) -> None: ...
    async def send_event(self, event: object) -> None: ...
    async def send_metric(self, metric: object) -> None: ...
    async def start(self) -> None: ...
    async def stop(self) -> None: ...
    async def flush_buffer(self) -> None: ...
    async def get_dynamic_rules(self) -> DynamicRulesProtocol | None: ...
    async def health_check(self) -> bool: ...
    def get_stats(self) -> dict[str, JsonValue]: ...
```

Implemented by the `guard-agent` package. Only active when `SecurityConfig.enable_agent = True`.
