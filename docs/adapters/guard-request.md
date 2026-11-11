---

title: Implementing GuardRequest
description: How to wrap your framework's request object to satisfy the GuardRequest protocol defined by guard-core.
keywords: guard-core, GuardRequest, request protocol, adapter development, request wrapper, protocol implementation
---

Implementing GuardRequest
=========================

Protocol Definition
-------------------

The `GuardRequest` protocol lives at `guard_core/protocols/request_protocol.py`:

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

The protocol is `runtime_checkable`, so you can verify your implementation at runtime with `isinstance(your_request, GuardRequest)`.

Property Mapping Table
----------------------

This table shows how each `GuardRequest` property maps to the native request object in different frameworks:

| GuardRequest | FastAPI / Starlette | Flask | Django |
|---|---|---|---|
| `url_path` | `request.url.path` | `request.path` | `request.path` |
| `url_scheme` | `request.url.scheme` | `request.scheme` | `request.scheme` |
| `url_full` | `str(request.url)` | `request.url` | `request.build_absolute_uri()` |
| `url_replace_scheme(s)` | `str(request.url.replace(scheme=s))` | Manual construction | Manual construction |
| `method` | `request.method` | `request.method` | `request.method` |
| `client_host` | `request.client.host` | `request.remote_addr` | `request.META['REMOTE_ADDR']` |
| `headers` | `request.headers` | `request.headers` | Wrap `request.META` |
| `query_params` | `request.query_params` | `request.args` | `request.GET` |
| `body()` | `await request.body()` | `request.get_data()` | `request.body` |
| `state` | `request.state` | Custom `SimpleNamespace` | Custom `SimpleNamespace` |
| `scope` | `request.scope` | Build dict with `app`, `route` | Build dict with `app`, `route` |

Full Implementation Example: FastAPI / Starlette
-------------------------------------------------

Starlette's `Request` object is close to the `GuardRequest` protocol but does not match it exactly. Here is a complete wrapper:

```python
from collections.abc import Mapping

from starlette.requests import Request

from guard_core.protocols.request_protocol import (
    GuardRequest,
    GuardRequestHeaders,
    RequestState,
)


class StarletteGuardRequest:
    def __init__(self, request: Request) -> None:
        self._request = request

    @property
    def url_path(self) -> str:
        return self._request.url.path

    @property
    def url_scheme(self) -> str:
        return self._request.url.scheme

    @property
    def url_full(self) -> str:
        return str(self._request.url)

    def url_replace_scheme(self, scheme: str) -> str:
        return str(self._request.url.replace(scheme=scheme))

    @property
    def method(self) -> str:
        return self._request.method

    @property
    def client_host(self) -> str | None:
        if self._request.client:
            return self._request.client.host
        return None

    @property
    def headers(self) -> GuardRequestHeaders:
        return self._request.headers

    @property
    def query_params(self) -> Mapping[str, str]:
        return self._request.query_params

    async def body(self) -> bytes:
        return await self._request.body()

    @property
    def state(self) -> RequestState:
        return self._request.state

    @property
    def scope(self) -> dict[str, object]:
        scope = self._request.scope
        return scope if isinstance(scope, dict) else dict(scope)
```

Full Implementation Example: Flask
----------------------------------

Flask requests are synchronous. The adapter must bridge that gap. Wrap the body retrieval to work with `async def`:

```python
from collections.abc import Mapping
from types import SimpleNamespace

from flask import Flask, Request

from guard_core.protocols.request_protocol import GuardRequestHeaders


class FlaskGuardRequest:
    def __init__(self, request: Request, app: Flask) -> None:
        self._request = request
        self._app = app
        self._state = SimpleNamespace()
        self._scope = self._build_scope()

    def _build_scope(self) -> dict[str, object]:
        scope: dict[str, object] = {"app": self._app}
        rule = self._request.url_rule
        if rule:
            scope["route"] = rule
        return scope

    @property
    def url_path(self) -> str:
        return self._request.path

    @property
    def url_scheme(self) -> str:
        return self._request.scheme

    @property
    def url_full(self) -> str:
        return self._request.url

    def url_replace_scheme(self, scheme: str) -> str:
        url = self._request.url
        current_scheme = self._request.scheme
        return url.replace(f"{current_scheme}://", f"{scheme}://", 1)

    @property
    def method(self) -> str:
        return self._request.method

    @property
    def client_host(self) -> str | None:
        return self._request.remote_addr

    @property
    def headers(self) -> GuardRequestHeaders:
        return dict(self._request.headers)

    @property
    def query_params(self) -> Mapping[str, str]:
        return self._request.args

    async def body(self) -> bytes:
        return self._request.get_data()

    @property
    def state(self) -> SimpleNamespace:
        return self._state

    @property
    def scope(self) -> dict[str, object]:
        return self._scope
```

Full Implementation Example: Django
-----------------------------------

Django's `HttpRequest` requires the most translation work:

```python
from collections.abc import Mapping
from types import SimpleNamespace

from django.http import HttpRequest

from guard_core.protocols.request_protocol import GuardRequestHeaders


class DjangoGuardRequest:
    def __init__(self, request: HttpRequest) -> None:
        self._request = request
        self._state = SimpleNamespace()
        self._headers = self._extract_headers()

    def _extract_headers(self) -> dict[str, str]:
        headers: dict[str, str] = {}
        for key, value in self._request.META.items():
            if key.startswith("HTTP_"):
                header_name = key[5:].replace("_", "-").title()
                headers[header_name] = value
            elif key in ("CONTENT_TYPE", "CONTENT_LENGTH"):
                header_name = key.replace("_", "-").title()
                headers[header_name] = value
        return headers

    @property
    def url_path(self) -> str:
        return self._request.path

    @property
    def url_scheme(self) -> str:
        return self._request.scheme

    @property
    def url_full(self) -> str:
        return self._request.build_absolute_uri()

    def url_replace_scheme(self, scheme: str) -> str:
        full_url = self._request.build_absolute_uri()
        current_scheme = self._request.scheme
        return full_url.replace(f"{current_scheme}://", f"{scheme}://", 1)

    @property
    def method(self) -> str:
        return self._request.method

    @property
    def client_host(self) -> str | None:
        return self._request.META.get("REMOTE_ADDR")

    @property
    def headers(self) -> GuardRequestHeaders:
        return self._headers

    @property
    def query_params(self) -> Mapping[str, str]:
        return self._request.GET.dict()

    async def body(self) -> bytes:
        return self._request.body

    @property
    def state(self) -> SimpleNamespace:
        return self._state

    @property
    def scope(self) -> dict[str, object]:
        scope: dict[str, object] = {}
        if hasattr(self._request, "resolver_match") and self._request.resolver_match:
            scope["route"] = self._request.resolver_match
            scope["app"] = getattr(self._request.resolver_match, "app_name", None)
        return scope
```

The `state` Property
--------------------

The `state` property is a mutable namespace that security checks use to pass data between pipeline stages. For example, the `RouteConfigCheck` stores the resolved `RouteConfig` and `client_ip` on `request.state` so downstream checks can access them without recomputing:

```python
request.state.route_config = route_config
request.state.client_ip = client_ip
```

Your wrapper's `state` must support arbitrary attribute assignment. Starlette's `request.state` does this natively. For Flask and Django, use `types.SimpleNamespace`:

```python
from types import SimpleNamespace

self._state = SimpleNamespace()
```

The `scope` Dictionary
----------------------

guard-core itself never reads `scope`. The `RouteConfigResolver`, `get_route_decorator_config()`, and `BehavioralProcessor` read only `request.state`, specifically `request.state.guard_decorator`, `request.state.guard_route_id`, `request.state.guard_endpoint_id`, and `request.state.guard_route_unresolved`. Reading `scope` and translating it into those `request.state` values is the **adapter's** job. The `scope` dictionary should contain at least two keys so the adapter has the data it needs:

- **`app`**: The application instance. The adapter reads `request.scope.get("app")` to access the app's route table and copies the `guard_decorator` stored on `app.state` into `request.state.guard_decorator`.
- **`route`**: The matched route object. Must have an `endpoint` attribute with `_guard_route_id` set by guard-core's decorator system. The adapter copies `endpoint._guard_route_id` into `request.state.guard_route_id` and derives `request.state.guard_endpoint_id` from the endpoint. These `request.state` values are what `get_route_decorator_config()` and `BehavioralProcessor.get_endpoint_id()` then read.

If your framework does not natively provide ASGI scope, build it in your wrapper. If route-level decorator support is not needed, an empty dict suffices -- global-level `SecurityConfig` settings will still apply.

An adapter that does resolve routes should also set `request.state.guard_route_unresolved` when matching fails, so a resolution bug is distinguishable from a route that simply carries no decorators. See [Reporting a Failed Match](decorators.md#reporting-a-failed-match).

Runtime Verification
--------------------

Because `GuardRequest` is `@runtime_checkable`, you can assert correctness in your adapter's initialization or tests:

```python
from guard_core.protocols.request_protocol import GuardRequest

wrapped = StarletteGuardRequest(raw_request)
assert isinstance(wrapped, GuardRequest)
```

This checks structural compatibility at runtime. It does not verify return types of each method, so always pair this with proper unit tests for each property.

Async/Sync Bridging
-------------------

The `body()` method is defined as `async def body(self) -> bytes`. For **async frameworks** (FastAPI/Starlette), this maps directly to `await request.body()`. For **sync frameworks** (Flask, Django), wrap the synchronous body access in an async function:

```python
async def body(self) -> bytes:
    return self._request.get_data()
```

Python's `async def` returning a synchronous value works, the `await` completes immediately. guard-core's pipeline is always `async`, so even sync frameworks must provide async protocol methods. The adapter's middleware is responsible for running the async pipeline (using `asyncio.run()`, `asgiref.sync_to_async`, or the framework's own async support).
