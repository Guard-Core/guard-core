---

title: Implementing GuardResponse and GuardResponseFactory
description: How to implement the GuardResponse and GuardResponseFactory protocols to create framework-native responses from guard-core security checks.
keywords: guard-core, GuardResponse, GuardResponseFactory, response protocol, adapter, error response, redirect
---

Implementing GuardResponse and GuardResponseFactory
===================================================

Protocol Definitions
--------------------

Both protocols live at `guard_core/protocols/response_protocol.py`:

```python
from collections.abc import MutableMapping
from typing import Protocol, runtime_checkable


@runtime_checkable
class GuardResponse(Protocol):
    @property
    def status_code(self) -> int: ...
    @property
    def headers(self) -> MutableMapping[str, str]: ...
    @property
    def body(self) -> bytes | None: ...


@runtime_checkable
class GuardResponseFactory(Protocol):
    def create_response(self, content: str, status_code: int) -> GuardResponse: ...
    def create_redirect_response(self, url: str, status_code: int) -> GuardResponse: ...
```

### GuardResponse

The response object returned by your factory and ultimately sent back to the client. The `headers` property **must be mutable** -- guard-core's `ErrorResponseFactory` writes security headers (HSTS, CSP, X-Frame-Options, etc.) directly onto the response via `response.headers[header_name] = header_value`.

`status_code`, `headers`, and `body` are the complete *required* `GuardResponse` surface; implementing just those three is enough to pass the pipeline.

!!! note "Optional: BoundedResponseBodyReader for response-body behavior rules"
    `body` is not read for behavioral `return_pattern` matching (`json:`, `regex:`, bare-substring) -- only `status:` patterns work against a plain `GuardResponse`. To let those three body-reading formats evaluate, additionally implement the optional `BoundedResponseBodyReader` capability (`async def read_body_prefix(self, max_bytes: int) -> bytes`) alongside `GuardResponse`, and set `SecurityConfig.behavior_scan_response_body=True`. This is genuinely optional: a response that only implements `GuardResponse` remains fully valid, and guard-core reports "could not evaluate" (never a false match or a false non-match) for a `return_pattern` rule it cannot check. See [Protocols - BoundedResponseBodyReader](../api/protocols.md#boundedresponsebodyreader) for the full contract, including the streaming/memory obligations on your implementation. If your adapter's `GuardResponse` previously matched an ordinary, non-streaming body through the (now-removed) `hasattr(response, "body")` codepath, that rule silently stops matching the moment your consumer upgrades guard-core, until you ship `BoundedResponseBodyReader` support -- this is not optional in the sense of "low priority", it is a required follow-up to avoid a silent regression for anyone using body-reading `return_pattern` rules against your adapter.

### GuardResponseFactory

A factory that produces `GuardResponse` instances. Guard-core's `ErrorResponseFactory` calls your factory's methods to build framework-native responses. You pass an instance of your factory into the `ResponseContext`, and the entire pipeline uses it from that point forward.

How ErrorResponseFactory Uses Your Factory
------------------------------------------

The `ErrorResponseFactory` in `guard_core/core/responses/factory.py` delegates response creation to your `GuardResponseFactory`:

```python
class ErrorResponseFactory:
    def __init__(self, context: ResponseContext):
        self.context = context

    async def create_error_response(
        self, status_code: int, default_message: str
    ) -> GuardResponse:
        custom_message = self.context.config.custom_error_responses.get(
            status_code, default_message
        )
        response = self.context.response_factory.create_response(
            custom_message, status_code
        )
        response = await self.apply_security_headers(response)
        response = await self.apply_modifier(response)
        return response

    async def create_https_redirect(self, request: GuardRequest) -> GuardResponse:
        https_url = request.url_replace_scheme("https")
        status_code = 301 if request.method.upper() in ("GET", "HEAD") else 308
        redirect_response = self.context.response_factory.create_redirect_response(
            str(https_url), status_code
        )
        return await self.apply_modifier(redirect_response)
```

The flow is:

1. A security check returns `await self.create_error_response(403, "Forbidden")`.
2. This calls `middleware.create_error_response()`, which delegates to `ErrorResponseFactory`.
3. `ErrorResponseFactory` checks `SecurityConfig.custom_error_responses` for a user-defined message override.
4. Your `GuardResponseFactory.create_response()` builds the actual framework response.
5. Security headers are applied via `response.headers[...] = ...`.
6. If `SecurityConfig.custom_response_modifier` is set, it receives the response for final transformation.

Implementation: FastAPI / Starlette
-----------------------------------

```python
from collections.abc import MutableMapping

from starlette.responses import PlainTextResponse, RedirectResponse, Response


class StarletteGuardResponse:
    def __init__(self, response: Response) -> None:
        self._response = response

    @property
    def status_code(self) -> int:
        return self._response.status_code

    @property
    def headers(self) -> MutableMapping[str, str]:
        return self._response.headers

    @property
    def body(self) -> bytes | None:
        if hasattr(self._response, "body"):
            return self._response.body
        return None


class StarletteResponseFactory:
    def create_response(self, content: str, status_code: int) -> StarletteGuardResponse:
        response = PlainTextResponse(content, status_code=status_code)
        return StarletteGuardResponse(response)

    def create_redirect_response(
        self, url: str, status_code: int
    ) -> StarletteGuardResponse:
        response = RedirectResponse(url=url, status_code=status_code)
        return StarletteGuardResponse(response)
```

If your framework's `Response` already has `status_code`, mutable `headers`, and `body` as properties, you may not need a wrapper at all. Starlette's `Response` satisfies all three natively, so a simpler approach is to use it directly:

```python
class StarletteResponseFactory:
    def create_response(self, content: str, status_code: int) -> Response:
        return PlainTextResponse(content, status_code=status_code)

    def create_redirect_response(self, url: str, status_code: int) -> Response:
        return RedirectResponse(url=url, status_code=status_code)
```

This works because Starlette's `Response` structurally satisfies `GuardResponse`.

Implementation: Flask
---------------------

Flask's `Response` has mutable headers but uses `data` instead of `body`:

```python
from collections.abc import MutableMapping

from flask import Response, redirect
from werkzeug.datastructures import Headers


class FlaskGuardResponse:
    def __init__(
        self, content: str = "", status_code: int = 200, headers: dict | None = None
    ) -> None:
        self._response = Response(content, status=status_code, headers=headers)

    @property
    def status_code(self) -> int:
        return self._response.status_code

    @property
    def headers(self) -> MutableMapping[str, str]:
        return self._response.headers

    @property
    def body(self) -> bytes | None:
        return self._response.data


class FlaskResponseFactory:
    def create_response(self, content: str, status_code: int) -> FlaskGuardResponse:
        return FlaskGuardResponse(content, status_code)

    def create_redirect_response(
        self, url: str, status_code: int
    ) -> FlaskGuardResponse:
        return FlaskGuardResponse(
            f"Redirecting to {url}",
            status_code,
            {"Location": url},
        )
```

Implementation: Django
----------------------

Django's `HttpResponse` has a dict-like `headers` property (Django 3.2+):

```python
from collections.abc import MutableMapping

from django.http import HttpResponse, HttpResponseRedirect


class DjangoGuardResponse:
    def __init__(self, response: HttpResponse) -> None:
        self._response = response

    @property
    def status_code(self) -> int:
        return self._response.status_code

    @property
    def headers(self) -> MutableMapping[str, str]:
        return self._response.headers

    @property
    def body(self) -> bytes | None:
        return self._response.content


class DjangoResponseFactory:
    def create_response(self, content: str, status_code: int) -> DjangoGuardResponse:
        response = HttpResponse(content, status=status_code)
        return DjangoGuardResponse(response)

    def create_redirect_response(
        self, url: str, status_code: int
    ) -> DjangoGuardResponse:
        response = HttpResponseRedirect(url)
        response.status_code = status_code
        return DjangoGuardResponse(response)
```

ResponseContext
---------------

Your `GuardResponseFactory` instance is passed into the `ResponseContext` dataclass, which is then used to construct the `ErrorResponseFactory`:

```python
from guard_core.core.responses.context import ResponseContext
from guard_core.core.responses.factory import ErrorResponseFactory
from guard_core.core.events import MetricsCollector


response_context = ResponseContext(
    config=security_config,
    logger=logger,
    metrics_collector=metrics_collector,
    agent_handler=agent_handler,
    guard_decorator=guard_decorator,
    response_factory=your_response_factory,  # Your GuardResponseFactory instance
)

error_factory = ErrorResponseFactory(response_context)
```

The `ResponseContext` dataclass is defined in `guard_core/core/responses/context.py`:

```python
@dataclass
class ResponseContext:
    config: SecurityConfig
    logger: Logger
    metrics_collector: MetricsCollector

    agent_handler: AgentHandlerProtocol | None = None
    redis_handler: RedisHandlerProtocol | None = None
    guard_decorator: BaseSecurityDecorator | None = None
    response_factory: GuardResponseFactory | None = None
    security_headers_manager: SecurityHeadersManager = field(
        default_factory=SecurityHeadersManager.isolated
    )
```

Security Headers
----------------

`ErrorResponseFactory.apply_security_headers()` iterates over the headers produced by `security_headers_manager.get_headers()` and writes them onto your response:

```python
async def apply_security_headers(
    self, response: GuardResponse, request_path: str | None = None
) -> GuardResponse:
    headers_config = self.context.config.security_headers
    if headers_config and headers_config.get("enabled", True):
        security_headers = await security_headers_manager.get_headers(request_path)
        for header_name, header_value in security_headers.items():
            response.headers[header_name] = header_value
    return response
```

This is why `GuardResponse.headers` must return a `MutableMapping`. If your framework's response uses an immutable header collection, you must wrap it with a mutable proxy.

Custom Response Modifier
------------------------

If `SecurityConfig.custom_response_modifier` is set, `ErrorResponseFactory.apply_modifier()` passes every response through it:

```python
async def apply_modifier(self, response: GuardResponse) -> GuardResponse:
    if self.context.config.custom_response_modifier:
        return await self.context.config.custom_response_modifier(response)
    return response
```

The modifier receives and returns a `GuardResponse`, so your wrapper must be what gets passed in. If you use framework-native responses directly (no wrapper), the modifier will receive the framework response -- which is fine as long as it satisfies `GuardResponse`.
