---

title: Protocols
description: The protocol interfaces that adapters must implement to integrate guard-core with any Python web framework
keywords: protocols, guard request, guard response, middleware protocol, adapter development, guard-core
---

Protocols
=========

Protocols are the most important API surface for adapter developers. Guard-core uses Python `Protocol` classes (PEP 544) to define the contracts that adapters must satisfy. The top-level protocols are `@runtime_checkable`. `RequestState`, `GuardRequestHeaders`, `GuardResponseHeaders` and the middleware sub-protocols are plain `Protocol` classes for static typing only, so do not pass them to `isinstance`.

___

GuardRequest
------------

The request protocol defines how guard-core reads incoming request data. Adapters must wrap their framework's request object to satisfy this interface.

```python
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

### Member Details

| Member              | Return Type          | Description                                                   |
|---------------------|---------------------|---------------------------------------------------------------|
| `url_path`          | `str`               | The path component of the URL (e.g., `"/api/users"`).         |
| `url_scheme`        | `str`               | The URL scheme (`"http"` or `"https"`).                       |
| `url_full`          | `str`               | The full URL string including scheme, host, path, and query.  |
| `url_replace_scheme`| `str`               | Returns the full URL with the scheme replaced. Used for HTTPS redirects. |
| `method`            | `str`               | The HTTP method (`"GET"`, `"POST"`, etc.).                    |
| `client_host`       | `str \| None`       | The connecting client's IP address. `None` if unavailable.    |
| `headers`           | `GuardRequestHeaders` | Request headers as a read-only container with `__getitem__`, `__contains__`, `get`, `keys()` and `items()`; it need not be a `Mapping`. Case handling depends on adapter. |
| `query_params`      | `Mapping[str, str]` | URL query parameters as a read-only mapping.                  |
| `body()`            | `bytes` (async)     | The raw request body. May be called multiple times by detection checks. |
| `state`             | `RequestState`      | A mutable state object for passing data between checks. Must support attribute assignment (`__setattr__(name, value: object)`). |
| `scope`             | `dict[str, object]` | ASGI-style scope dict for adapters needing lower-level access. guard-core never reads it; the adapter's own route resolution does. |

### RequestState

```python
class RequestState(Protocol):
    def __setattr__(self, name: str, value: object, /) -> None: ...
```

The per-request attribute bag: any name can be set, none is declared. Pass the framework's own bag (Starlette `State`, Flask `g`, a `SimpleNamespace`, or the Django request itself). A name is only there once something set it, so read it back with `getattr` and a default.

### GuardRequestHeaders

```python
class GuardRequestHeaders(Protocol):
    def __getitem__(self, key: str, /) -> str: ...
    def __contains__(self, key: str, /) -> bool: ...
    @overload
    def get(self, key: str, /) -> str | None: ...
    @overload
    def get(self, key: str, default: str, /) -> str: ...
    def keys(self) -> Iterable[str]: ...
    def items(self) -> Iterable[tuple[str, str]]: ...
```

| Member          | Return Type                    | Description                                                                 |
|-----------------|--------------------------------|-----------------------------------------------------------------------------|
| `__getitem__`   | `str`                          | The value under `key`; `KeyError` (or a subclass) when absent.              |
| `__contains__`  | `bool`                         | Whether a header named `key` is set.                                        |
| `get(key)`      | `str \| None`                  | The value under `key`, or `None` when absent.                               |
| `get(key, default)` | `str`                      | The value under `key`, or `default` when absent.                            |
| `keys()`        | `Iterable[str]`                | The header names; `dict(headers)` reads it.                                 |
| `items()`       | `Iterable[tuple[str, str]]`    | The `(name, value)` pairs the header scan and the CORS check walk.          |

It is not a `Mapping`: Werkzeug `EnvironHeaders` iterates `(name, value)` pairs, so `__iter__` and `__len__` are not part of the surface. Pass the framework's own header object or a plain `dict[str, str]`; lookups use the container's own casing rules, and only a plain `dict` is case-sensitive.

### Implementation Notes

**`state`**: Guard-core sets these attributes on `state` during pipeline execution:

- `state.route_config` -- `RouteConfig | None`
- `state.client_ip` -- `str`
- `state.is_whitelisted` -- `bool`: `True` for a global `whitelist` match unless `whitelist_access_only` is on (the default since 5.0.0), when it is always `False`; `state.whitelist_entry` then holds the matching entry
- `state.is_exempt` -- `bool`

The adapter's `state` object must support dynamic attribute assignment (e.g., a simple namespace or the framework's built-in state).

**`scope`**: guard-core never reads it (`grep -rn 'scope' guard_core` outside `protocols/` finds no read of a request scope), so an empty dict satisfies the protocol. An adapter that resolves routes itself may keep the matched route in it (the Starlette adapter uses `scope["route"]`) and records the result on `state` (`guard_decorator`, `guard_route_id`, `guard_endpoint_id`, `guard_route_unresolved`).

**`body()`**: The detection engine calls `body()` to scan request bodies for threats. Adapters should ensure the body is buffered and can be read multiple times (not consumed on first read).

**`headers`**: Must be iterable via `.items()` for header scanning. Guard-core reads headers case-insensitively in many places (e.g., `headers.get("User-Agent")`), but the mapping itself does not need to be case-insensitive.

___

BoundedBodyReader
------------------

Optional capability protocol. Import it from `guard_core.protocols` (or `guard_core.sync.protocols` for the blocking mirror, `SyncBoundedBodyReader`). An adapter implements it alongside `GuardRequest` to let detection inspect a size-capped prefix of a body whose `Content-Length` is missing or unusable (for example `Transfer-Encoding: chunked`), instead of that body being skipped entirely.

```python
@runtime_checkable
class BoundedBodyReader(Protocol):
    async def read_body_prefix(self, max_bytes: int) -> bytes: ...
```

| Member               | Return Type     | Description                                                    |
|----------------------|-----------------|------------------------------------------------------------------|
| `read_body_prefix()` | `bytes` (async) | Read at most `max_bytes` of the body, from its start.          |

An adapter that only implements `GuardRequest` is still fully valid; guard-core treats the absence of `BoundedBodyReader` as "cannot bound the read" and skips the body rather than reading it in full.

!!! warning "`read_body_prefix` has no engine deadline"
    guard-core awaits `read_body_prefix` (and `GuardRequest.body`) in full with no deadline of its own, because cancelling or abandoning a read half-way can drop bytes the application still needs (`asyncio` cannot safely cancel a call mid-flight, and a blocking call cannot be cancelled from the outside at all). An adapter that wants a stalled client cut off implements [`IdleBoundedBodyReader`](#idleboundedbodyreader). Without it, a client that stops sending holds the request until the server's own timeout (uvicorn has no request-body read timeout, so that is the reverse proxy's or the WSGI server's: gunicorn `--timeout`, uWSGI `harakiri`). guard-core logs one warning per adapter class that names the missing method.

!!! warning "Detection only sees the prefix"
    Whichever mechanism produces the bytes to scan (`Content-Length` under the cap, or `read_body_prefix`), detection only ever inspects the leading `detection_max_body_inspect_bytes` bytes of the body. A payload placed after that many bytes of filler, or a signature split across the boundary, is not detected. This is the deliberate memory/detection tradeoff of bounded-memory scanning, not a bug, and it is not equivalent to full-body scanning.

!!! danger "Implementations must enforce the bound themselves"
    guard-core defensively slices the returned bytes to `max_bytes`, but that slice only trims what `read_body_prefix` already returned -- it cannot stop an implementation from reading or buffering more than `max_bytes` internally first. An implementation that ignores `max_bytes` and reads the full body before returning defeats the memory bound this protocol exists to provide (see [GHSA-xv6g-49vj-7w9c](https://github.com/Guard-Core/guard-core/security/advisories/GHSA-xv6g-49vj-7w9c)). Implementations **must not** buffer more than `max_bytes` while producing the prefix.

### IdleBoundedBodyReader

```python
@runtime_checkable
class IdleBoundedBodyReader(Protocol):
    async def read_body_prefix_until_idle(
        self, max_bytes: int, idle_timeout: float
    ) -> bytes: ...
```

| Member                          | Return Type     | Description                                                                 |
|---------------------------------|-----------------|-----------------------------------------------------------------------------|
| `read_body_prefix_until_idle()` | `bytes` (async) | Read at most `max_bytes` of the body, or raise when the client goes idle.   |

Optional, and consulted first. guard-core resolves the choice once per adapter class: `read_body_prefix_until_idle`, then `read_body_prefix`, then `body`. The deadline measures idle time, not total time: a client that keeps sending is never cut off, however large the upload, and a client that sends no byte for `idle_timeout` seconds is. guard-core passes `SecurityConfig.body_read_timeout` as `idle_timeout`.

- Raise `guard_core.exceptions.BodyReadStalledError` when no byte arrives for `idle_timeout` seconds. guard-core answers `408` when `fail_secure` is on, and logs it, sends a `suspicious_request` event and lets the request through when it is off. Neither counts as a strike.
- Raise `guard_core.exceptions.BodyReadFailedError` when the read fails, such as a dropped connection. guard-core answers `400` under `fail_secure`. Any other exception from the method is treated the same way.
- Never drop consumed bytes: every byte read must still reach the application, so buffer the prefix and replay it before the untouched remainder of the stream.
- The memory obligation of `BoundedBodyReader` applies: do not buffer more than `max_bytes`.
- `SyncIdleBoundedBodyReader` is the blocking mirror. The sync tree calls it on the request thread and never moves the read to another thread. A blocking read cannot be timed from the outside, so a sync adapter applies `idle_timeout` to its stream (Flask and Django map the server's socket timeout to `BodyReadStalledError`).

### Route knowledge

Optional, and what lets an app serve a page that looks like a probe (D-75). A path that a script-extension row (`.php`, `.asp`, `.jsp`, `.py`, `.sh` and the other v4.4.0 extensions), a source-map row or a named probe row (`/management`, `/system/log`, `/language/en`, `wp-admin`, `README.md`, `/en/inicio.html`) matches is flagged by default. It is clean when the route template the adapter matched for the request literally contains the probe token: the extension, the named segment, or the matched last segment. A catch-all or converter such as Starlette `{p:path}` or Flask `<path:filename>` carries no token and does not clear it. An adapter that gives no route knowledge behaves exactly as v4.4.0.

- Record the matched template as `request.state.guard_route_template` (a `str`) next to `guard_route_unresolved` before the pipeline runs. `\.` and `[.]` are unescaped before the test, so a Tornado `r"/(.*)\.php"` declares `.php`. Text inside `{...}` and `<...>` is removed before the test (never `:name`), so a parameter named `language` or `version` does not declare the probe token.
- Or implement `route_template(path) -> str | None` on the middleware. guard-core calls it once per request, in the first check of the pipeline, when the request state has no `guard_route_template` yet and the route is not marked unresolved, and records the raw answer on the state. The same raw template is what the events carry as `route_template` and the metrics carry as their `endpoint` tag, after the engine normalises it (`/orgs/{org}/old/{year}`). Keep an LRU in the adapter and clear it when the route set changes.
- A value in a query or body carries no route and keeps the v4.4.0 behavior.

### Static files

Optional (D-80 item 2). A `.ts` or `.map` URL path under a static-file mount is a served file, not a probe, when the file exists in that mount. Implement `static_file_exists(path) -> bool` on the middleware (`async def` in the async tree, a plain method in the sync tree). guard-core calls it once per request, only when the last segment of the path (case-insensitive, `;params` stripped, a trailing `/` ignored) ends in `.ts` or `.map`, and never when the adapter recorded `guard_route_unresolved`. Answer `True` only when the matched route is a static-file mount and the framework's own traversal-safe lookup finds a regular file in it (Starlette `StaticFiles.lookup_path`, Flask `safe_join` with `os.path.isfile`, Django `safe_join` with `is_file`, Tornado `StaticFileHandler.get_absolute_path` with the root-prefix check of `validate_absolute_path`); any other answer, a non-`True` value or an exception leaves the path flagged. Do not cache the answer: a file that appears or disappears is seen on the next request. The source and dump extensions (`.py`, `.sql`, `.php`, `.java`, `.sh`, `.tsx` and the rest) stay flagged even when the file exists. guard-core records a `True` answer as `request.state.guard_static_file_served`.

___

GuardResponse
-------------

The response protocol defines how guard-core reads and modifies outgoing responses.

```python
@runtime_checkable
class GuardResponse(Protocol):
    @property
    def status_code(self) -> int: ...
    @property
    def headers(self) -> GuardResponseHeaders: ...
    @property
    def body(self) -> bytes | None: ...
```

### Member Details

| Member        | Return Type               | Description                                           |
|---------------|--------------------------|-------------------------------------------------------|
| `status_code` | `int`                    | HTTP status code. Used directly by `status:` return-pattern rules. |
| `headers`     | `GuardResponseHeaders`   | Response headers. Must be mutable for security header injection. |
| `body`        | `bytes \| None`          | Response body bytes, when already fully materialized. **Not** read for behavioral `return_pattern` matching -- see `BoundedResponseBodyReader` below for that. |

### GuardResponseHeaders

```python
class GuardResponseHeaders(Protocol):
    def __getitem__(self, key: str, /) -> str: ...
    def __setitem__(self, key: str, value: str, /) -> None: ...
    def __delitem__(self, key: str, /) -> None: ...
    def __contains__(self, key: str, /) -> bool: ...
    def get(self, key: str, /) -> str | None: ...
    def keys(self) -> Iterable[str]: ...
    def items(self) -> Iterable[tuple[str, str]]: ...
```

| Member         | Return Type                 | Description                                                              |
|----------------|-----------------------------|--------------------------------------------------------------------------|
| `__getitem__`  | `str`                       | The value under `key`; `KeyError` (or a subclass) when absent.           |
| `__setitem__`  | `None`                      | Set `key` to `value`, replacing any value it held.                       |
| `__delitem__`  | `None`                      | Remove `key`; `KeyError` (or a subclass) when absent.                    |
| `__contains__` | `bool`                      | Whether a header named `key` is set.                                     |
| `get(key)`     | `str \| None`               | The value under `key`, or `None` when absent.                            |
| `keys()`       | `Iterable[str]`             | The header names; `dict(headers)` and `{**headers}` read it.             |
| `items()`      | `Iterable[tuple[str, str]]` | The `(name, value)` pairs, as the adapter copies them back out.          |

It is not a `MutableMapping`: Werkzeug `Headers` iterates `(name, value)` pairs and a Django response iterates its body, so `__iter__` and `__len__` are not part of the surface. Pass the framework's own header object (Werkzeug `Headers`, Django `ResponseHeaders`, Starlette `MutableHeaders`, Tornado `HTTPHeaders`) or a plain `dict[str, str]`. `append(name, value)` (Starlette `MutableHeaders`) is an optional extra the engine uses when present.

___

BoundedResponseBodyReader
--------------------------

Optional capability protocol. Import it from `guard_core.protocols` (or `guard_core.sync.protocols` for the blocking mirror, `SyncBoundedResponseBodyReader`). An adapter implements it alongside `GuardResponse` to let `return_pattern` behavior rules (`json:`, `regex:`, bare-substring) inspect a size-capped prefix of the response body, gated by `SecurityConfig.behavior_scan_response_body` (default `False`).

```python
@runtime_checkable
class BoundedResponseBodyReader(Protocol):
    async def read_body_prefix(self, max_bytes: int) -> bytes: ...
```

| Member               | Return Type     | Description                                                    |
|----------------------|-----------------|------------------------------------------------------------------|
| `read_body_prefix()` | `bytes` (async) | Read at most `max_bytes` of the body, from its start, without disrupting delivery of the rest to the client. |

`BehaviorTracker._check_response_pattern` never reads `GuardResponse.body` and never probes for this capability with `hasattr` -- capability detection is an explicit `isinstance` check against this protocol, which is safe because `read_body_prefix` is a plain method rather than a property (an `isinstance` check on a `runtime_checkable` `Protocol` never invokes a method member, only a property member). An adapter that only implements `GuardResponse` is still fully valid; guard-core treats the absence of `BoundedResponseBodyReader` as "cannot evaluate this rule" rather than as "no match" -- it returns `None` from `_check_response_pattern` (distinct from `False`) and logs a throttled warning, instead of silently reporting no match. Inside `process_response` the read is shared across the rules of one response (and with a `custom_response_modifier` that reads `.body`, see the `custom_response_modifier_max_body_bytes` field): one bounded (async tree) or unbounded (sync tree) read per response. A `custom_response_modifier` that reads `.body` makes the engine call `read_body_prefix(max_bytes)` with `max_bytes` covering the declared `Content-Length`; for that call the implementation must return the whole body (every chunk up to `max_bytes`) rather than stop at the first chunk, and the engine gives the modifier the bytes only when their length equals the declared `Content-Length`.

!!! danger "Lockstep upgrade required for every adapter"
    Before this capability existed, `_check_response_pattern` read `GuardResponse.body` directly (guarded by `hasattr`). For an **ordinary, non-streaming** response whose `.body` is a plain, non-raising, already-materialized attribute, that old codepath matched correctly. It does **not** match under the current release, `behavior_scan_response_body=True` or not, until the adapter implements `BoundedResponseBodyReader.read_body_prefix`. guard-core, fastapi-guard, flaskapi-guard, and djapi-guard are separate repositories, each adapter pins `guard-core` with no version constraint, and upgrading guard-core alone -- without also upgrading the adapter to a release that implements this protocol -- silently drops every body-reading `return_pattern` rule for that adapter, with no error and no signal beyond the pre-existing throttled could-not-evaluate log line. `status:` patterns are unaffected, since they never touch the body.

!!! danger "A streaming response must keep streaming"
    Unlike the request side, guard-core does not own delivery of the response to the client -- the adapter does, after the security pipeline returns. `read_body_prefix` MUST NOT consume the underlying stream to completion, MUST NOT block waiting for more data than the stream is currently ready to produce (an indefinite stream such as server-sent events or long polling may never reach `max_bytes`), and the response object MUST still deliver its complete, unbounded body to the client afterward exactly as if `read_body_prefix` had never been called. The standard implementation shape is a tee: buffer chunks up to `max_bytes` from the underlying stream, return that prefix, and replace the outgoing body iterator with one that replays the buffered bytes followed by the untouched remainder of the original stream. Buffer-then-forward (reading the whole body before sending any of it to the client) is not an acceptable implementation: it turns every large download into a memory spike and breaks SSE and long polling.

!!! danger "Implementations must enforce the bound themselves"
    Exactly as with `BoundedBodyReader` on the request side (see [GHSA-xv6g-49vj-7w9c](https://github.com/Guard-Core/guard-core/security/advisories/GHSA-xv6g-49vj-7w9c)): guard-core defensively slices the returned bytes to `max_bytes`, but that slice only trims what `read_body_prefix` already returned -- it cannot stop an implementation from reading or buffering more than `max_bytes` internally first, and it cannot force a streaming response to keep streaming. Implementations **must not** buffer more than `max_bytes` while producing the prefix. On requests the attacker controls the body directly; on responses the attacker controls only which endpoint they hit and the application produces the body, so any large streaming endpoint (a file download, an export, an SSE stream) can force this read on every request through it once `behavior_scan_response_body` is enabled -- size the cap and pick routes accordingly.

___

MaterializedBodyResponse
------------------------

Optional capability protocol. An adapter implements it alongside `GuardResponse` to say the response already holds its whole body in memory.

```python
@runtime_checkable
class MaterializedBodyResponse(Protocol):
    @property
    def body_is_materialized(self) -> bool: ...
```

| Member                 | Return Type | Description                                                                                  |
|------------------------|-------------|----------------------------------------------------------------------------------------------|
| `body_is_materialized` | `bool`      | `True` when the whole body is in memory, so reading `body` costs nothing and consumes nothing. |

It is read once per response by `custom_response_modifier` handling. When it is exactly `True`, the modifier gets the real response: real `body` bytes, one call, no view, no prefetch and no `custom_response_modifier_max_body_bytes` cap. Absent, `False` or any other value keeps the bounded path. Derive it from the framework's own signal, read before anything touches the body: Starlette `Response` holds `body` (`FileResponse` and `StreamingResponse` do not), Django `not response.streaming`, Werkzeug `not response.is_streamed` read before `.data`, Tornado a buffered write rather than a chunked one.

___

GuardResponseFactory
--------------------

Adapters must provide a factory that creates framework-native response objects.

```python
@runtime_checkable
class GuardResponseFactory(Protocol):
    def create_response(self, content: str, status_code: int) -> GuardResponse: ...
    def create_redirect_response(self, url: str, status_code: int) -> GuardResponse: ...
```

| Method                    | Purpose                                                    |
|---------------------------|------------------------------------------------------------|
| `create_response`         | Creates a plain text/JSON error response.                  |
| `create_redirect_response`| Creates an HTTP redirect (used for HTTPS enforcement).     |

___

GuardMiddlewareProtocol
-----------------------

Defines the interface that the adapter's middleware class must expose to the security check pipeline.

```python
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

### Attributes

| Attribute                   | Type                  | Description                                       |
|-----------------------------|-----------------------|---------------------------------------------------|
| `config`                    | `SecurityConfig`      | The security configuration.                       |
| `logger`                    | `logging.Logger`      | Logger instance for the middleware.                |
| `last_cloud_ip_refresh`     | `int`                 | Timestamp of the last cloud IP refresh.           |
| `suspicious_request_counts` | `dict[str, dict[str, int]]` | Nested counters indexed by IP, then by detection category (`xss`, `sqli`, `custom`, ...). Read the total via `sum(values())`. |

### Properties

| Property                | Purpose                                                 |
|-------------------------|---------------------------------------------------------|
| `guard_decorator`       | The route-decorator registry, or `None` when no route is decorated. The engine reads it with a `None` default, so a middleware that has no such attribute works and has no route configs. |
| `event_bus`             | `SecurityEventBusProtocol` for emitting security events. |
| `route_resolver`        | `RouteResolverProtocol` for decorator resolution.       |
| `response_factory`      | `ResponseFactoryProtocol` for the engine's responses, or `None` for a host that builds none. |
| `rate_limit_handler`    | `RateLimitHandlerProtocol` or `None`.                   |
| `agent_handler`         | `AgentHandlerProtocol` or `None`.                       |
| `geo_ip_handler`        | `GeoIPHandler` (the handler of this tree) or `None`.    |
| `guard_response_factory`| `GuardResponseFactory` from the adapter, or `None`.     |

### Methods

| Method                                          | Return Type              | Description                                                                 |
|-------------------------------------------------|--------------------------|-----------------------------------------------------------------------------|
| `create_error_response(status_code, default_message)` (async) | `GuardResponse` | The error response for a denied request: the configured custom message for `status_code`, else `default_message`. |
| `refresh_cloud_ip_ranges()` (async)             | `None`                   | Refresh the cached cloud-provider ranges and update `last_cloud_ip_refresh`. |

### Middleware sub-protocols

Defined in `guard_core/protocols/middleware_protocol.py`. They are not `@runtime_checkable`.

```python
class RouteDecoratorRegistryProtocol(Protocol):
    @property
    def _route_configs(self) -> Mapping[str, RouteConfig]: ...
    @property
    def route_config_revision(self) -> int: ...


class RateLimitHandlerProtocol(Protocol):
    @property
    def redis_handler(self) -> RedisHandlerProtocol | None: ...
    @property
    def agent_handler(self) -> AgentHandlerProtocol | None: ...
    async def check_rate_limit_tiers(
        self,
        request: GuardRequest,
        client_ip: str,
        create_error_response: Callable[[int, str], Awaitable[GuardResponse]],
        tiers: Sequence[RateLimitTier],
        config: SecurityConfig | None = None,
        window_identity: str | None = None,
        verdict: RateLimitVerdict | None = None,
    ) -> RateLimitBlock | None: ...
    async def report_rate_limit_block(
        self,
        request: GuardRequest,
        client_ip: str,
        block: RateLimitBlock,
        tier: RateLimitTier,
        config: SecurityConfig | None = None,
        attribution: dict[str, object] | None = None,
    ) -> None: ...


class SecurityEventBusProtocol(Protocol):
    @property
    def agent_handler(self) -> AgentHandlerProtocol | None: ...
    async def send_middleware_event(
        self,
        event_type: str,
        request: GuardRequest,
        action_taken: str,
        reason: str,
        **kwargs: object,
    ) -> None: ...
    async def send_https_violation_event(
        self, request: GuardRequest, route_config: RouteConfig | None
    ) -> None: ...
    async def send_cloud_detection_events(
        self,
        request: GuardRequest,
        client_ip: str,
        cloud_providers_to_check: list[str],
        route_config: RouteConfig | None,
        cloud_handler: CloudManager,
        passive_mode: bool,
        cloud_details: tuple[str, str] | None = None,
        attribution: dict[str, object] | None = None,
    ) -> None: ...


class RouteResolverProtocol(Protocol):
    def get_route_config(self, request: GuardRequest) -> RouteConfig | None: ...
    def should_bypass_check(
        self, check_name: str, route_config: RouteConfig | None
    ) -> bool: ...
    def get_cloud_providers_to_check(
        self, route_config: RouteConfig | None
    ) -> list[str] | None: ...


class ResponseFactoryProtocol(Protocol):
    @property
    def security_headers_manager(self) -> object: ...
    async def create_https_redirect(self, request: GuardRequest) -> GuardResponse: ...
    async def apply_modifier(
        self, response: GuardResponse, request: GuardRequest | None = None
    ) -> GuardResponse: ...
```

| Protocol                         | Member                                  | Description                                                              |
|----------------------------------|-----------------------------------------|--------------------------------------------------------------------------|
| `RouteDecoratorRegistryProtocol` | `_route_configs`                        | Every decorated route's config, keyed by route id.                       |
|                                  | `route_config_revision`                 | Changes whenever a route config is added or edited.                      |
| `RateLimitHandlerProtocol`       | `redis_handler`                         | The shared Redis backend, or `None` when rate limits are in memory.      |
|                                  | `agent_handler`                         | The agent the handler reports blocks to, or `None`.                      |
|                                  | `check_rate_limit_tiers(...)`           | Count the request against the tiers; the block it hit, or `None`.        |
|                                  | `report_rate_limit_block(...)`          | Report a rate-limit block to the agent.                                  |
| `SecurityEventBusProtocol`       | `agent_handler`                         | The agent the bus forwards events to, or `None`.                         |
|                                  | `send_middleware_event(...)`            | Send one security event to the agent.                                    |
|                                  | `send_https_violation_event(...)`       | Send the event for a request that required HTTPS.                        |
|                                  | `send_cloud_detection_events(...)`      | Send the events for a request from a blocked cloud provider.             |
| `RouteResolverProtocol`          | `get_route_config(request)`             | The request's route config, or `None`.                                   |
|                                  | `should_bypass_check(check_name, route_config)` | `True` when the route bypasses the named check.                  |
|                                  | `get_cloud_providers_to_check(route_config)` | The cloud providers to block for the route, or `None`.              |
| `ResponseFactoryProtocol`        | `security_headers_manager`              | The security-headers manager; readers check its type.                    |
|                                  | `create_https_redirect(request)` (async) | Build the redirect to the HTTPS URL.                                    |
|                                  | `apply_modifier(response, request=None)` (async) | Run the configured response modifier over the response.         |

___

GeoIPHandler
------------

Protocol for geolocation services. Adapters can provide any implementation (MaxMind, IPInfo, custom).

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

| Method            | Description                                         |
|-------------------|-----------------------------------------------------|
| `is_initialized`  | Whether the handler has been initialized.           |
| `initialize()`    | Perform async initialization (e.g., download DB).   |
| `initialize_redis(redis_handler)` | Attach the shared Redis backend for caching the dataset across workers. |
| `initialize_agent(agent_handler)` | Attach the agent so dataset-refresh failures can be reported. |
| `get_country(ip)` | Return ISO country code for the IP, or `None`.      |
| `refresh()`       | Reload the dataset from source (periodic update). Required by the protocol even if a given implementation makes it a no-op. |
| `close()`         | Release the dataset/file handles.                   |

___

RedisHandlerProtocol
--------------------

Protocol for every Redis operation the engine calls. `RedisManager` implements all of it, and startup checks a handler for every member.

```python
@runtime_checkable
class RedisHandlerProtocol(Protocol):
    config: SecurityConfig

    async def get_key(self, namespace: str, key: str) -> str | None: ...
    async def get_many(self, pairs: Sequence[tuple[str, str]]) -> list[str | None]: ...
    async def set_key(
        self, namespace: str, key: str, value: RedisValue, ttl: int | None = None
    ) -> bool | None: ...
    async def set_key_if_absent(
        self, namespace: str, key: str, value: RedisValue, ttl: int | None = None
    ) -> bool: ...
    async def incr(
        self, namespace: str, key: str, ttl: int | None = None
    ) -> int | None: ...
    async def write_atomically(
        self,
        *,
        sets: Sequence[tuple[str, str, RedisValue, int | None]] = (),
        deletes: Sequence[tuple[str, str]] = (),
        increment: tuple[str, str] | None = None,
    ) -> None: ...
    async def delete(self, namespace: str, key: str) -> int | None: ...
    async def delete_pattern(self, pattern: str) -> int | None: ...
    async def keys(self, pattern: str) -> list[str] | None: ...
    async def write_ban_extending_only(
        self,
        namespace: str,
        key: str,
        expiry: str,
        duration: int,
        *,
        version: tuple[str, str],
        advance_version: bool = False,
        rule_owned: bool = False,
    ) -> float: ...
    async def owned_ban_members(self) -> list[str]: ...
    async def owned_ban_state(
        self, namespace: str, key: str
    ) -> tuple[float | None, float | None]: ...
    async def purge_owned_ban(self, member: str) -> int: ...
    async def disown_ban(self, namespace: str, key: str) -> None: ...
    async def record_sliding_window_hit(
        self,
        namespace: str,
        key: str,
        timestamp: float,
        window_start: float,
        ttl: int,
        *,
        index: tuple[str, int] | None = None,
        index_refused: list[bool] | None = None,
    ) -> int: ...
    async def count_sliding_window_hits(
        self, namespace: str, key: str, window_start: float
    ) -> int: ...
    async def sum_indexed_window_hits(
        self, namespace: str, index_key: str, window_start: float
    ) -> int: ...
    def detection_correlation_keys(self, client_ip: str) -> list[str]: ...
    async def record_detection_strikes(
        self,
        client_ip: str,
        categories: Sequence[str],
        timestamp: float,
        window_start: float,
        ttl: int,
        cap: int,
    ) -> tuple[int, int, dict[str, int]]: ...
    async def read_detection_categories(
        self, client_ip: str, window_start: float
    ) -> list[str]: ...
    async def forget_detection_strikes(self, client_ip: str) -> None: ...
    async def initialize(self) -> None: ...
    async def initialize_agent(self, agent_handler: AgentHandlerProtocol) -> None: ...
    def get_connection(self) -> AsyncContextManager[Redis]: ...
    def is_connected(self) -> bool: ...
```

`config` is read directly: the engine uses `config.redis_prefix` and the Redis switches. `get_connection()` must yield a redis-py-compatible asyncio client, because the engine runs pipelines, `evalsha`, `scan_iter`, `zrange` and `execute_command("MGET")` on it. At startup, a handler that lacks any member is reported once with every missing name, through the same path as the other misconfigurations: a warning with `fail_on_misconfiguration=False`, a refusal to start with it on.

### SecurityHeadersRedisHandler

`@runtime_checkable`. The four members the security headers override path calls on a handler: `config: SecurityConfig`, `async get_key(namespace, key) -> str | None`, `async set_key(namespace, key, value, ttl=None) -> bool | None` and `get_connection() -> AsyncContextManager[Redis]`, with the same meaning as on `RedisHandlerProtocol`. A handler registered under a config is kept for that path when it has these four, whatever else of `RedisHandlerProtocol` it lacks.

A handler that implements the members directly keeps its live client in `_redis` (`None` while disconnected): after a cold start under `redis_fail_open` the engine reads that attribute to tell whether a reconnect succeeded. `is_connected()` answers the same question for a handler that keeps its client elsewhere; the engine calls it when the handler has it and falls back to `_redis` otherwise.

### RedisHandlerBase

Subclass `RedisHandlerBase` (importable from `guard_core` and `guard_core.handlers`) to plug in your own connection handling and keep every other method as `RedisManager` has it. It extends `RedisManager`, so the Lua scripts and the key layout exist once, and unlike `RedisManager` it is not a singleton: each instance keeps its own `config` and client.

```python
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from redis.asyncio import Redis

from guard_core import RedisHandlerBase


class MyRedisHandler(RedisHandlerBase):
    def __init__(self, config, client: Redis) -> None:
        self.config = config
        self._client = client

    async def initialize(self) -> None:
        await self._client.ping()

    @asynccontextmanager
    async def get_connection(self) -> AsyncIterator[Redis]:
        yield self._client
```

Override `initialize` and `get_connection` to bring your own client; the inherited `initialize` and `get_connection` open `RedisManager`'s own pool from `config`. Override any other method to change it. The synchronous tree has the same class in `guard_core.sync`.

___

AgentHandlerProtocol
--------------------

Protocol for the Guard Agent telemetry system.

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

| Member                       | Return Type                 | Description                                                              |
|------------------------------|-----------------------------|--------------------------------------------------------------------------|
| `initialize_redis(redis_handler)` (async) | `None`         | Attach the shared Redis backend used for cross-worker buffering.         |
| `send_event(event)` (async)  | `None`                      | Enqueue a security event for delivery. Must not block or raise.          |
| `send_metric(metric)` (async)| `None`                      | Enqueue a metric for delivery. Must not block or raise.                  |
| `start()` (async)            | `None`                      | Start the background buffering/flush and rule-sync loops.                |
| `stop()` (async)             | `None`                      | Stop the background loops and release resources. Must be idempotent.     |
| `flush_buffer()` (async)     | `None`                      | Force an immediate send of any buffered events and metrics.              |
| `get_dynamic_rules()` (async)| `DynamicRulesProtocol \| None` | The latest dynamic rules, or `None` when none are available.           |
| `health_check()` (async)     | `bool`                      | `True` when the agent can reach its collector.                           |
| `get_stats()`                | `dict[str, JsonValue]`      | The handler's counters as a JSON-shaped mapping.                         |

`JsonValue` is `str | int | float | bool | None | list[JsonValue] | dict[str, JsonValue]` (`guard_core/protocols/agent_protocol.py`).

### DynamicRulesProtocol

`@runtime_checkable`. The read-only view of one rule set that `AgentHandlerProtocol.get_dynamic_rules` returns on every rule poll. `guard_core.models.DynamicRules` and guard-agent's own `DynamicRules` satisfy it as they are. Every member is a property:

| Property                      | Type                              |
|-------------------------------|-----------------------------------|
| `rule_id`                     | `str`                             |
| `version`                     | `int`                             |
| `timestamp`                   | `datetime`                        |
| `expires_at`                  | `datetime \| None`                |
| `ttl`                         | `int`                             |
| `ip_blacklist`                | `list[str]`                       |
| `ip_whitelist`                | `list[str]`                       |
| `ip_ban_duration`             | `int`                             |
| `blocked_countries`           | `list[str]`                       |
| `whitelist_countries`         | `list[str]`                       |
| `global_rate_limit`           | `int \| None`                     |
| `global_rate_window`          | `int \| None`                     |
| `endpoint_rate_limits`        | `dict[str, tuple[int, int]]`      |
| `blocked_cloud_providers`     | `set[str]`                        |
| `blocked_user_agents`         | `list[str]`                       |
| `suspicious_patterns`         | `list[str]`                       |
| `enable_penetration_detection`| `bool \| None`                    |
| `enable_ip_banning`           | `bool \| None`                    |
| `enable_rate_limiting`        | `bool \| None`                    |
| `auto_ban_threshold`          | `int \| None`                     |
| `auto_ban_duration`           | `int \| None`                     |
| `enable_rate_limit_auto_ban`  | `bool \| None`                    |
| `emergency_mode`              | `bool`                            |
| `emergency_whitelist`         | `list[str]`                       |
| `emergency_whitelist_only`    | `bool`                            |

___

CloudIpStoreProtocol
--------------------

```python
@runtime_checkable
class CloudIpStoreProtocol(Protocol):
    async def get(self, provider: str) -> set[str] | None: ...
    async def set(
        self, provider: str, ranges: set[str], ttl: int | None = None
    ) -> None: ...
    async def clear(self) -> None: ...


CloudIpStoreFactory = Callable[[RedisHandlerProtocol | None], CloudIpStoreProtocol]
```

| Member                     | Description                                                                                       |
|----------------------------|---------------------------------------------------------------------------------------------------|
| `get(provider)`            | The cached CIDR ranges for `provider`, or `None` on a miss (an empty set means known, no ranges). |
| `set(provider, ranges, ttl=None)` | Cache `ranges` for `provider`, expiring after `ttl` seconds.                               |
| `clear()`                  | Drop all cached provider ranges.                                                                  |

See [Cloud IP store](cloud-ip-store.md) for the contract and the default implementation.

___

RouteIdentity
-------------

```python
class RouteIdentity(NamedTuple):
    handler: object
    path_params: tuple[tuple[str, str], ...]
```

The handler a router dispatches to, plus the path parameters it captured. It is an in-process dict key, never persisted and never sent to Redis. `handler` is the dispatched object itself (function, class plus method name tuple, ...), never a qualname string, so two handlers that share a name never compare equal. `path_params` holds the router's converted values as strings, sorted by name, positional args as `"0"`, `"1"`. Import it from `guard_core.protocols`.
