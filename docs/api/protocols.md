---

title: Protocols
description: The protocol interfaces that adapters must implement to integrate guard-core with any Python web framework
keywords: protocols, guard request, guard response, middleware protocol, adapter development, guard-core
---

Protocols
=========

Protocols are the most important API surface for adapter developers. Guard-core uses Python `Protocol` classes (PEP 544) to define the contracts that adapters must satisfy. All protocols are `@runtime_checkable`.

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
    def headers(self) -> Mapping[str, str]: ...
    @property
    def query_params(self) -> Mapping[str, str]: ...
    async def body(self) -> bytes: ...
    @property
    def state(self) -> Any: ...
    @property
    def scope(self) -> dict[str, Any]: ...
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
| `headers`           | `Mapping[str, str]` | Request headers as a read-only mapping. Case handling depends on adapter. |
| `query_params`      | `Mapping[str, str]` | URL query parameters as a read-only mapping.                  |
| `body()`            | `bytes` (async)     | The raw request body. May be called multiple times by detection checks. |
| `state`             | `Any`               | A mutable state object for passing data between checks. Must support attribute assignment. |
| `scope`             | `dict[str, Any]`    | ASGI-style scope dict. Used for route resolution (`scope["route"]`). |

### Implementation Notes

**`state`**: Guard-core sets these attributes on `state` during pipeline execution:

- `state.route_config` -- `RouteConfig | None`
- `state.client_ip` -- `str`
- `state.is_whitelisted` -- `bool`
- `state.is_exempt` -- `bool`

The adapter's `state` object must support dynamic attribute assignment (e.g., a simple namespace or the framework's built-in state).

**`scope`**: Must include a `"route"` key with an object that has an `endpoint` attribute for decorator resolution. If the framework does not have route objects in scope, decorator-based features will not activate.

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

!!! warning "The call is timeout-bounded in the async tree only"
    In `guard_core` (async), guard-core waits at most `SecurityConfig.body_read_timeout` seconds (default `3.0`) for `read_body_prefix` to return, whether the adapter is implementing `BoundedBodyReader` or `GuardRequest.body`. A stalled adapter (a stuck SSE producer, a long-poll that never yields, a buggy implementation) degrades to the same fail-closed "body unavailable" outcome a raising reader already produces, instead of hanging the request indefinitely. The stalled call itself cannot be cancelled -- `asyncio` cannot safely kill a call mid-flight -- so it keeps running in the background after guard-core gives up waiting on it; the timeout bounds guard-core's own wait, not the adapter's work. In `guard_core.sync`, `read_body_prefix`/`body` is called directly with no bound at all: `body_read_timeout` is ignored, and a stalled sync adapter blocks the request for as long as it takes, exactly like any other slow call in a WSGI application. Bound it at the WSGI server instead (gunicorn `--timeout`, uWSGI `harakiri`); guard-core does not and cannot safely cancel a blocking call from the outside without spawning unbounded background threads, which an earlier release of this protocol did and removed after it proved to leak threads under a sustained stall and silently drop detection under ordinary concurrent load once its fixed thread pool was exhausted.

!!! warning "Detection only sees the prefix"
    Whichever mechanism produces the bytes to scan (`Content-Length` under the cap, or `read_body_prefix`), detection only ever inspects the leading `detection_max_body_inspect_bytes` bytes of the body. A payload placed after that many bytes of filler, or a signature split across the boundary, is not detected. This is the deliberate memory/detection tradeoff of bounded-memory scanning, not a bug, and it is not equivalent to full-body scanning.

!!! danger "Implementations must enforce the bound themselves"
    guard-core defensively slices the returned bytes to `max_bytes`, but that slice only trims what `read_body_prefix` already returned -- it cannot stop an implementation from reading or buffering more than `max_bytes` internally first. An implementation that ignores `max_bytes` and reads the full body before returning defeats the memory bound this protocol exists to provide (see [GHSA-xv6g-49vj-7w9c](https://github.com/Guard-Core/guard-core/security/advisories/GHSA-xv6g-49vj-7w9c)). Implementations **must not** buffer more than `max_bytes` while producing the prefix.

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
    def headers(self) -> MutableMapping[str, str]: ...
    @property
    def body(self) -> bytes | None: ...
```

### Member Details

| Member        | Return Type               | Description                                           |
|---------------|--------------------------|-------------------------------------------------------|
| `status_code` | `int`                    | HTTP status code. Used directly by `status:` return-pattern rules. |
| `headers`     | `MutableMapping[str, str]`| Response headers. Must be mutable for security header injection. |
| `body`        | `bytes \| None`          | Response body bytes, when already fully materialized. **Not** read for behavioral `return_pattern` matching -- see `BoundedResponseBodyReader` below for that. |

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

`BehaviorTracker._check_response_pattern` never reads `GuardResponse.body` and never probes for this capability with `hasattr` -- capability detection is an explicit `isinstance` check against this protocol, which is safe because `read_body_prefix` is a plain method rather than a property (an `isinstance` check on a `runtime_checkable` `Protocol` never invokes a method member, only a property member). An adapter that only implements `GuardResponse` is still fully valid; guard-core treats the absence of `BoundedResponseBodyReader` as "cannot evaluate this rule" rather than as "no match" -- it returns `None` from `_check_response_pattern` (distinct from `False`) and logs a throttled warning, instead of silently reporting no match. This read is not cached across rules: each `return_pattern` rule checked against a response calls `read_body_prefix` independently and pays its own bounded (async tree) or unbounded (sync tree) read.

!!! danger "Lockstep upgrade required for every adapter"
    Before this capability existed, `_check_response_pattern` read `GuardResponse.body` directly (guarded by `hasattr`). For an **ordinary, non-streaming** response whose `.body` is a plain, non-raising, already-materialized attribute, that old codepath matched correctly. It does **not** match under the current release, `behavior_scan_response_body=True` or not, until the adapter implements `BoundedResponseBodyReader.read_body_prefix`. guard-core, fastapi-guard, flaskapi-guard, and djapi-guard are separate repositories, each adapter pins `guard-core` with no version constraint, and upgrading guard-core alone -- without also upgrading the adapter to a release that implements this protocol -- silently drops every body-reading `return_pattern` rule for that adapter, with no error and no signal beyond the pre-existing throttled could-not-evaluate log line. `status:` patterns are unaffected, since they never touch the body.

!!! danger "A streaming response must keep streaming"
    Unlike the request side, guard-core does not own delivery of the response to the client -- the adapter does, after the security pipeline returns. `read_body_prefix` MUST NOT consume the underlying stream to completion, MUST NOT block waiting for more data than the stream is currently ready to produce (an indefinite stream such as server-sent events or long polling may never reach `max_bytes`), and the response object MUST still deliver its complete, unbounded body to the client afterward exactly as if `read_body_prefix` had never been called. The standard implementation shape is a tee: buffer chunks up to `max_bytes` from the underlying stream, return that prefix, and replace the outgoing body iterator with one that replays the buffered bytes followed by the untouched remainder of the original stream. Buffer-then-forward (reading the whole body before sending any of it to the client) is not an acceptable implementation: it turns every large download into a memory spike and breaks SSE and long polling.

!!! danger "Implementations must enforce the bound themselves"
    Exactly as with `BoundedBodyReader` on the request side (see [GHSA-xv6g-49vj-7w9c](https://github.com/Guard-Core/guard-core/security/advisories/GHSA-xv6g-49vj-7w9c)): guard-core defensively slices the returned bytes to `max_bytes`, but that slice only trims what `read_body_prefix` already returned -- it cannot stop an implementation from reading or buffering more than `max_bytes` internally first, and it cannot force a streaming response to keep streaming. Implementations **must not** buffer more than `max_bytes` while producing the prefix. On requests the attacker controls the body directly; on responses the attacker controls only which endpoint they hit and the application produces the body, so any large streaming endpoint (a file download, an export, an SSE stream) can force this read on every request through it once `behavior_scan_response_body` is enabled -- size the cap and pick routes accordingly.

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
    def event_bus(self) -> Any: ...
    @property
    def route_resolver(self) -> Any: ...
    @property
    def response_factory(self) -> Any: ...
    @property
    def rate_limit_handler(self) -> Any: ...
    @property
    def agent_handler(self) -> Any: ...
    @property
    def geo_ip_handler(self) -> Any: ...
    @property
    def guard_response_factory(self) -> Any: ...

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
| `event_bus`             | `SecurityEventBus` for emitting security events.        |
| `route_resolver`        | `RouteConfigResolver` for decorator resolution.         |
| `response_factory`      | `ErrorResponseFactory` for creating error responses.    |
| `rate_limit_handler`    | `RateLimitManager` instance.                            |
| `agent_handler`         | Agent handler or `None`.                                |
| `geo_ip_handler`        | `GeoIPHandler` or `None`.                               |
| `guard_response_factory`| `GuardResponseFactory` from the adapter.                |

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
| `get_country(ip)` | Return ISO country code for the IP, or `None`.      |
| `refresh()`       | Reload the dataset from source (periodic update). Required by the protocol even if a given implementation makes it a no-op. |
| `close()`         | Release the dataset/file handles.                   |

___

RedisHandlerProtocol
--------------------

Protocol for Redis operations. Matches the `RedisManager` interface.

```python
@runtime_checkable
class RedisHandlerProtocol(Protocol):
    async def get_key(self, namespace: str, key: str) -> Any: ...
    async def set_key(
        self, namespace: str, key: str, value: Any, ttl: int | None = None
    ) -> bool | None: ...
    async def delete(self, namespace: str, key: str) -> int | None: ...
    async def keys(self, pattern: str) -> list[str] | None: ...
    async def initialize(self) -> None: ...
    def get_connection(self) -> AsyncContextManager[Any]: ...
```

___

AgentHandlerProtocol
--------------------

Protocol for the Guard Agent telemetry system.

```python
@runtime_checkable
class AgentHandlerProtocol(Protocol):
    async def initialize_redis(self, redis_handler: RedisHandlerProtocol) -> None: ...
    async def send_event(self, event: Any) -> None: ...
    async def send_metric(self, metric: Any) -> None: ...
    async def start(self) -> None: ...
    async def stop(self) -> None: ...
    async def flush_buffer(self) -> None: ...
    async def get_dynamic_rules(self) -> Any | None: ...
    async def health_check(self) -> bool: ...
```
