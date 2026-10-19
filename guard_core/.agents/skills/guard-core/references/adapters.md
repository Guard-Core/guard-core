# Adapters

Implement three protocols to bridge a framework into the guard-core pipeline. Everything else (checks, detection, Redis, telemetry) works out of the box.

## GuardRequest

```python
from guard_core.protocols import GuardRequest


class MyFrameworkRequest:
    def __init__(self, native_request):
        self._request = native_request

    @property
    def url_path(self) -> str:
        return self._request.path

    @property
    def url_scheme(self) -> str:
        return self._request.scheme

    @property
    def url_full(self) -> str:
        return str(self._request.url)

    def url_replace_scheme(self, scheme: str) -> str:
        return self.url_full.replace(f"{self.url_scheme}://", f"{scheme}://", 1)

    @property
    def method(self) -> str:
        return self._request.method

    @property
    def client_host(self) -> str | None:
        return self._request.remote_addr

    @property
    def headers(self):
        return dict(self._request.headers)

    @property
    def query_params(self):
        return dict(self._request.args)

    async def body(self) -> bytes:
        return await self._request.body()

    @property
    def state(self):
        return self._request.state

    @property
    def scope(self) -> dict:
        return self._request.scope
```

### `client_host` and a missing peer address

Return `None` from `client_host` only for a genuinely absent connecting-peer address (for example a Unix domain socket transport, or a misbehaving ASGI/WSGI server that never sets one) -- not as a placeholder for "not yet known" or "trust the forwarded header instead." `None` is a real branch guard-core acts on before the security pipeline even runs: `BypassHandler.handle_passthrough` (`guard_core/core/bypass/handler.py`) resolves an identity via `extract_client_ip`, and if that resolves to `"unknown"` (the fallback whenever there is no peer address and no `"unix"` token in `trusted_proxies` to authorize trusting `X-Forwarded-For` instead), `fail_secure=True` (the default) rejects the request with 403 before any check runs. An adapter fronted by a real reverse proxy should always populate `client_host` with the connecting socket peer (never `None`) and let guard-core's `trusted_proxies`/`X-Forwarded-For` handling resolve the real client from there; only a genuinely peer-less transport should return `None`, and that deployment then needs `"unix"` in `trusted_proxies` to keep working. See [the pipeline reference](pipeline.md#pre-pipeline-missing-client-address) for the full mechanism.

## Bounded body reading

Two optional capability protocols let guard-core inspect a size-capped prefix of a body without buffering the rest. Both are separate from `GuardRequest`/`GuardResponse`: an adapter that implements only the base protocol is still fully valid, and guard-core treats the absence of the capability as cannot bound the read rather than reading the body in full.

`BoundedBodyReader` (`guard_core/protocols/request_protocol.py:73-104`) is implemented alongside `GuardRequest`: `async def read_body_prefix(self, max_bytes: int) -> bytes`. It is consulted when a request has no usable `Content-Length` (for example chunked transfer encoding), so the body can still be inspected for penetration detection up to `detection_max_body_inspect_bytes` instead of being skipped entirely. Read from the underlying stream and stop at `max_bytes`; do not buffer more than `max_bytes` internally while producing the prefix, the memory obligation guard-core cannot enforce from the caller side (GHSA-xv6g-49vj-7w9c).

`BoundedResponseBodyReader` (`guard_core/protocols/response_protocol.py:55-113`) is implemented alongside `GuardResponse`: the same `async def read_body_prefix(self, max_bytes: int) -> bytes` signature, consulted by `return_pattern` behavior rules (`json:`, `regex:`, bare substring) when `SecurityConfig.behavior_scan_response_body` is `True`, bounded by `behavior_max_response_body_inspect_bytes`. Unlike the request side, `GuardResponse.body` is not a safe fallback here: an adapter may implement it as a property that raises for a response whose body is not yet fully materialized (a streaming response in particular), and that raise is indistinguishable from no body to a caller that cannot see inside the property, so `BoundedResponseBodyReader` is the only sanctioned way to read response body bytes for pattern matching. Implement it by teeing the outgoing body stream: consume chunks, buffer only up to `max_bytes`, return that prefix, and still deliver the complete, unbounded body to the client afterward exactly as if the method had never been called, typically by replacing the body iterator with one that first replays the captured prefix and then continues the original iterator untouched. Never consume the underlying stream to completion or block waiting for more data than it is currently ready to produce; an indefinite stream (server-sent events, long polling) may never reach `max_bytes`, so return whatever prefix is available at the first natural stopping point instead.

`IdleBoundedBodyReader` (`guard_core/protocols/request_protocol.py`) is the optional request-side method guard-core tries first: `async def read_body_prefix_until_idle(self, max_bytes: int, idle_timeout: float) -> bytes`. guard-core passes `SecurityConfig.body_read_timeout` as `idle_timeout`. Raise `guard_core.exceptions.BodyReadStalledError` when no byte arrives for `idle_timeout` seconds (guard-core answers 408 under `fail_secure`, with a log line and an event and no strike) and `guard_core.exceptions.BodyReadFailedError` when the read fails (400). Never drop consumed bytes: buffer the prefix and replay it before the untouched remainder of the stream. guard-core resolves the reader once per adapter class: `read_body_prefix_until_idle`, then `read_body_prefix`, then `body`. The older two are awaited in full with no deadline of their own and one warning names the missing method. `SyncIdleBoundedBodyReader` is the blocking mirror: the sync tree calls it on the request thread and never starts a thread for the read, so a sync adapter applies the idle timeout to its stream or maps the server's socket timeout to `BodyReadStalledError`.

The protocols are reachable as `guard_core.BoundedBodyReader` and `guard_core.BoundedResponseBodyReader` (`guard_core/protocols/__init__.py`, which also exports `IdleBoundedBodyReader`), with blocking mirrors `guard_core.sync.SyncBoundedBodyReader`, `guard_core.sync.SyncBoundedResponseBodyReader` and `SyncIdleBoundedBodyReader` (`guard_core.sync.protocols`). A limit on concurrent request-body reads is opt-in in the async tree through `async_body_read_max_concurrent` (default `None`, no limit) and defaults to 64 in the sync tree through `sync_body_read_max_concurrent`; a read whose slot wait passes `body_read_timeout` gets the same `fail_secure` outcome (408), never a silent skip.

## GuardResponse / GuardResponseFactory

```python
from guard_core.protocols import GuardResponse, GuardResponseFactory


class MyFrameworkResponse:
    def __init__(self, status_code: int, headers: dict, body: bytes | None):
        self._status_code = status_code
        self._headers = headers
        self._body = body

    @property
    def status_code(self) -> int:
        return self._status_code

    @property
    def headers(self):
        return self._headers

    @property
    def body(self) -> bytes | None:
        return self._body


class MyFrameworkResponseFactory:
    @staticmethod
    def create_response(content: str, status_code: int) -> GuardResponse:
        return MyFrameworkResponse(
            status_code,
            {"content-type": "application/json"},
            content.encode(),
        )

    @staticmethod
    def create_redirect_response(url: str, status_code: int) -> GuardResponse:
        return MyFrameworkResponse(status_code, {"location": url}, None)
```

## Middleware wiring

Adapters build the event bus, metrics collector, and composite handler through `HandlerInitializer.initialize_agent_integrations()` so the composite agent handler and event filter are wired automatically. An adapter that bypasses the initializer must construct the `CompositeAgentHandler` and install it as the `agent_handler` on the event bus and metrics collector, or mute and enrichment will not apply uniformly.

Build the pipeline through `guard_core.core.checks.build_default_pipeline(middleware)` rather than hand-listing check classes; it passes `config.muted_check_logs` into `SecurityCheckPipeline`, so both pipeline-level block/error log lines and the in-check `log_activity()` calls honor `muted_check_logs`.

`build_default_pipeline` also filters the check catalogue through each check's `applies_to(config, route_configs)`. Route configuration reaches that filter only through `getattr(middleware, "guard_decorator", None)`, which is not part of `GuardMiddlewareProtocol` and so is optional; when it is absent or `None`, `route_configs` is `None` and every check whose predicate consults route configuration is kept rather than dropped. An adapter that cannot expose `guard_decorator` therefore loses the build-time elimination for those route-driven checks specifically (checks gated purely by global `SecurityConfig` flags are unaffected either way), but the protection is identical in both cases: build the pipeline (or rebuild it) after the application has registered its routes and attached its `SecurityDecorator`, and expose that decorator instance as `middleware.guard_decorator`, to get the smaller pipeline. See [the pipeline reference](pipeline.md#which-checks-get-built) for the full elimination mechanism.
