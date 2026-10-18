---

title: Security Headers
description: SecurityHeadersManager internals for CSP, HSTS, CORS, and default security headers in guard-core
keywords: security headers, csp, hsts, cors, owasp, guard-core
---

Security Headers
================

The `SecurityHeadersManager` applies HTTP security headers to responses following OWASP best practices. It supports Content Security Policy (CSP), HTTP Strict Transport Security (HSTS), CORS, and a comprehensive set of default headers.

SecurityHeadersManager
----------------------

### Singleton and per-middleware instances

`SecurityHeadersManager()` is a thread-safe singleton (`threading.Lock`, double-checked `__new__`), pre-instantiated as `security_headers_manager` at module level. Every middleware gets its own manager as well: `ResponseContext.security_headers_manager` defaults to `SecurityHeadersManager.isolated()`, and the `ErrorResponseFactory` built on that context uses it, so two guarded apps in one process keep their own agent handler and header cache. The headers themselves come from the `SecurityConfig` the middleware was built with, never from another app's configuration.

### Default Headers

Applied to every response when the manager is enabled:

| Header                           | Default Value                                    |
|----------------------------------|--------------------------------------------------|
| `X-Content-Type-Options`         | `nosniff`                                        |
| `X-Frame-Options`                | `SAMEORIGIN`                                     |
| `X-XSS-Protection`               | `0`                                              |
| `Referrer-Policy`                | `strict-origin-when-cross-origin`                |
| `Permissions-Policy`             | `geolocation=(), microphone=(), camera=()`       |
| `X-Permitted-Cross-Domain-Policies` | `none`                                        |
| `X-Download-Options`             | `noopen`                                         |
| `Cross-Origin-Embedder-Policy`   | not sent (opt in, for example `require-corp`)    |
| `Cross-Origin-Opener-Policy`     | `same-origin`                                    |
| `Cross-Origin-Resource-Policy`   | `same-site`                                      |

Set `cross_origin_embedder_policy` in `SecurityConfig.security_headers` to send `Cross-Origin-Embedder-Policy`.

### The `security_headers` dictionary

A partial `SecurityConfig.security_headers` dict merges over the defaults key by key (`hsts` sub-key by sub-key), so `{"csp": {...}}` keeps HSTS and every default header. `None`, `{}` and `{"enabled": False}` switch every header off. A value of `None` switches that one header off: `frame_options`, `content_type_options`, `xss_protection`, `referrer_policy`, `permissions_policy`, `permitted_cross_domain_policies`, `download_options`, `cross_origin_embedder_policy`, `cross_origin_opener_policy`, `cross_origin_resource_policy`; `hsts: None` and `csp: None` do the same for those two. An unknown key is reported through `fail_on_misconfiguration` (a warning in 4.5, a startup failure from 5.0).

### Application headers and operator values

A default header is added only when the application did not set that header (compared without case). A value the operator configured replaces the application's: `custom`, `csp`, `hsts`, and any default header whose configured value differs from the built-in one. The merged set is cached by the content of `security_headers` (one entry per distinct configuration, never by object identity or path), so an agent event and an unsafe-CSP warning come once per configuration.

### Configuration

The `configure()` method accepts keyword-only arguments:

```python
security_headers_manager.configure(
    enabled=True,
    csp={"default-src": ["'self'"], "script-src": ["'self'", "cdn.example.com"]},
    hsts_max_age=31536000,
    hsts_include_subdomains=True,
    hsts_preload=True,
    frame_options="DENY",
    content_type_options="nosniff",
    xss_protection="0",
    referrer_policy="no-referrer",
    permissions_policy="camera=()",
    custom_headers={"X-Custom": "value"},
    cors_origins=["https://example.com"],
    cors_allow_credentials=True,
    cors_allow_methods=["GET", "POST"],
    cors_allow_headers=["Authorization"],
)
```

### The global `configure()` and the cross-app override

A call to `security_headers_manager.configure(...)` sets exactly what it passes (every parameter has a "not passed" marker so the call can tell which keys it passed). **A call without `override_apps=True` changes only the manager's own headers and does not reach any guarded app**: the middlewares and every released adapter call it at startup with every key filled in, and that call stays inert for the apps, as in 4.4.0. To change the headers of every guarded app, pass the flag:

```python
security_headers_manager.configure(
    csp={"default-src": ["'self'", "https://cdn.example"]},
    override_apps=True,
)
```

- **The manager's own headers** keep the full replace: what the call does not pass is absent (a call with only `csp` also clears HSTS and every default header on the manager).
- **The cross-app override** (only with `override_apps=True`): the keys the call passes override the `security_headers` config of every guarded app in the process, from the next response on, for paths already served and paths never served. The keys it does not pass are not overridden, so each app keeps its own value for them. `None` switches that header off for every app. `hsts_max_age`, `hsts_include_subdomains` and `hsts_preload` merge sub-key by sub-key over each app's `hsts`. A passed `enabled` wins in both directions: `enabled=True` switches on an app whose own `security_headers` is off (the default set), `enabled=False` switches every app off; not passed keeps each app's own.
- **Clearing**: `configure(override_apps=True)` with no other argument clears the override (and resets the manager). `reset()` (async) clears the manager and the override, in the process and in Redis. A write of `security_headers_manager.enabled` is never an override.
- **Never silent**: every call with the flag that changes the override logs one line and sends the security headers event (`action_taken` `override_changed` or `override_cleared`; metadata `override_keys`, `dropped_keys`, `override_values`, `dropped_values`). A call that drops keys from an active override, a clearing call included, logs a WARNING that names the dropped keys. Header names and values go through the request-log redaction, so a custom `X-Auth-Token` value never appears. A call without the flag logs nothing new.

With Redis on, the override is persisted by `initialize_redis`, `_load_cached_config` and `_cache_configuration` (the manager's own CSP, HSTS and custom headers keep their 24-hour keys). An app's manager calls `initialize_redis(redis_handler, config)` on its first response, and the override is saved under `{redis_prefix}security_headers:override:{hash}`, where `hash` is the hash of the startup config that app runs, with no TTL. Each worker pulls it at most once per 5 seconds (through the app's own Redis connection) and applies a newer record. "Newer" is the time of the call on Redis time: each worker measures its offset to Redis `TIME` in `initialize_redis` and on every pull (one extra `TIME` command per pull, none on a response that does not pull) and corrects its stamp by it, so workers with different clocks still order two calls correctly; a Redis error keeps the last offset, and a worker without Redis stamps on its own clock, so a call in one worker reaches the others within about 5 seconds. A worker started with another config uses another key and ignores it; a redeploy with another config never serves an older deployment's values. A Redis error on pull or save keeps the last applied override and retries after 5 seconds, whatever `redis_fail_open` says. A key missing from Redis clears an override the worker took from it. Two services that share a `redis_prefix` and run an identical config share the override: give every service its own prefix.

### CSP Configuration

CSP directives are stored as `dict[str, list[str]]` and serialized by `_build_csp()`:

```python
{"default-src": ["'self'"], "script-src": ["'self'", "'nonce-abc123'"]}
# becomes: "default-src 'self'; script-src 'self' 'nonce-abc123'"
```

!!! warning "Unsafe Sources"
    The manager logs a warning when CSP directives contain `'unsafe-inline'` or `'unsafe-eval'`.

### HSTS Configuration

HSTS is built from a config dictionary:

```python
{"max_age": 31536000, "include_subdomains": True, "preload": True}
# becomes: "max-age=31536000; includeSubDomains; preload"
```

**Preload validation**:

- `max_age` must be >= 31536000 (1 year) for preload. If not, preload is disabled with a warning.
- `includeSubDomains` must be `True` for preload. If not, it is force-enabled with a warning.

### CORS Configuration

```python
cors_config = {
    "origins": ["https://example.com"],
    "allow_credentials": True,
    "allow_methods": ["GET", "POST"],
    "allow_headers": ["Authorization"],
}
```

**Safety check**: If `origins` contains `"*"` and `allow_credentials` is `True`, credentials are force-disabled and the CORS configuration is blocked. This prevents a known security vulnerability.

### Getting Headers

```python
headers = await security_headers_manager.get_headers(request_path="/api/data")
```

**Caching**: Headers are cached per request path in a `TTLCache(maxsize=1000, ttl=300)`. Cache keys are SHA-256 hashes of normalized paths.

**Composition order**:

1. Default headers (copy)
2. CSP header (if configured)
3. HSTS header (if configured)
4. Custom headers (override any defaults)

### CORS Headers

```python
cors_headers = await security_headers_manager.get_cors_headers(
    origin="https://example.com"
)
```

Returns an empty dict if:

- CORS is not configured.
- The origin is not in the allowed list.
- Wildcard origin with credentials (security block).

### CSP Violation Reporting

```python
is_valid = await security_headers_manager.validate_csp_report(report_json)
```

Validates the structure of a CSP violation report (checks for `document-uri`, `violated-directive`, `blocked-uri` in the `csp-report` object) and logs the violation.

### Header Name and Value Validation

Custom header names pass through `_validate_header_name()`:

- Requires the RFC 9110 token grammar (`` [!#$%&'*+.^_`|~0-9A-Za-z-]+ ``); rejects `\r`, `\n`, and any other non-token character.

All header values pass through `_validate_header_value()`:

- Rejects values containing `\r` or `\n` (HTTP response splitting prevention).
- Rejects values longer than 8192 bytes.
- Strips non-printable characters except tab.

Both validators also run on `custom_headers` loaded back from Redis; a name or value that fails validation discards the entire cached `custom_headers` entry (logged, not raised).

### Redis Integration

`initialize_redis` loads and saves the manager's own CSP, HSTS and custom headers (24-hour TTL) and, for an app's manager, the override record described above (no TTL).
