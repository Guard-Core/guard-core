---

title: Security Decorators API - Guard Core
description: API reference for guard-core's security decorator system including SecurityDecorator, RouteConfig, and all mixins
keywords: security decorators, guard-core, route config, access control, authentication
---

Security Decorators
===================

The decorators module provides route-level security controls that can be applied to individual endpoints. These decorators offer fine-grained control over security policies on a per-route basis, complementing the global security pipeline. Framework adapters expose these decorators to their users through their own decorator interfaces.

___

Overview
--------

Security decorators allow you to:

- Apply specific security rules to individual routes
- Override global security settings for specific endpoints
- Combine multiple security measures in a clean, readable way
- Implement behavioral analysis and monitoring per endpoint

___

Main Decorator Class
--------------------

### SecurityDecorator

The main decorator class that combines all security capabilities. This is the primary class you'll use in your application.

**Example Usage:**

```python
from guard_core import SecurityConfig
from guard_core.decorators import SecurityDecorator
from guard_core.handlers.ipinfo_handler import IPInfoManager

config = SecurityConfig(geo_ip_handler=IPInfoManager(token="your-ipinfo-token"))
guard_deco = SecurityDecorator(config)


@app.get("/api/sensitive")
@guard_deco.rate_limit(requests=5, window=300)
@guard_deco.require_ip(whitelist=["10.0.0.0/8"])
@guard_deco.block_countries(["CN", "RU"])
def sensitive_endpoint():
    return {"data": "sensitive"}
```

`block_countries()`/`allow_countries()` need a `geo_ip_handler` on `SecurityConfig` to do anything: `check_country_access()` returns `None` (no verdict) immediately when `geo_ip_handler` is falsy, so a route decorated with a country rule but no handler configured silently never blocks or allows based on country.

___

Base Classes
------------

### BaseSecurityDecorator

Base class providing core decorator functionality and route configuration management.

### RouteConfig

Configuration class that stores security settings for individual routes.

___

Mixin Classes
-------------

The decorator system uses mixins to organize different types of security features:

### AccessControlMixin

Provides IP-based and geographic access control decorators.

**Available Decorators:**

- `@guard_deco.require_ip(whitelist=[], blacklist=[])` - IP address filtering
- `@guard_deco.block_countries(countries=[])` - Block specific countries
- `@guard_deco.allow_countries(countries=[])` - Allow only specific countries
- `@guard_deco.block_clouds(providers=[])` - Block cloud provider IPs
- `@guard_deco.bypass(checks=[])` - Bypass specific security checks

### AuthenticationMixin

Provides authentication and authorization decorators.

**Available Decorators:**

- `@guard_deco.require_https()` - Force HTTPS
- `@guard_deco.require_auth(type="bearer")` - Require authentication
- `@guard_deco.api_key_auth(header_name="X-API-Key")` - API key authentication
- `@guard_deco.require_headers(headers={})` - Require specific headers

**`require_headers` semantics**

Each key of `headers` is a header name; a missing header is always rejected. The value `"required"` keeps presence-only semantics: any value satisfies the check as long as the header is present. Any other configured value must match the request header's value exactly, or the request is rejected with the reason `Header 'X' does not match the required value`, which never echoes the expected or received value.

```python
@app.get("/api/internal")
@guard_deco.require_headers({"X-Request-Id": "required", "X-Internal-Version": "2"})
def internal_endpoint():
    return {"data": "internal"}
```

!!! warning "Breaking Change"
    Before this fix, a configured value other than `"required"` was never enforced: the decorator was a silent no-op for it, and neither a missing header nor a mismatched value was rejected. A route decorated with a non-`"required"` value now enforces it; audit any `require_headers()` call that used a placeholder or example string as the value.

### RateLimitingMixin

Provides rate limiting decorators.

**Available Decorators:**

- `@guard_deco.rate_limit(requests=10, window=60)` - Basic rate limiting
- `@guard_deco.geo_rate_limit(limits={})` - Geographic rate limiting

### BehavioralMixin

Provides behavioral analysis and monitoring decorators.

**Available Decorators:**

- `@guard_deco.usage_monitor(max_calls, window, action)` - Monitor endpoint usage
- `@guard_deco.return_monitor(pattern, max_occurrences, window, action)` - Monitor return patterns
- `@guard_deco.behavior_analysis(rules=[])` - Apply multiple behavioral rules
- `@guard_deco.suspicious_frequency(max_frequency, window, action)` - Detect suspicious frequency

### ContentFilteringMixin

Provides content and request filtering decorators.

**Available Decorators:**

- `@guard_deco.block_user_agents(patterns=[])` - Block user agent patterns
- `@guard_deco.content_type_filter(allowed_types=[])` - Filter content types
- `@guard_deco.max_request_size(size_bytes)` - Limit request size
- `@guard_deco.require_referrer(allowed_domains=[])` - Require specific referrers
- `@guard_deco.custom_validation(validator)` - Add custom validation logic
- `@guard_deco.detection_exclusion(headers=None, params=None, body_fields=None, categories=None, scan_body=None)` - Per-route detection scoping

**`require_referrer` semantics**

`allowed_domains` entries accept three forms: a bare host (`example.com`), a scheme-prefixed URL (`https://example.com`), or a scheme-prefixed URL with a port (`https://example.com:8443`). An entry containing `://` is reduced to its host (and port, if present) before comparison; a bare entry is lowercased with any trailing slash or path stripped. The request's `Referer` header is then matched against each configured entry, exactly or as a subdomain.

**`detection_exclusion` semantics**

```python
def detection_exclusion(
    self,
    headers: set[str] | None = None,
    params: set[str] | None = None,
    body_fields: set[str] | None = None,
    categories: set[str] | None = None,
    scan_body: bool | None = None,
    semantic_headers: set[str] | None = None,
) -> Callable[[Callable[..., Any]], Callable[..., Any]]: ...
```

All six kwargs are optional (`set[str] | None` for `headers`/`params`/`body_fields`/`categories`/`semantic_headers`, `bool | None` for `scan_body`). Passing `None` (or omitting) leaves the corresponding `RouteConfig` field unset, the route inherits the global `SecurityConfig` value at request time. Passing a value replaces the inherited value at this route only.

- `headers`, header names skipped by detection. Merged with `SecurityConfig.excluded_detection_headers` and the hardcoded default exclusion list.
- `params`, query parameter names skipped by detection. Replaces (does not merge with) the global set when set.
- `body_fields`, top-level JSON body keys skipped by detection. Replaces the global set when set.
- `categories`, categories the regex scanner runs at this route. Replaces the global `enabled_detection_categories`. Custom user patterns always run regardless.
- `semantic_headers`, header names whose values skip the semantic analyzer only (regex scanning is unchanged). Merged with `SecurityConfig.excluded_semantic_detection_headers`.
- `scan_body`, whether to scan the request body at this route. Replaces the global `detection_scan_body` when set.

```python
@app.post("/api/markdown-editor/save")
@guard_deco.detection_exclusion(
    body_fields={"content", "draft"},
    categories={"sqli", "cmd_injection"},
)
def save_markdown():
    return {"saved": True}
```

### AdvancedMixin

Provides advanced detection and time-based decorators.

**Available Decorators:**

- `@guard_deco.time_window(start_time, end_time, timezone)` - Time-based access control
- `@guard_deco.suspicious_detection(enabled=True)` - Toggle suspicious pattern detection
- `@guard_deco.honeypot_detection(trap_fields=[])` - Detect bots using honeypot fields

___

Utility Functions
-----------------

### get_route_decorator_config

```python
def get_route_decorator_config(
    request: GuardRequest,
    decorator_handler: BaseSecurityDecorator,
) -> RouteConfig | None:
    """
    Extract route security configuration from the current request.
    """
```

___

Integration with Middleware
---------------------------

The decorators work in conjunction with the SecurityMiddleware to provide comprehensive protection:

1. **Route Configuration**: Decorators configure route-specific settings
2. **Middleware Processing**: SecurityMiddleware reads decorator configurations and applies them
3. **Override Behavior**: Route-specific settings can override global middleware settings

**Example Integration:**

```python
from guard_core import SecurityConfig
from guard_core.decorators import SecurityDecorator

config = SecurityConfig(
    enable_ip_banning=True,
    enable_rate_limiting=True,
    rate_limit=100,
    rate_limit_window=3600,
)

guard_deco = SecurityDecorator(config)


@guard_deco.rate_limit(requests=10, window=300)
@app.get("/api/limited")
def limited_endpoint():
    return {"data": "limited"}


@app.get("/api/public")
def public_endpoint():
    return {"data": "public"}


app.state.guard_decorator = guard_deco
```

___

Best Practices
--------------

### Decorator Order

Apply decorators in logical order, with more specific restrictions first:

```python
@app.post("/api/admin/sensitive")
@guard_deco.require_https()
@guard_deco.require_auth(type="bearer")
@guard_deco.require_ip(whitelist=["10.0.0.0/8"])
@guard_deco.rate_limit(requests=5, window=3600)
@guard_deco.suspicious_detection(enabled=True)
def admin_endpoint():
    return {"status": "admin action"}
```

### Combining Behavioral Analysis

Use multiple behavioral decorators for comprehensive monitoring:

```python
@app.get("/api/rewards")
@guard_deco.usage_monitor(max_calls=50, window=3600, action="ban")
@guard_deco.return_monitor("rare_item", max_occurrences=3, window=86400, action="ban")
@guard_deco.suspicious_frequency(max_frequency=0.1, window=300, action="alert")
def rewards_endpoint():
    return {"reward": "rare_item", "value": 1000}
```

### Geographic and Cloud Controls

Combine geographic and cloud provider controls:

```python
@app.get("/api/restricted")
@guard_deco.allow_countries(["US", "CA", "GB"])
@guard_deco.block_clouds(["AWS", "GCP"])
def restricted_endpoint():
    return {"data": "geo-restricted"}
```

### Content Filtering

Apply content filtering for upload endpoints:

```python
@app.post("/api/upload")
@guard_deco.content_type_filter(["image/jpeg", "image/png"])
@guard_deco.max_request_size(5 * 1024 * 1024)
@guard_deco.require_referrer(["myapp.com"])
def upload_endpoint():
    return {"status": "uploaded"}
```

___

Error Handling
--------------

Decorators integrate with the middleware's error handling system. When decorator conditions are not met, appropriate HTTP responses are returned:

### 403 Forbidden

IP restrictions, country blocks, authentication failures

### 429 Too Many Requests

Rate limiting violations

### 400 Bad Request

Content type mismatches, missing headers

### 413 Payload Too Large

Request size limits exceeded

___

Configuration Priority
----------------------

Security settings are applied in the following priority order:

1. Decorator Settings (highest priority)
2. Global Middleware Settings
3. Default Settings (lowest priority)

This allows for flexible override behavior where routes can customize their security requirements while maintaining global defaults.

Decorator settings override global settings only for the aspects they configure, they do not shadow the global settings wholesale. This matters most for IP and country access control, where the IP and country aspects are evaluated independently: a route-level `ip_whitelist` match suppresses only the global IP-list gate (it does not exempt the request from country enforcement), and only an actual `whitelist_countries` match for the resolved country suppresses the global country gate. A route-level deny (`ip_blacklist` or `blocked_countries`) is enforced at the route step and, on its own, never disables the global IP or country rules, which still run afterward. Within the IP aspect, a route `ip_whitelist` match wins over that same route's own `ip_blacklist`.
