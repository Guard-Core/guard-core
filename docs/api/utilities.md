---

title: Utilities API - Guard Core
description: Helper functions and utilities for logging, security checks, and request handling in guard-core
keywords: security utilities, logging functions, security checks, request handling, guard-core
---

Utilities
=========

The `utils` module provides various helper functions for security operations.

___

Logging Functions
-----------------

setup_custom_logging
---------------------

```python
def setup_custom_logging(
    log_file: str | None = None, log_format: str = "text"
) -> logging.Logger:
    """
    Setup custom logging for Guard Core.

    Configures a hierarchical logger that outputs to console and file.
    A console handler is always attached, but it carries a filter that
    yields to the host's own root logger handlers whenever they exist
    (checked at emission time, not at setup time), so the event
    propagates to the host's handlers instead, avoiding a duplicate line.
    File output is optional for persistence, and is unaffected by the
    root logger's state.

    Args:
        log_file: Optional path to log file. If None, only console output
                  (when the root logger has no handlers of its own, see
                  above) is used.
                  If provided, creates the directory if it doesn't exist.
        log_format: "text" (default) or "json" for structured JSON output.

    Returns:
        logging.Logger: Configured logger with namespace "guard_core"

    Note: This function is synchronous (not async).
    """
```

log_activity
------------

```python
async def log_activity(
    request: GuardRequest,
    logger: logging.Logger,
    log_type: str = "request",
    reason: str = "",
    passive_mode: bool = False,
    trigger_info: str = "",
    level: Literal["INFO", "DEBUG", "WARNING", "ERROR", "CRITICAL"] | None = "WARNING",
    check_name: str | None = None,
    muted_check_logs: frozenset[str] | None = None,
    on_block: Callable[[GuardRequest, dict[str, Any]], Any] | None = None,
    sensitive_headers: frozenset[str] | None = None,
    sensitive_params: frozenset[str] | None = None,
) -> None:
    """
    Universal logging function for all types of requests and activities.
    Returns immediately without logging when `level` is `None`, or when
    `check_name` is present in `muted_check_logs`.
    """
```

Parameters:

- `request`: The request object implementing `GuardRequest`
- `logger`: The logger instance
- `log_type`: Type of log entry (default: "request", can also be "suspicious")
- `reason`: Reason for flagging an activity
- `passive_mode`: Whether to enable passive mode logging format
- `trigger_info`: Details about what triggered detection
- `level`: The logging level to use. If `None`, logging is disabled. Defaults to "WARNING".
- `sensitive_headers`: Extra header names redacted as `[REDACTED]` from the built message, merged with the hardcoded default set (`authorization`, `proxy-authorization`, `cookie`, `x-api-key`); matched case-insensitively.
- `sensitive_params`: Extra query-parameter names whose values are redacted as `[REDACTED]` in the URL segment of the built message, merged with the hardcoded default set (`access_token`, `refresh_token`, `api_key`, `apikey`, `token`, `password`, `secret`, `client_secret`, `signature`); matched case-insensitively. The parameter's own name and the rest of the URL are left untouched.

This is a unified logging function that handles regular requests, suspicious activities, and passive mode logging.

___

Redaction Helpers
-----------------

Both functions apply Guard Core's grammar-based redaction (JSON, XML, key=value pairs, and URL userinfo, query, and fragment segments), replacing sensitive values with the literal `[REDACTED]`. Each takes `sensitive_params`, `sensitive_body_fields`, and `sensitive_headers` as optional `frozenset[str] | None` arguments that EXTEND the hardcoded default sets rather than replace them; passing `None` for an argument means the defaults for that set apply on their own.

The hardcoded defaults are:

- Header names (`_DEFAULT_SENSITIVE_LOG_HEADERS`): `authorization`, `proxy-authorization`, `cookie`, `x-api-key`
- Field names (`_DEFAULT_SENSITIVE_LOG_FIELDS`): `access_token`, `refresh_token`, `api_key`, `apikey`, `token`, `password`, `secret`, `client_secret`, `signature`

Both are intended for consumers that store or render guard event text (a block reason, an endpoint, a user agent, a pattern source, metadata context, or a content preview) and hold no `SecurityConfig` to drive the redaction that `log_activity` applies internally.

redact_blob_for_display
-----------------------

```python
def redact_blob_for_display(
    text: str,
    sensitive_params: frozenset[str] | None,
    sensitive_body_fields: frozenset[str] | None,
    sensitive_headers: frozenset[str] | None = None,
) -> str: ...
```

Parameters:

- `text`: The free-form blob to redact, such as a block reason, trigger info, user agent, or pattern source.
- `sensitive_params`: Extra field names that extend the default field set above. `None` means defaults only.
- `sensitive_body_fields`: Extra body field names that extend the default field set above. `None` means defaults only.
- `sensitive_headers`: Extra header names that extend the default header set above. `None` means defaults only.

Example usage:

```python
from guard_core.utils import redact_blob_for_display

safe_reason = redact_blob_for_display(reason, None, None)
logger.warning(f"blocked: {safe_reason}")
```

redact_url_for_display
----------------------

```python
def redact_url_for_display(
    url: str,
    sensitive_params: frozenset[str] | None,
    sensitive_body_fields: frozenset[str] | None = None,
    sensitive_headers: frozenset[str] | None = None,
) -> str: ...
```

Parameters:

- `url`: The URL or path to redact. In addition to the query and fragment, a userinfo password (`user:password@host`) is masked.
- `sensitive_params`: Extra field names that extend the default field set above. `None` means defaults only.
- `sensitive_body_fields`: Extra body field names that extend the default field set above. `None` means defaults only.
- `sensitive_headers`: Extra header names that extend the default header set above. `None` means defaults only.

Example usage:

```python
from guard_core.utils import redact_url_for_display

safe_endpoint = redact_url_for_display(request.url, None)
logger.warning(f"blocked request to {safe_endpoint}")
```

**Limits.** Both helpers redact a `key=value`/`key: value` grammar (and JSON, XML, and URL structure built on top of it); they do not parse natural language. A sentence like `"the password provided was hunter2"` has no `key=value` shape for the grammar to match, so `hunter2` reaches the output unchanged. A key and its `=`/`:` separator split across a newline (`token\n=hunter2`) are two separate lines to the grammar, not one pair, so the value is not redacted. A key name written with non-ASCII homoglyphs (a Cyrillic `а` in place of the Latin `a`, for example) will not match any entry in the sensitive-name sets, which compare literal characters, so that pair's value is left in place too. A sensitive key with an empty value immediately followed by `<` (`token=<b>bold</b>`) treats the whole run up to the next hard separator as the value, with the angle brackets themselves never ending that run, so the redaction covers the entire run rather than stopping at the first `>` it contains. Callers should treat these helpers as a best-effort mask for the shapes they do cover, not a guarantee that no secret shape can reach the output.

___

Security Check Functions
------------------------

is_user_agent_allowed
---------------------

```python
async def is_user_agent_allowed(user_agent: str, config: Any) -> bool:
    """
    Check if user agent is allowed.
    """
```

check_ip_country
----------------

```python
async def check_ip_country(
    request: str | GuardRequest, config: Any, geo_ip_handler: GeoIPHandler
) -> bool:
    """
    Check if IP is from a blocked country.
    """
```

is_ip_allowed
-------------

```python
async def is_ip_allowed(
    ip: str,
    config: Any,
    geo_ip_handler: GeoIPHandler | None = None,
    *,
    skip_ip_lists: bool = False,
    skip_countries: bool = False,
    skip_clouds: bool = False,
) -> bool:
    """
    Check if IP address is allowed. `skip_ip_lists`/`skip_countries` let a
    caller that has already evaluated one aspect (e.g. a route-level check)
    skip re-evaluating it here. Delegates to `check_ip_access()`, which evaluates the IP lists,
    country rules and blocked cloud providers and also reports cloud-provider blocks
    (provider and network). `skip_clouds=True` leaves cloud blocking to the caller,
    as the HTTP pipeline does because `CloudProviderCheck` blocks clouds there;
    whitelisted and `exempt_ips` IPs pass the cloud step. `is_ip_allowed()` keeps its
    bool-only return for backward compatibility.
    """
```

The `geo_ip_handler` parameter is now properly optional - it's only needed when country filtering is configured. If it's not provided when country filtering is configured, the function will work correctly but won't apply country filtering rules.

This function intelligently handles:

- Whitelist/blacklist checking
- Country filtering (only when GeoIPHandler is provided)
- Cloud provider detection (only when cloud blocking is configured)

This selective processing aligns with Guard Core's smart resource loading to optimize performance.

detect_penetration_attempt
--------------------------

```python
async def detect_penetration_attempt(
    request: GuardRequest,
    config: SecurityConfig | None = None,
    route_config: RouteConfig | None = None,
) -> DetectionResult: ...
```

Detect potential penetration attempts in the request using the enhanced Detection Engine.

This function analyzes various parts of the request (query params, URL path, headers, body) using the Detection Engine's components including pattern matching, semantic analysis, and performance monitoring.

Parameters:

- `request`: The request object implementing `GuardRequest`
- `config`: Optional `SecurityConfig`. When provided, drives global header/param/body-field exclusion sets and the active category filter.
- `route_config`: Optional `RouteConfig`. Per-route overrides take precedence over `config` when both are non-`None`.

Returns a [`DetectionResult`](detection-result.md) dataclass:

- `is_threat: bool`, `True` if any pattern (regex or semantic) matched.
- `trigger_info: str`, Human-readable description of what triggered the hit, or empty string when `is_threat` is `False`.
- `threat_categories: list[str]`, Ordered list of categories that matched (e.g. `["sqli", "xss"]`). Categories with no `category` label (legacy semantic threats) are skipped.
- `threat_scores: dict[str, float]`, Maximum score recorded per category. Regex matches contribute `1.0`; semantic matches contribute their probability or threat score.

The Detection Engine provides:

- Timeout-protected pattern matching (configured via `detection_compiler_timeout` in SecurityConfig)
- Intelligent content preprocessing that preserves attack patterns
- Semantic analysis for obfuscated attacks (when enabled)
- Performance monitoring for pattern effectiveness

Example usage:

```python
from guard_core.protocols import GuardRequest
from guard_core.utils import detect_penetration_attempt


@app.post("/api/submit")
async def submit_data(request: GuardRequest):
    result = await detect_penetration_attempt(request)
    if not result.is_threat:
        return {"success": True}
    logger.warning(
        f"Attack detected: {result.trigger_info} "
        f"categories={result.threat_categories} "
        f"scores={result.threat_scores}"
    )
    return {"error": "Suspicious activity detected"}
```

extract_client_ip
-----------------

```python
async def extract_client_ip(
    request: GuardRequest,
    config: Any,
    agent_handler: AgentHandlerProtocol | None = None,
) -> str:
    """
    Securely extract the client IP address from the request, considering trusted proxies.

    This function implements a secure approach to IP extraction that protects against
    X-Forwarded-For header injection attacks.
    """
```

Parameters:

- `request`: The request object implementing `GuardRequest`
- `config`: The security configuration (must have `trusted_proxies` and `trusted_proxy_depth` attributes)
- `agent_handler`: Optional agent handler for sending IP spoofing telemetry events

This function provides a secure way to extract client IPs by:

1. Only trusting X-Forwarded-For headers from configured trusted proxies
2. Using the connecting IP when not from a trusted proxy
3. Properly handling proxy chains based on configured depth
4. Detecting and reporting IP spoofing attempts via the agent handler

UNKNOWN_CLIENT_IDENTITY
------------------------

```python
UNKNOWN_CLIENT_IDENTITY: str = "unknown"
```

Sentinel value `extract_client_ip` returns when no client address can be resolved (for example, `request.client_host` is `None` and no `"unix"` trusted-proxy fallback applies). Exported from `guard_core.utils`, mirrored at `guard_core.sync.utils`. Adapters and callers should compare a resolved identity against this constant rather than the literal string `"unknown"`.

```python
from guard_core.utils import UNKNOWN_CLIENT_IDENTITY, extract_client_ip

client_ip = await extract_client_ip(request, config)
if client_ip == UNKNOWN_CLIENT_IDENTITY:
    logger.warning("Unable to resolve a client address for this request")
```

___

Usage Examples
--------------

```python
from guard_core.utils import (
    setup_custom_logging,
    log_activity,
    detect_penetration_attempt,
)

# Setup logging (synchronous function)
# Console only
logger = setup_custom_logging()  # or setup_custom_logging(None)

# Console + file
logger = setup_custom_logging("security.log")

# Log regular request
await log_activity(request, logger)

# Log suspicious activity
await log_activity(
    request, logger, log_type="suspicious", reason="Suspicious pattern detected"
)

# Check for penetration attempts
result = await detect_penetration_attempt(request)
if result.is_threat:
    logger.warning(f"{result.trigger_info} - {result.threat_categories}")
```
