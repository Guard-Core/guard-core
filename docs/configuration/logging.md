---

title: Logging Configuration
description: Configuring log levels, formats, file output, and the JsonFormatter in guard-core
keywords: logging, json formatter, log levels, security events, guard-core
---

Logging Configuration
=====================

Guard-core uses Python's standard `logging` module with configurable levels, formats, and output destinations.

Log Level Fields
----------------

### `log_suspicious_level`

**Type**: `"INFO" | "DEBUG" | "WARNING" | "ERROR" | "CRITICAL" | None`
**Default**: `"WARNING"`

Controls the log level for suspicious activity events (blocked requests, penetration attempts, banned IPs, rate limit violations).

Set to `None` to suppress suspicious activity logging entirely.

### `log_request_level`

**Type**: Same as above
**Default**: `None`

Controls the log level for all incoming requests (the `RequestLoggingCheck`). Disabled by default to avoid high-volume logging in production.

Set to `"INFO"` or `"DEBUG"` for development or audit requirements.

___

Log Format
----------

### `log_format`

**Type**: `"text" | "json"`
**Default**: `"text"`

**Text format** (default):

```text
[guard_core] 2026-03-23 10:15:32,123 - WARNING - Suspicious activity detected from 10.0.0.1: GET /api/data - Reason: SQL injection pattern matched - Headers: {...}
```

**JSON format**:

```json
{"timestamp": "2026-03-23 10:15:32,123", "level": "WARNING", "logger": "guard_core", "message": "Suspicious activity detected from 10.0.0.1: GET /api/data - Reason: SQL injection pattern matched - Headers: {...}"}
```

### JsonFormatter

The `JsonFormatter` class in `guard_core.utils` produces structured JSON log output:

```python
class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        log_entry = {
            "timestamp": self.formatTime(record, self.datefmt),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        return json.dumps(log_entry, default=str)
```

Adapters can use this formatter directly for custom logging handlers.

___

Custom Log File
---------------

### `custom_log_file`

**Type**: `str | None`
**Default**: `None`

Path to a log file for guard-core events. The directory is created automatically if it does not exist.

```python
SecurityConfig(
    custom_log_file="/var/log/guard-core/security.log",
    log_format="json",
)
```

When set, guard-core creates a file handler with the configured formatter. A console handler is also always attached, but it yields to the host's own root handlers whenever they exist; see "Avoiding duplicate log lines" below.

___

Log Setup
---------

The `setup_custom_logging()` function initializes the guard-core logger:

```python
def setup_custom_logging(
    log_file: str | None = None,
    log_format: str = "text",
) -> logging.Logger
```

This is called internally by the middleware during initialization. It:

1. Gets or creates the `"guard_core"` logger.
2. Clears existing handlers on the `"guard_core"` logger.
3. Adds a `StreamHandler` (console) with the configured formatter, always, carrying a filter that yields to the host's own root logger handlers; see "Avoiding duplicate log lines" below.
4. Optionally adds a `FileHandler` if `log_file` is specified, unfiltered, regardless of the root logger's state.
5. Sets the logger level to `INFO`.

___

Avoiding Duplicate Log Lines
-----------------------------

The `"guard_core"` logger keeps `propagate=True`, so its records always reach any handlers already attached to the process's root logger (a host calling `logging.basicConfig()`, for example). Guard's own console handler used to be attached unconditionally, so a host with root handlers configured saw every guard security event printed twice: once formatted by guard's handler, once via propagation through the host's.

`setup_custom_logging()` always attaches its own console handler to `"guard_core"`, but that handler carries a filter that checks `logging.getLogger().handlers` at the moment each record is emitted, not at setup time. Guard's console output yields to the host's root handlers whenever they exist, whichever was configured first: if the host configures its root logger before guard's `setup_custom_logging()` runs, or only afterward, guard's own console handler goes silent the moment root handlers exist, and the event reaches the host's handlers exactly once through propagation. Only while the root logger has no handlers at all does guard's own console handler emit, so output still appears when nothing else is configured to show it.

A host that wants guard's own formatted output (text or JSON) while running its own root logger handlers should either set `custom_log_file` (the file handler carries no such filter and is always attached) or attach a handler directly to the `"guard_core"` logger.

___

Log Activity Function
---------------------

The core logging function is `log_activity()` in `guard_core.utils`:

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
) -> None
```

**Log types and their message formats**:

| `log_type`     | Message Format                                                    |
|----------------|---------------------------------------------------------------------|
| `"request"`    | `Request from {ip}: {method} {url} - Headers: {...}`               |
| `"suspicious"` | `Suspicious activity detected from {ip}: {method} {url} - Reason: {reason} - Headers: {...}` |
| Other          | `{Type} from {ip}: {method} {url} - Details: {reason} - Headers: {...}` |

**Passive mode**: When `passive_mode=True` and `log_type="suspicious"`, the message is prefixed with `[PASSIVE MODE] Penetration attempt detected` when `trigger_info` is set, in the format `[PASSIVE MODE] Penetration attempt detected from {ip}: {method} {url} - Trigger: {trigger_info} - Headers: {...}`. When `trigger_info` is empty (for example a passive rate-limit hit), the line is `[PASSIVE MODE] Suspicious activity detected from {ip}: {method} {url} - Reason: {reason} - Headers: {...}`, so the reason is never dropped.

**Level `None`**: When `level` is `None`, the function returns immediately without logging.

___

Sensitive Data Redaction
------------------------

Guard-core redacts sensitive values out of its own log lines, and only its own log lines. Coverage is limited to the surfaces named in this section: header values, query-string parameter values by name, and body-field values by name at any depth, including the subtree a JSON body is serialized into once it is deeper than `detection_max_json_depth`. Parameter and field names are never redacted, only the value behind a sensitive name. The raw-body and application-server access-log limitations documented further down are the edges of that coverage, not omissions.

### Headers

Header values are redacted before any of the message formats above are built, so the redaction applies everywhere `Headers: {...}` appears: the request line, the suspicious line (both active and passive mode), and the generic line. The detection engine's own per-header attack line is redacted separately, against the same sensitive-header set.

The default redacted set matches the header name case-insensitively: `authorization`, `proxy-authorization`, `cookie`, `x-api-key`. A matched value is replaced with the literal string `[REDACTED]`; the header's own key casing is preserved in the output.

When a header value trips a pattern match, the detection engine logs its own line at `log_suspicious_level`: `Potential attack detected from {ip}: {value} - Suspicious pattern in header '{name}'`. The default excluded-header set that keeps detection from scanning `Host`, `User-Agent`, `Accept`, and similar boilerplate headers does not include `authorization` or `cookie`, so both are scanned for patterns like any other header. When the header named in `{name}` is in the sensitive set, `{value}` is replaced with `[REDACTED]`:

```text
Potential attack detected from 203.0.113.9: [REDACTED] - Suspicious pattern in header 'Cookie'
```

Non-sensitive header values are still shown in that line on purpose, operators need to see the offending payload.

### Query string

Every guard log line carries the full URL, query string included, so a secret passed as a query parameter (`?access_token=...`, `?api_key=...`) used to reach the log verbatim. Query parameters whose name is in the sensitive set now have their value replaced with `[REDACTED]` in the URL segment of every `log_activity` line; the parameter's own name spelling and every other part of the URL, scheme, host, path, and the other parameters, are preserved byte for byte. Pairs are split on both `&` and `;`, with whichever separator was written preserved in the output, so `?foo=bar;token=SECRET` logs as `?foo=bar;token=[REDACTED]`. A parameter with no `=` (a bare flag) is left alone, and parameter names themselves are never redacted:

```text
Request from 203.0.113.9: GET https://api.example/v1/items?access_token=[REDACTED]&page=2 - Headers: {...}
```

The detection engine's per-parameter line is redacted the same way: `Potential attack detected from {ip}: {value} - Suspicious pattern in query param '{name}'` shows `[REDACTED]` in place of `{value}` when `{name}` is sensitive.

The URL fragment is redacted as a query string (`#token=SECRET` becomes `#token=[REDACTED]`); a hash-routing fragment such as `#/route?token=SECRET` or `#token=SECRET?x=1` is tokenized on `?`, `&` and `;` so every `name=value` token inside it is checked and the rest is kept as written. A token whose `=` is percent-encoded (`token%3DSECRET`) is decoded for the name check and replaced entirely by `[REDACTED]` when the name is sensitive. Percent-decoding is repeated up to three times before the check, so a token that hides a second pair behind an encoded `&` or `;` (`a%3D1%26token%3DSECRET`) is replaced entirely, and double-encoded JSON is still recognized. A path segment that decodes to JSON containing a sensitive key is printed as its redacted serialization; any other path segment is printed as written. Matrix parameters inside a path segment (`/api;token=SECRET/x`) go through the same name check as query pairs. The same URL redaction is applied everywhere a URL or path is displayed: the URL segment of guard log lines, the detection engine's `Suspicious pattern in URL path` line and its telemetry preview, and the `path` field of the `on_block` payload. A whole path that decodes to JSON is handled before it is split into segments, so a JSON string containing `/` is not shredded. The log-line redactor walks JSON iteratively with the same depth cap as detection (`detection_max_json_depth`); anything nested deeper is replaced wholesale by `[REDACTED]`, so a pathologically nested value can never make a log call fail.

### Body fields

The detection engine's per-field line, raised when a JSON key at any depth, an `application/x-www-form-urlencoded` field, or a multipart text part trips a pattern, redacts the value the same way when the field's own name is in the sensitive set. Unlike the header and query-parameter lines, the body-field line names the field on its own, with no wrapping phrase:

```text
Potential attack detected from 203.0.113.9: [REDACTED] - Suspicious pattern in password
```

The field name itself is never redacted, so the line still names which field tripped detection, and non-sensitive field values are still shown.

The same body-field name set also applies to JSON carried inside a header, query parameter or URL path value (`?data={"password": ...}`), for both the detection line and the telemetry preview. Such a value goes through the same recursive walker as a JSON body, so nested objects and arrays are covered, and the line for the enclosing header, parameter or path shows the JSON with every sensitive value replaced by `[REDACTED]`. When a sensitive key's own value is itself an object or array, that whole subtree is collapsed to one `[REDACTED]` rather than walked further, so every descendant it holds is covered by the parent key's name alone. The `Headers: {...}` segment and the URL segment of every guard log line apply the same body-field redaction: a header or query value that parses as JSON is printed with every value under a sensitive key, and every descendant of it, replaced by `[REDACTED]`, while a JSON value with no sensitive key is printed byte for byte. The same applies to any other structured content inside a header, parameter, path or body value. Pairs are recognised by a grammar, not by a list of separators: a name is a run of letters, digits, `_`, `.` and `-` (percent-encoded bytes and `+` included, decoded up to three times, case-insensitive), optionally wrapped in matching quotes, followed by one or more `=` or `:` tokens, literal or percent-encoded, with any horizontal whitespace before, between or after them; any other character ends a name, so `&`, `;`, `,`, `?`, `|`, quotes, brackets, newlines and every kind of whitespace all separate pairs. When the name is sensitive the value is replaced up to the next hard separator (`&`, `;`, `,`, `?`, `|`, a bracket, a newline, the closing quote) or up to the next whitespace that starts another pair, so a secret that contains spaces is redacted whole: `password=my secret <script>` becomes `password=[REDACTED]`, `a=1 password=x b=2` becomes `a=1 password=[REDACTED] b=2`, and `password: SECRET`, `password = SECRET`, `PASSWORD==SECRET` and `"password":"SECRET"` are all redacted. A value under a non-sensitive name is scanned again with the same grammar, so `filename="password=SECRET"`, `data=password=SECRET`, JSON string values, XML text and XML attributes (`<user password="x"/>`) are covered; a JSON value is walked key by key first and its string values then go through the same grammar. A name that is still percent-encoded after three decoding rounds is treated as sensitive, so an over-encoded pair is redacted rather than shown. This grammar serves every display: the `Headers: {...}` segment, the URL segment, the detection engine's per-component line and telemetry preview (including a header excluded from detection when it trips the always-scanned Log4Shell pattern), and every event and hook field. The redaction is a single bounded pass over the value and runs only when a line is actually emitted.

When a JSON body is deeper than `detection_max_json_depth`, the remaining subtree is serialized and scanned as one value under the parent key's label; the line's display text is built from a copy of that subtree in which every value under a sensitive key name, at any depth, is `[REDACTED]`, so a sensitive key nested inside a non-sensitive parent (`{"password": "..."}` under `wrapper`) no longer prints raw, while non-sensitive content in the subtree is still shown.

### Telemetry

The `log_sensitive_headers`, `log_sensitive_params`, and `log_sensitive_body_fields` sets also govern the `content_preview` field on the detection engine's `pattern_detected` telemetry event sent to `agent_handler`: a sensitive header, query parameter, or body field gets the same redacted display text there as in the log line, instead of the raw matched value. The same event also carries the matched pattern on two fields the SaaS keys campaigns on: `pattern_matched` (the top-level `SecurityEvent` field) is the matched regex's source text, or `semantic:<attack_type>` for a semantic hit, passed through the same display redaction used for header and body values, so a custom pattern whose literal text looks like `password=hunter2` is redacted to `password=[REDACTED]` there while `metadata.pattern` keeps the raw matched pattern text. `metadata.threat_categories` is the detection engine's category list for the hit (for example `["sqli"]`) and `metadata.category` is its first entry, semantic hits mapped onto the same category names; `handler_name` is `"sus_patterns"` on every event this handler sends, and every other emitter sets its own handler name.

### Shared default set

`log_sensitive_params` and `log_sensitive_body_fields` extend the same hardcoded default, `guard_core.utils._DEFAULT_SENSITIVE_LOG_FIELDS`: `access_token`, `refresh_token`, `api_key`, `apikey`, `token`, `password`, `secret`, `client_secret`, `signature`. `log_sensitive_headers` extends its own, smaller default set (see Headers above); the two default sets are independent of each other.

### Config fields

| Field | Type | Default | Redacts | Extend-only | Case-insensitive | Revalidated on reassignment |
|-------|------|---------|---------|--------------|-------------------|------------------------------|
| `log_sensitive_headers` | `frozenset[str]` | `frozenset()` | `Headers: {...}` segment and the detection engine's per-header line | Yes | Yes | Yes |
| `log_sensitive_params` | `frozenset[str]` | `frozenset()` | URL segment and the detection engine's per-parameter line | Yes | Yes | Yes |
| `log_sensitive_body_fields` | `frozenset[str]` | `frozenset()` | The detection engine's per-field line | Yes | Yes | Yes |

```python
SecurityConfig(
    log_sensitive_headers={"x-internal-token"},
    log_sensitive_params={"session_id"},
    log_sensitive_body_fields={"ssn"},
)
```

```text
Request from 10.0.0.1: GET /api/data - Headers: {'authorization': '[REDACTED]', 'x-internal-token': '[REDACTED]', 'user-agent': 'curl/8.0'}
```

### Bodies of other content types

A body that is not JSON, form or multipart (text/plain, XML, no content type) is scanned as one value; its detection line and telemetry preview are built from a redacted copy: the text is tried as JSON first, then as `name=value` pairs split on `&`, `;`, `?` and newlines, and XML elements `<name>value</name>`, with every sensitive name's value replaced by `[REDACTED]` and other content still shown. A body declared multipart whose parts cannot be parsed (for example a boundary that does not match the declared one) is never shown raw: its line and preview are `[REDACTED]`.

### Proxy identity headers in warnings

The `X-Forwarded-For` spoof warning and its telemetry event show only the tokens of the header that parse as IP addresses; anything else in that header is `[REDACTED]`. Header names are matched after stripping surrounding whitespace, so an adapter that hands guard-core a header name with trailing whitespace still gets the value redacted.

### Telemetry event fields

Every event, metric and hook payload field that carries a URL or path (`endpoint`, `endpoint_id`, `excluded_path`, `redirect_url`, the on_block `path`, CSP report URIs) goes through the same URL redaction as the log lines, and every displayed header value (user agent and referrer block reasons, content-type violations, decorator events) goes through the same value redaction. Error logs from a failing check print the exception type and a redacted message, never the raw exception text, so a header value that breaks parsing cannot reach the log through the error.

### Name and path limitation

Field names are never redacted anywhere: a secret used as a JSON key or a query parameter name is disclosed as a name. The URL path is not redacted by name: a bare token embedded as a path segment is printed in full (only a path segment that decodes to JSON with a sensitive key is redacted); put such tokens in a header or query parameter with a sensitive name instead.

### Application server access logs

Redaction covers guard-core's own log lines only. The application server's access log (gunicorn, uvicorn, nginx) prints the raw request line, query string included, on its own; configure that logger separately if query-string secrets must not reach it.

### Escape hatches

`log_suspicious_level=None` and `muted_check_logs` still silence a line entirely; redaction is not a substitute for either, it only protects the lines that do get logged. `agent_sensitive_headers` is unrelated: it governs headers stripped from telemetry payloads sent to the agent, not guard log lines.

All three fields are revalidated on reassignment and on `model_copy(update=...)`, the same as `muted_check_logs`: assigning a bare `str` or `bytes` value raises `ValidationError` instead of being iterated character by character and silently redacting nothing; a `list` or `set` is coerced to `frozenset`.

___

Security Event Logging
----------------------

Guard-core logs security events at specific levels:

| Event                    | Default Level | Source                    |
|--------------------------|--------------|---------------------------|
| Request blocked          | `WARNING`    | Various check implementations |
| Penetration attempt      | `WARNING`    | `SuspiciousActivityCheck` |
| IP banned                | `WARNING`    | `SuspiciousActivityCheck` |
| Rate limit exceeded      | `WARNING`    | `RateLimitManager`        |
| IP spoofing attempt      | `WARNING`    | `extract_client_ip()`     |
| CSP violation            | `WARNING`    | `SecurityHeadersManager`  |
| Emergency mode block     | `WARNING`    | `EmergencyModeCheck`      |
| Redis connection failure | `ERROR`      | `RedisManager`            |
| Pattern timeout          | `WARNING`    | `SusPatternsManager`      |
| Cloud IP range update    | `INFO`       | `CloudManager`            |

___

Log Sanitization
----------------

User-supplied values in log messages are sanitized by `_sanitize_for_log()`:

```python
def _sanitize_for_log(value: str) -> str:
    sanitized = value.replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t")
    sanitized = "".join(
        char if ord(char) >= 32 or char in "\t\n\r" else f"\\x{ord(char):02x}"
        for char in sanitized
    )
    return sanitized
```

This prevents log injection attacks through control characters in headers like `X-Forwarded-For`.

___

Redaction Verification
-----------------------

The unit suite covers the redaction grammar above with a fixed set of hand-picked cases. The `Redaction Gate` GitHub Actions workflow (`.github/workflows/redaction-gate.yml`) covers the rest of the shape space: `tests/redaction_gate/genprobe.py` plants a unique secret into every combination of sensitive field name, casing, assignment token, whitespace, position, separator, quoting, wrapper, percent-encoding depth, trigger pattern and value shape, dropped onto every request surface guard-core exposes (headers, cookies, query strings, URL fragments and path segments, matrix parameters, form fields, multipart parts, JSON at various depths and nesting, and more). It runs a mandatory one-axis-at-a-time sweep across every surface, plus a seeded random sample of additional combinations, through both the async and sync `detect_penetration_attempt` entry points and the full `SecurityCheckPipeline`, and scans every log line, `SecurityEvent`, `SecurityMetric`, `on_block`/`on_error` payload, Logfire call and OpenTelemetry span for the planted secret.

The gate fails (exit code 1, red CI check) if any case leaks its secret anywhere. A case where the trigger never fired (`NOT_DETECTED`) or where the secret was planted as a bare token with no `key=value` assignment (`UNASSIGNED_TOKEN`, not a redaction failure) is reported separately and does not fail the job. Every run uploads a `redaction-gate-ledger` artifact (the full JSON case ledger plus the raw run log) and writes the `RESULT` and axis-summary blocks to the job's step summary, so a regression names the exact axis combination and surface that leaked without needing to reproduce the run.
