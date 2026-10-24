---

title: Detection Tuning
description: Guide to tuning guard-core's detection engine for optimal sensitivity vs performance tradeoffs
keywords: detection tuning, sensitivity, performance, false positives, guard-core
---

Detection Tuning
================

The detection engine's behavior is controlled by several `SecurityConfig` fields prefixed with `detection_`. This guide explains each field and how to tune them for different deployment scenarios.

Configuration Fields
--------------------

### `detection_compiler_timeout`

**Type**: `float` | **Default**: `2.0` | **Range**: 0.1 - 10.0

Maximum time in seconds for a single regex pattern match. Patterns that exceed this timeout are cancelled, preventing ReDoS attacks from consuming server resources.

| Value    | Tradeoff                                                     |
|----------|--------------------------------------------------------------|
| `0.5`    | Very aggressive. May cause false negatives on complex inputs.|
| `2.0`    | Balanced. Catches most attacks while limiting resource usage.|
| `5.0`    | Permissive. Better detection but higher latency risk.        |

### `detection_max_scan_seconds`

**Type**: `float` | **Default**: `10.0` | **Range**: 0.1 - 60.0

CPU time allowed for regex scanning one request (thread CPU time, not wall time, so a busy or CPU-starved host does not exhaust it), summed across every field (query parameters, headers, body values) and every pattern, not per `detect()` call. Once the budget is spent, the remaining patterns and request values are not scanned and the request gets a weighted `pattern_timeout` threat (pattern `scan_time_budget_exhausted`) that counts toward the anomaly score and the reported `timeouts`, the same way a per-pattern `detection_compiler_timeout` does, so padding a request with filler cannot silently skip detection. The default is far above normal traffic (a few milliseconds per request, roughly 16 ms for 8,863 characters on one measured CPU) and about 6 times the worst legitimate case the value cap allows (256 benign query parameters, 512 scan units, measured at about 1.5 s on that CPU), which leaves headroom for slower hosts. Only regex pattern CPU time counts, not decoding or semantic analysis. A pattern that hits `detection_compiler_timeout` is charged that timeout.

In the async tree the scan awaits the regex worker instead of blocking the event loop, so other requests run between patterns. A single regex that is already executing still holds the GIL until it returns. The sync tree has no event loop and keeps blocking.

### `detection_pattern_validation_cache_path`

**Type**: `str | None` | **Default**: `None`

Optional file path for a disk-backed pattern-validation cache. When set, the empirical cost-verdict outcome of `validate_pattern_safety` (probe synthesis plus timed subprocess probes) is cached keyed by pattern, flags, the effective content-length cap, interpreter, validator source, and engine version, so a process boot reuses prior certifications instead of re-timing every custom pattern. The cheap deterministic layers (dangerous constructs, compile check, structural detectors) always re-run; entries from a different engine version, interpreter or validator sources are ignored and overwritten, host-caused rejects (deadline, subprocess timeout) are never stored, and a cache file or directory that is group- or world-writable or owned by another user is not loaded or written (every pattern is then validated in full). Leave unset to keep every validation fully empirical. Aimed at shared-nothing workers and hosts where subprocess spawn latency makes startup validation prohibitively slow.

### `detection_max_content_length`

**Type**: `int` | **Default**: `10000` | **Range**: 1000 - 100000

Maximum character count for content passed to the detection engine. Content exceeding this limit is truncated (with attack-preserving logic if enabled).

| Value     | Tradeoff                                                    |
|-----------|-------------------------------------------------------------|
| `3000`    | Fast processing. May miss attacks in large request bodies.  |
| `10000`   | Balanced for most APIs.                                     |
| `50000`   | Thorough scanning. Higher memory and CPU usage per request. |

### `detection_max_body_inspect_bytes`

**Type**: `int` | **Default**: `262144` | **Range**: 1024 - 10485760

Maximum bytes read from the start of the request body and inspected during detection. Bodies whose `Content-Length` exceeds this are never read or scanned, bounding memory on the detection hot path.

This is a memory bound, not full-body coverage. Only the first `detection_max_body_inspect_bytes` bytes of the body are ever scanned, whether they come from a `Content-Length`-bounded read or from an adapter's `BoundedBodyReader.read_body_prefix`. An attacker who pads a request with that many bytes of filler before the actual payload, or splits a signature across the boundary, evades detection; this is inherent to bounded-memory scanning and cannot be closed without reading the whole body. Raise the value to shrink the blind spot at the cost of holding more memory per inspected request; it is a tradeoff, not a full-scan guarantee.

Distinct from `detection_max_content_length` (the regex scan window over already-decoded content) and `max_request_size` (the request-size gate that returns a 413).

### `body_read_timeout`

**Type**: `float` | **Default**: `3.0` | **Range**: 0.0 (exclusive) - 30.0

Seconds a request-body read may sit idle. Detection reads the body through the adapter's `read_body_prefix_until_idle(max_bytes, idle_timeout)` and passes this value as `idle_timeout`. A client that keeps sending is never cut off, however large the upload. A client that stops sending for this long is: the adapter raises `BodyReadStalledError` and guard-core answers `408` when `fail_secure` is on, or logs it, sends an event and lets the request through when it is off. A read that fails (a dropped connection, an adapter error) answers `400` under `fail_secure`. Neither outcome counts as a strike.

An adapter that has no `read_body_prefix_until_idle` is read through `read_body_prefix`, then `body`, awaited in full with no deadline of its own. One warning per adapter class names the missing method, and the server's own timeout is the only bound on such a read. `guard_core.sync` reads on the request thread and never on another thread, so no read is abandoned half-way; a sync adapter applies the idle timeout to its stream or maps the server's socket timeout to `BodyReadStalledError`.

The same value is how long a read waits for a free slot when a slot limit is set (`async_body_read_max_concurrent`, `sync_body_read_max_concurrent`). The async tree also uses it as the `asyncio.wait_for` bound on the response-body read of a `return_pattern` rule.

### `async_body_read_max_concurrent`

**Type**: `int | None` | **Default**: `None` | **Range**: 1 - 10000 | **Scope**: async tree

`None` means no limit, as in v4.4.0: a request-body read never waits for a slot, so a flood of slow clients is bounded by `body_read_timeout` and the server's own limits only. When set to `N`, the `N+1`th concurrent read waits for a slot for up to `body_read_timeout`, then gets the `fail_secure` outcome: `408` with a log line and an event and no strike when `fail_secure` is on, a log line and an event and the request passes unscanned when it is off, never a silent skip. Size it with care: N slow clients that hold every slot make each other body wait for one. The bound is per process; event loops on several threads share it as a soft limit.

### `sync_body_read_max_concurrent`

**Type**: `int` | **Default**: `64` | **Range**: 1 - 10000 | **Scope**: sync tree

Request bodies the sync tree reads at once, each on its own request thread. A further request waits for a slot for up to `body_read_timeout`, then gets the same `fail_secure` outcome as above. The async tree does not read this field.

### `detection_preserve_attack_patterns`

**Type**: `bool` | **Default**: `True`

When `True`, the truncation algorithm identifies attack-like regions in the content and preserves them in the truncated output, even if they fall beyond the `max_content_length` boundary. Set to `False` for simple left-truncation when performance is critical.

### `detection_semantic_threshold`

**Type**: `float` | **Default**: `0.7` | **Range**: 0.0 - 1.0

Minimum score from the `SemanticAnalyzer` to classify content as a threat. The semantic analyzer scores content across multiple attack types (XSS, SQL injection, command injection, path traversal, template injection).

| Value    | Tradeoff                                                     |
|----------|--------------------------------------------------------------|
| `0.3`    | Very sensitive. High detection rate but more false positives.|
| `0.7`    | Balanced. Good detection with low false positive rate.       |
| `0.9`    | Conservative. Only high-confidence semantic threats trigger. |

!!! note "Separate from the threat score threshold"
    `detection_semantic_threshold` is the knob for semantic findings. `detection_threat_score_threshold` only governs the regex anomaly score and does not silence a semantic finding. A value of `0.0` flags every request and is reported by `fail_on_misconfiguration`.

!!! info "Semantic vs Regex"
    Regex patterns provide definitive threat detection. Semantic analysis is a secondary layer that catches obfuscated or novel attacks. Lowering the semantic threshold increases the chance of catching evasion attempts but also increases false positives on legitimate content containing technical terms.

### `excluded_semantic_detection_headers`

**Type**: `set[str]` | **Default**: `set()`

Opt-in list of header names whose values skip the semantic analyzer only, matched case-insensitively. Regex category scanning of those headers is unchanged, and `excluded_detection_headers` keeps its own meaning (a listed header is not scanned at all). The semantic analyzer counts base64 as obfuscation and encoding layers, so JWT session cookies and bearer tokens can score close to `detection_semantic_threshold` (0.30 to 0.59 measured on sample cookies, 0.71 reported). For apps with JWT sessions, set `excluded_semantic_detection_headers={"cookie", "authorization"}` instead of raising the global threshold. A route can add names with `@security.detection_exclusion(semantic_headers={...})`.

### `detection_anomaly_threshold`

**Type**: `float` | **Default**: `3.0` | **Range**: 1.0 - 10.0

Number of standard deviations slower than the mean execution time to flag a pattern as anomalous; a faster-than-average execution is never flagged. This tracks performance anomalies, not security threats. Anomaly events sent to the agent handler are additionally rate-limited per pattern by `PerformanceMonitor`'s `anomaly_emission_cooldown` (default 60s), so a host-wide stall cannot burst thousands of events at once, see `docs/internals/detection-engine.md`.

| Value    | Tradeoff                                                     |
|----------|--------------------------------------------------------------|
| `2.0`    | Sensitive anomaly detection. More alerts on normal variance. |
| `3.0`    | Standard. Catches significant deviations.                    |
| `5.0`    | Only extreme outliers trigger alerts.                        |

### `detection_slow_pattern_threshold`

**Type**: `float` | **Default**: `0.1` | **Range**: 0.01 - 1.0

Execution time in seconds above which a pattern is considered slow. Slow patterns are reported in performance diagnostics and may indicate ReDoS vulnerability.

### `detection_monitor_history_size`

**Type**: `int` | **Default**: `1000` | **Range**: 100 - 10000

Number of recent performance metrics retained in the `PerformanceMonitor`. Larger values provide better statistical analysis but consume more memory.

### `detection_max_tracked_patterns`

**Type**: `int` | **Default**: `1000` | **Range**: 100 - 5000

Maximum number of unique patterns tracked by the performance monitor. When exceeded, the oldest pattern's stats are evicted. Also controls the `PatternCompiler` cache size.

### `detection_threat_score_threshold`

**Type**: `float` | **Default**: `1.0` | **Range**: 0.0 - 10.0

Regex anomaly score required to flag a request as a threat.

!!! warning "This does not govern semantic findings"
    A request is a threat when its regex anomaly score reaches `detection_threat_score_threshold` **or** the semantic analyzer reports any finding. Raising `detection_threat_score_threshold` therefore does **not** silence semantic findings. Use [`detection_semantic_threshold`](#detection_semantic_threshold) to tune those. A value of `0.0` flags every request and is reported by `fail_on_misconfiguration`.

### `detection_scan_body`

**Type**: `bool` | **Default**: `True`

Whether to scan the request body during detection. Set to `False` to restrict detection to the URL path, query parameters, and headers: the body is then never read or matched, regardless of its shape.

### Source file paths in JSON bodies

A value that is a bare script or source file name (`index.php`, `run.sh`, `q.sql`, `app.rb`) in a query value or a JSON body field is flagged as a sensitive file access. Four JSON shapes that webhooks send list changed files, so Guard Core does not flag a plain path (the value ends at the extension, with no suffix trick, path info or query string) in them:

| Shape | Pinned example |
|---|---|
| Push change list: `added`, `removed`, `modified` of an object reached through `commits` or `head_commit` | `{"commits": [{"modified": ["src/app/main.py"]}]}` |
| Review comment: `path` beside `diff_hunk` or `position` | `{"comment": {"path": "src/app.py", "diff_hunk": "@@ -1 +1 @@", "position": 3}}` |
| Pull request file: `filename` beside `patch` or `status` | `[{"filename": "setup.py", "status": "modified", "patch": "@@ -1 +1 @@"}]` |
| Stack frame: `filename` or `abs_path` beside `lineno` or `function`, inside `frames` | `{"frames": [{"filename": "app/main.py", "abs_path": "/srv/app/app/main.py", "function": "main", "lineno": 9}]}` |

A push change list also clears the rows for sensitive file names, so a push that lists `config/settings.py`, `.env.example`, `config/database.yml`, `wp-config.php` or `tsconfig.json` is not flagged: `{"commits": [{"added": ["config/settings.py", ".env.example"]}]}`. Only a plain relative name is cleared. `../.env`, `/srv/app/.env`, `.env?x=1`, `settings.py/x`, `.env%00.jpg` and `settings.py;.jpg` are still flagged. In a stack frame, `abs_path` also clears the absolute path row.

A scalar such as `{"path": "x.py"}`, `{"file": ".env"}` or `{"page": "index.php"}`, the same names under any other key, a trick suffix (`main.php%00.jpg`) and traversal in these shapes are still flagged.

A body field that carries another benign shape is the route's to declare, with `detection_exclusion(body_fields=...)`. A set skips the field in every category. A map from a field name to a set of categories skips only those categories for that field, and every other category still applies to it (the same two forms and the same validation as `params`):

```python
@security.detection_exclusion(body_fields={"changed_file"})
async def every_category_skipped(): ...


@security.detection_exclusion(body_fields={"changed_file": {"sensitive_file"}})
async def only_sensitive_file_skipped(): ...
```

`SecurityConfig.excluded_detection_body_fields` takes the same two forms for every route, and a route's own value replaces the global one (it is not merged with it):

```python
config = SecurityConfig(
    excluded_detection_body_fields={"changed_file": {"sensitive_file"}},
)
```

A body sent under a content type that is not JSON, form or multipart is scanned as one text, as before. When it starts with `{` or `[`, each of its string literals that holds a backslash is also decoded and scanned on its own, so an escaped payload (`\u003cscript\u003e`, also nested in further escaped JSON) is found; a body with no backslash is not walked. Path rows which need a whole value never apply to those literals.

___

Tuning Profiles
---------------

### High Security

For applications handling sensitive data where false negatives are unacceptable:

```python
SecurityConfig(
    detection_compiler_timeout=5.0,
    detection_max_content_length=50000,
    detection_preserve_attack_patterns=True,
    detection_semantic_threshold=0.3,
    detection_anomaly_threshold=2.0,
    detection_slow_pattern_threshold=0.05,
)
```

### Balanced (Default)

Suitable for most production deployments:

```python
SecurityConfig(
    detection_compiler_timeout=2.0,
    detection_max_content_length=10000,
    detection_preserve_attack_patterns=True,
    detection_semantic_threshold=0.7,
    detection_anomaly_threshold=3.0,
    detection_slow_pattern_threshold=0.1,
)
```

### High Performance

For high-throughput APIs where latency is critical:

```python
SecurityConfig(
    detection_compiler_timeout=0.5,
    detection_max_content_length=3000,
    detection_preserve_attack_patterns=False,
    detection_semantic_threshold=0.9,
    detection_anomaly_threshold=5.0,
    detection_slow_pattern_threshold=0.05,
    detection_monitor_history_size=100,
    detection_max_tracked_patterns=200,
)
```

### Detection Disabled

For routes where detection is not needed (e.g., health checks):

```python
SecurityConfig(
    enable_penetration_detection=False,
)
```

Or per-route via decorators:

```python
@security.suspicious_detection(enabled=False)
async def health_check():
    return {"status": "ok"}
```

___

Diagnostics
-----------

The `SusPatternsManager` provides runtime diagnostics:

```python
from guard_core.handlers.suspatterns_handler import sus_patterns_handler

stats = await sus_patterns_handler.get_performance_stats()
# {
#     "summary": {"total_executions": 15432, "avg_execution_time": 0.003, ...},
#     "slow_patterns": [...],
#     "problematic_patterns": [...]
# }

status = await sus_patterns_handler.get_component_status()
# {"compiler": True, "preprocessor": True, "semantic_analyzer": True, "performance_monitor": True}
```

Use these diagnostics to identify patterns that need optimization or replacement.

Binary uploads and the artifact density gate
--------------------------------------------

Text-decoded binary bodies (multipart file uploads, zip archives) used to produce spurious pattern matches on artifact bytes, so binary uploads were blocked and their client IPs auto-banned. The sus-pattern engine now discards a regex match that is about to become a threat when the match comes from a registered noise-prone heuristic pattern (the shell-source family: glued backtick pairs, dollar substitutions, the shell keyword chain, quote splice, glob wildcard atoms, template fragments, LDAP paren conjunctions; the registry is `NOISE_PRONE_PATTERN_SOURCES` in the pattern table) and the scanned string is dense in binary artifact characters: control characters (except tab, newline, carriage return, plus DEL), Latin-1/Latin-Ext-A artifact bytes outside a small text allowlist, surrogateescape bytes and the Unicode replacement character, with at least 4 such characters inside the 64-character margin around the match. Signature patterns are deliberately never gated, so padded-payload recall (webshells, pickle opcodes, base64-fragmented parts) is unchanged. The check is an O(1) prefix-sum difference per match, built once per scanned string, and is invisible on pure text: a string with zero artifacts passes every match through unchanged, so accented European text, Cyrillic, CJK and every other non-Latin script keep full detection coverage. See `specs/06-suspatterns.md` ("Binary artifact density gate") for the exact definition; derived threats without a match position (timeouts, decode-budget exhaustion, semantic and JSON structural threats) are not filtered by this gate.

Printable-run islands for binary file parts
-------------------------------------------

The density gate suppresses noise-prone pattern matches near artifact bytes, but a non-gated pattern can still fire inside a compressed file part: in half a megabyte of deflate output the probability of a short attack-shaped printable fragment (for example the LDAP `)(` followed by `!`) reaches certainty, and a fragment that lands in a locally clean 64-character window is not gated. Instead of extending that whack-a-mole to every pattern, the scan input for the part is reduced before pattern matching ever runs. A multipart file-part payload whose binary artifact characters (the same set the density gate counts, via `build_binary_prefix`) make up at least a fifth of it is binary-dense and is reduced to its printable runs (`extract_binary_islands` in `guard_core/detection_engine/binary_islands.py`): runs of tab, newline, carriage return, ASCII 0x20-0x7E, and decoded non-ASCII printable characters, keeping only runs whose length reaches `detection_binary_min_run_length` (default 16) and scanning each retained run as its own scan value, so no pattern can match across the binary bytes that separate two runs, and no pair of sub-threshold matches can accumulate into a block across that gap. A part payload below the ratio (text uploads, small files, mostly-text documents) keeps its full scan, text parts without a filename are never reduced, and whole-body fallback scans (`_scan_blob_body`) are never reduced at all: raw-body signature coverage (pickle opcodes at scan-window boundaries, UTF-16/32 payloads routed through the wide-encoding preprocessor, null-byte LDAP shapes) is a deliberate contract the density gate already preserves, and content-level reduction would break it. Each retained run costs one scan value against `detection_max_scan_values` and its length against `detection_max_scan_chars`, so the existing budgets bound a payload that decomposes into many runs.

The effect on compressed data is that the printable runs it produces are almost never 16 characters long, so a large archive yields no scannable content at all and the false-positive rate stops growing with file size. Text genuinely embedded in a binary-dense file survives: a script inside a PDF's text sections, a stored path inside an archive, a padded webshell's code run, all form one long run that is scanned in full, and file names, multipart field names, and part headers are scanned regardless. Two things are given up, deliberately, and only for binary-dense part payloads: an attack pattern whose printable characters are shorter than the configured run length is not detected, and a pattern whose match would span embedded binary bytes (for example the null-byte LDAP shapes inside a file part) is not detected either; both remain detected in text payloads, which keep their full scan. Raising the threshold trades recall for fewer noise matches; lowering it toward 4 restores short-fragment detection at the cost of reintroducing statistical matches on large binary uploads.

___

Known Limitations
------------------

- **NoSQL operator detection.** Numeric range operators (`$gt`, `$gte`, `$lt`, `$lte` with a numeric literal) are not flagged as NoSQL injection: they are indistinguishable from legitimate range queries. Auth-bypass shapes (`$ne` null or boolean, `$gt ""`, `$regex`, `$where`, `$exists`, `$in`) are flagged. Use schema validation or route-level allowlisting for numeric fields.
- **SSRF via attacker-controlled DNS.** Any hostname can resolve to an internal IP at request time, and no request-body pattern can see a DNS answer. Use an egress-time resolved-IP check (DNS-rebinding-aware) for fields that accept arbitrary hostnames, not pattern matching alone.
- **Command execution aliases.** Node's `execFile`/`execFileSync`, Ruby's `Kernel#spawn` and backtick literals, Perl's list-form `system`, Go's `os/exec.Command`, PowerShell's `Invoke-Expression`, and any project-local wrapper function around any of these are not covered. Use a language-aware static analyzer or a runtime sandbox for code paths that execute external processes.
- **Python dynamic dispatch.** `os.__dict__ ['system'](...)`, `globals() ['os'].system(...)`, `operator.attrgetter(...)`, and chained `importlib` indirection are not covered. Avoid resolving dangerous stdlib callables from request-controlled strings; use an explicit allowlist of callable names if dynamic dispatch is required.
- **Dynamic code execution.** String-concatenated property access such as `window['ev'+'al']`, an alias bound earlier such as `var x = eval; x(...)`, and a non-literal argument such as `Function(atob(encoded))` are not covered. Use a Content-Security-Policy that disallows `unsafe-eval` as the enforcement layer; pattern matching cannot resolve an expression it does not evaluate.
- **Custom pattern validation timeout.** A custom pattern registered through `add_pattern` (directly, restored from Redis, or pushed by a dynamic rule) whose honest reach-probe measurement needs more than the shared wall-clock budget is refused with the timeout reason rather than accepted; simplify the pattern to bring it under that budget. When a pattern's probe enumeration alone would exceed that budget, a deterministic stride sample of the probe sets (every probe family and repeat site represented) is timed instead of the full enumeration. The budget is 40 seconds on an unloaded host and scales by the same measured load factor that normalizes the sample times (ceiling 240 seconds), so a verdict does not depend on the machine or its load.
- **Nested unbounded quantifiers are refused before timing.** A custom pattern whose group carries an unbounded quantifier and is itself unboundedly quantified (the `(x+)+` shape) is rejected with the dangerous-construct reason without a timed probe, even when a mandatory separator inside the group makes it linear; `^(?:/[^/]+)+/?$` is refused although it backtracks linearly. Rewrite such a pattern so the repeated group starts with its separator and the first segment stands alone, for example `^/[^/]+(?:/[^/]+)*/?$`. This is deliberate: exponential triggers are short and a probe can miss one, so a false rejection is preferred over a false acceptance.

___

Request Contexts per Category
-----------------------------

Every pattern category runs only on the request contexts it is scoped to. A payload in a context outside the category's set is never matched, whatever the pattern. The sets, as shipped:

| Category | Contexts |
|----------|----------|
| `cmd_injection` | `header`, `query_param`, `request_body` (the glued-shell substitution patterns also run on `url_path`) |
| `cms_probing` | `query_param`, `request_body`, `url_path` |
| `code_injection` | `header`, `query_param`, `request_body`, `url_path` |
| `deserialization` | `header`, `query_param`, `request_body`, `url_path` |
| `dir_traversal` | `header`, `query_param`, `request_body`, `url_path` |
| `file_inclusion` | `header`, `query_param`, `request_body`, `url_path` |
| `file_upload` | `header`, `query_param`, `request_body` |
| `http_split` | `header`, `query_param`, `request_body`, `url_path` |
| `ldap` | `header`, `query_param`, `request_body`, `url_path` |
| `nosql` | `header`, `query_param`, `request_body`, `url_path` |
| `path_traversal` | `header`, `query_param`, `request_body`, `url_path` |
| `proto_pollution` | `header`, `query_param`, `request_body`, `url_path` |
| `recon` | `query_param`, `request_body`, `url_path` (the whole-value path rows, whose leading separator is optional on a URL path, count on `query_param` and `request_body` only when the value starts with `/` or `\`) |
| `sensitive_file` | `query_param`, `request_body`, `url_path` |
| `sqli` | `header`, `query_param`, `request_body`, `url_path` (three noise-prone rows, the bare `ORDER BY n` terminator, the glued comment and the bare `EXEC sp_`/`xp_`, stay on `query_param` and `request_body`; a quote- or digit-prefixed `ORDER BY n` and a `;`- or quote-prefixed `EXEC` run everywhere) |
| `ssrf` | `header`, `query_param`, `request_body`, `url_path` |
| `template` | `header`, `query_param`, `request_body`, `url_path` |
| `xml` | `header`, `query_param`, `request_body`, `url_path` |
| `xss` | `header`, `query_param`, `request_body`, `url_path` |

Every category also runs on the `unknown` context, which is what a direct `SusPatternsManager.detect()` call without a context uses. Multipart parts, form fields and JSON values scan as `request_body`; the `Cookie` header scans one `name=value` pair at a time, as `header`; a matrix parameter or path segment scans as `url_path`. 4.0.0 reviewed the whole matrix pair by pair with the per-context benchmark: nineteen (category, context) pairs that were never scanned gained coverage where the malicious corpus fired and the benign corpus stayed clean (three of them extend an already-disclosed false-positive class into one more context, with the corpus ids named in the benchmark), `sqli` gained `header` and `url_path` with three noise-prone rows kept narrow at pattern level, and every pair still excluded (`cmd_injection` on paths beyond the substitution patterns, `file_upload` on paths, `cms_probing`, `recon` and `sensitive_file` on headers) is one where the malicious corpus gains nothing on that context. That benchmark (`tests/test_sus_patterns/test_detection_benchmark.py`, run by the Detection Gate workflow) now measures recall and false positives per context for every category, so a change to any set shows up as a number, not a surprise.
