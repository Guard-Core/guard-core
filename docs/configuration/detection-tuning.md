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

### `detection_pattern_validation_cache_path`

**Type**: `str | None` | **Default**: `None`

Optional file path for a disk-backed pattern-validation cache. When set, the empirical cost-verdict outcome of `validate_pattern_safety` (probe synthesis plus timed subprocess probes) is cached keyed by pattern, flags, and engine version, so a process boot reuses prior certifications instead of re-timing every custom pattern. The cheap deterministic layers (dangerous constructs, compile check, structural detectors) always re-run; cache entries produced by a different engine version are ignored and overwritten. Leave unset to keep every validation fully empirical. Aimed at shared-nothing workers and hosts where subprocess spawn latency makes startup validation prohibitively slow.

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

**Type**: `float` | **Default**: `3.0` | **Range**: 0.0 (exclusive) - 30.0 | **Scope**: both trees

Seconds to wait for an adapter's `read_body_prefix`/`body` call before treating the body as unavailable to detection. In `guard_core` (async) this bounds the wait via `asyncio.wait_for`, against a stalled or misbehaving adapter/stream.

In `guard_core.sync`, a blocking call cannot be cancelled from the outside, so each read attempt runs on its own daemon thread and `body_read_timeout` bounds how long the caller joins that thread; the thread itself keeps running in the background until the adapter's call returns, only the caller stops waiting for it. `sync_body_read_max_concurrent` (default `64`) caps how many such threads may be blocked at once; once that budget is exhausted, further attempts queue for it and give up (logging the exhaustion) rather than spawning without limit.

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

!!! info "Semantic vs Regex"
    Regex patterns provide definitive threat detection. Semantic analysis is a secondary layer that catches obfuscated or novel attacks. Lowering the semantic threshold increases the chance of catching evasion attempts but also increases false positives on legitimate content containing technical terms.

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

Anomaly/threat score required to flag a request as a threat.

### `detection_scan_body`

**Type**: `bool` | **Default**: `True`

Whether to scan the request body during detection. Set to `False` to restrict detection to the URL path, query parameters, and headers: the body is then never read or matched, regardless of its shape.

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

Every category also runs on the `unknown` context, which is what a direct `SusPatternsManager.detect()` call without a context uses. Multipart parts, form fields and JSON values scan as `request_body`; a cookie value scans as `header`; a matrix parameter or path segment scans as `url_path`. 4.0.0 reviewed the whole matrix pair by pair with the per-context benchmark: nineteen (category, context) pairs that were never scanned gained coverage where the malicious corpus fired and the benign corpus stayed clean (three of them extend an already-disclosed false-positive class into one more context, with the corpus ids named in the benchmark), `sqli` gained `header` and `url_path` with three noise-prone rows kept narrow at pattern level, and every pair still excluded (`cmd_injection` on paths beyond the substitution patterns, `file_upload` on paths, `cms_probing`, `recon` and `sensitive_file` on headers) is one where the malicious corpus gains nothing on that context. That benchmark (`tests/test_sus_patterns/test_detection_benchmark.py`, run by the Detection Gate workflow) now measures recall and false positives per context for every category, so a change to any set shows up as a number, not a surprise.
