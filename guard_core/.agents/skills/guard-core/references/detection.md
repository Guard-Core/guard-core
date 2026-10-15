# Detection Engine

`guard_core.detection_engine` exposes four components, orchestrated by `SusPatternsManager` (`guard_core/handlers/suspatterns_handler.py`).

## Public entry point

```python
from guard_core.handlers.suspatterns_handler import SusPatternsManager

result = await SusPatternsManager().detect(
    content=user_input,
    ip_address=request.client_host or "unknown",
    context="query_param",  # one of the context zones
    correlation_id=None,
    enabled_categories=None,  # subset of the 19, None = all
)
```

`context` filters which categories run. Valid zones: `query_param`, `header`, `url_path`, `request_body`, `unknown`. Each category maps to a frozenset of zones via `CATEGORY_CONTEXT_MAP`; a category runs only when its zones include the supplied context. `unknown` is the catch-all.

## detect() return shape

`dict[str, Any]` with at least: `is_threat: bool`, `threat_score`, `threats` (list of regex + semantic threat dicts), `regex_threats`, `semantic_threats`, `matched_patterns`, `timeouts`, `execution_time_ms`, `detection_method` (`"enhanced"` when a `PatternCompiler` is wired, else `"legacy"`).

For a boolean + pattern-name result, use `detect_pattern_match(content, ip_address, context, correlation_id) -> tuple[bool, str | None]`.

## DetectionResult

`guard_core.detection_result.DetectionResult` is a lightweight dataclass:

```python
@dataclass
class DetectionResult:
    is_threat: bool
    trigger_info: str
    threat_categories: list[str] = field(default_factory=list)
    threat_scores: dict[str, float] = field(default_factory=dict)
```

## The 19 categories

`ALL_DETECTION_CATEGORIES` (`guard_core/handlers/suspatterns_handler.py`): `xss`, `sqli`, `dir_traversal`, `path_traversal`, `cmd_injection`, `file_inclusion`, `ldap`, `xml`, `ssrf`, `nosql`, `file_upload`, `template`, `http_split`, `sensitive_file`, `cms_probing`, `recon`, `proto_pollution`, `code_injection`, `deserialization`.

`deserialization` (CWE-502) matches Java (`rO0AB`), .NET `BinaryFormatter` (`AAEAAAD`) and Ruby `Marshal` (`BAh[Jv7bV]`) serialized payloads in their base64 wire form (`_DESERIALIZATION_JAVA_B64_RE`, `_DESERIALIZATION_DOTNET_B64_RE`, `_DESERIALIZATION_RUBY_B64_RE`, defined in `guard_core/handlers/_suspatterns_sources.py:269-272` and still importable from `guard_core.handlers.suspatterns_handler` by the original names), the raw XAML gadget marker `<ObjectDataProvider` (`guard_core/handlers/_suspatterns_pattern_table.py:704`), and PHP (`O:`/`C:`/`E:`). Python pickle is matched two ways: the base64 marker `gASV`/`gAWV` (`_DESERIALIZATION_PICKLE_B64_RE`, defined in `guard_core/handlers/_suspatterns_sources.py:271` and still importable from `guard_core.handlers.suspatterns_handler`), and the raw (non-base64) protocol-0 `GLOBAL` opcode text itself, `c<module>\n<name>\n` (`_DESERIALIZATION_PICKLE_OS_GLOBAL_RE`, `_DESERIALIZATION_PICKLE_GLOBAL_GENERIC_RE`, defined in `guard_core/handlers/_suspatterns_sources.py:273-278` and still importable from `guard_core.handlers.suspatterns_handler`, wired into the category's pattern list in `guard_core/handlers/_suspatterns_pattern_table.py`). Raw bytes are reachable: the request body is decoded with `body_bytes.decode("utf-8", errors="surrogateescape")` (`guard_core/_utils/penetration_detection.py:102`), which never rejects a byte, so non-UTF-8 pickle opcode bytes reach the patterns unchanged. `tests/test_sus_patterns/test_pickle_global_opcode_prefix_bypass.py` proves raw and binary-prefixed pickle payloads are detected through the real `detect_penetration_attempt` entry point across the request body, form body, multipart body, query parameter, and JSON body shapes.

`SusPatternsManager` (`guard_core/handlers/suspatterns_handler.py`) is composed from private mixin and helper modules under `guard_core/handlers/_suspatterns_*.py` (pattern-source tables, the compiled-pattern registry, the per-value regex pass, the additional views, semantic/preprocessing glue); every name importable from `suspatterns_handler` today stays importable from that same module path, the split is internal only.

`ssrf` also matches the IPv4-mapped IPv6 loopback bracket form (`http://[::ffff:127.0.0.1]/`) and a trailing-dot `localhost` (`http://localhost./`), alongside its existing dotted-quad, `localhost`, private/link-local-range, and cloud-metadata-alias coverage; `http://[::ffff:8.8.8.8]/` (a public address in the same bracket shape) stays unflagged.

## Request-value scan cap

`SecurityConfig.detection_max_scan_values` (default `512`, `ge=2`) bounds the total number of individual values -- query parameters, header values, JSON keys and leaf values, form fields, multipart parts, including JSON embedded within a single value -- scanned per request across the whole penetration-detection pass (`guard_core/_security_config_fields.py`). The budget is a per-request `contextvars.ContextVar` pair (`guard_core/_utils/detection_scan.py`), reset around each `detect_penetration_attempt` call. Each named value costs two scan units, one for its name and one for its value, so the minimum is `2`, not `1`. Once the cap is reached, remaining values in that request are not scanned, and a one-time `logger.warning` (per request) names the client IP, so the fail-open stays visible instead of silent.

Request parameter/field/key **names**, not only values, are scanned for injection patterns (`_scan_component_name` in `guard_core/_utils/detection_scan.py`, called from `_scan_query_params`, `_scan_headers`, `_scan_json_value`, `_scan_form_body`, and `_scan_multipart_body` in `guard_core/_utils/body_content_scan.py`): `?username[$ne]=admin`, `?__proto__[isAdmin]=true`, a JSON body key `"1;DROP TABLE x"`, or a multipart field named `__proto__[x]` are all detected via the name, even when the value itself is benign. An excluded header's name and value still get the Log4Shell JNDI shield (`ALWAYS_SCAN_HEADER_PATTERNS`, `guard_core/handlers/suspatterns_handler.py`, checked by `_scan_excluded_header_component` in `guard_core/_utils/body_content_scan.py`) rather than the full pipeline, preserving the excluded-header design.

Each has a default weight of `1.0` in `DETECTION_CATEGORY_WEIGHTS`; specific regex patterns override via `DETECTION_PATTERN_WEIGHT_OVERRIDES` (e.g. a bare `SELECT ... FROM` is down-weighted to 0.5 to reduce false positives).

## Request-char scan cap

`SecurityConfig.detection_max_scan_chars` (default `65536`, `ge=1024`, `le=262144`) bounds the total characters, across every value handed to the pattern engine per request, at the same accounting point `detection_max_scan_values` uses (`_scan_char_budget_exhausted` alongside `_scan_value_budget_exhausted`, `guard_core/_utils/detection_scan.py`). `detection_max_scan_values` bounds the *count* of scanned values; a handful of individually large values can cost as much CPU as many small ones without ever approaching that count, which is what this cap closes (GHSA-3hfx-8m47-5f9h residual: 28 values x 9342 characters cost 1.81s CPU in enhanced mode with no cap). The budget is a leaky-bucket, not a hard per-value truncation: a value already in progress when checked (the running total from *prior* values is still under the cap) is always scanned in full, even if that pushes the total over the cap, so a single large legitimate value (a big JSON body scanned as one blob, for example) is never silently skipped outright; only values that would *start* after the budget is already spent are skipped. Once that happens, a one-time `logger.warning` per request names the cap and the client IP, the same signal `detection_max_scan_values` gives.

`detect_penetration_attempt(request, config)` configures the detection singleton from `config` when it is unconfigured (`state.compiler is None`) or was last configured from a different config object (identity compared, `guard_core/_utils/penetration_detection.py::_ensure_detection_singleton_configured`), instead of requiring the caller to call `sus_patterns_handler.configure(config)` itself first. This is idempotent and cheap on the hot path (an identity check, not a rebuild) once the singleton is already configured from the same object. Before this, a direct caller of `detect_penetration_attempt` that never explicitly configured the singleton (guard-core-mcp's `check_payload`, a PoC script, a test) ran the legacy path: `_check_regex_pattern` dispatches every pattern through `shared_regex_executor().submit(...)` plus `future.result(timeout=...)`, about 8300 cross-thread round trips for the 28x9342 body, 14 to 19s CPU instead of the enhanced path's 1.81s -- an order of magnitude slower, with different detection results on some payloads.

The detection singleton follows one `SecurityConfig` per process: `sus_patterns_handler` holds a single `_DetectionState` built from whichever config object last configured it. Calling `detect_penetration_attempt` with alternating config objects reconfigures the singleton on every switch, discarding the compiled-pattern cache the previous config built (`PatternCompiler`, `ContentPreprocessor`, `SemanticAnalyzer`, `PerformanceMonitor` are all rebuilt from the new config); a process that legitimately alternates between two `SecurityConfig` objects on every other request pays a full reconfigure every time, not just on the first switch. The swap itself is a single attribute assignment: the new `_DetectionState` is built completely before `sus_patterns_handler._detection_state` is reassigned to it, so a concurrent reader either sees the old, fully-built state or the new, fully-built state, never a half-constructed one. There is no lock around the swap; a race between two concurrent reconfigures from different config objects can still leave either one as the final state, but never a torn state.

When the request's declared `Content-Length` exceeds `detection_max_body_inspect_bytes`, `_read_capped_body` (`guard_core/_utils/body_reader.py`) branches on whether the request implements the bounded reader (`read_body_prefix`, `guard_core/protocols/request_protocol.py`): if it does, only the first `detection_max_body_inspect_bytes` bytes are read through it and scanned, so an attack in the first kilobyte of an oversized body is still detected without ever buffering the oversized body in memory; if it does not, the body is not read at all, the same skip as before `detection_max_body_inspect_bytes` gained bounded-reader support, since there is no way to read a bounded prefix without one. Either way a one-time warning names the cap, the client, and which of the two happened. Both this path (`_read_oversized_declared_body`) and the no-`Content-Length` prefix path (`_read_capped_body_prefix`) fetch the same `_capped_body_fetch_size(max_bytes)` (`max_bytes` plus `_straddle_overlap_bytes()`, the longest compiled pattern length up to 256 bytes), so a signature straddling the cap boundary is caught on either path identically; before this shared helper, only the no-`Content-Length` path applied the overlap, and a declared oversized `Content-Length` missed a straddling signature the other path would have caught.

Three constant-factor cuts reduce the per-byte cost of the enhanced path itself, each proven result-identical (same recall, same false-positive count) by the two-sided detection-gate corpus and benchmark before and after. First: `PerformanceMonitor.record_metric` (`guard_core/detection_engine/monitor.py`) computed `stats.avg_execution_time` with `statistics.mean`, which does exact `Fraction` arithmetic; called once per pattern check (about 8600 times for the 28x9342-character shape above), this accounted for roughly 30% of enhanced-mode CPU for a request that large. It now uses `math.fsum(stats.recent_times) / len(stats.recent_times)`, the same approach `monitor_anomalies.py` already used elsewhere.

Second: `SemanticAnalyzer.analyze` (`guard_core/detection_engine/semantic.py`) called `extract_tokens` twice on the same content, once inside `analyze_attack_probability` and once for `token_count`; it now extracts tokens once per `analyze` call and reuses them for both.

Third: the url-decoded detection view (`_check_url_decoded_view_patterns`, `guard_core/handlers/suspatterns_handler.py`) independently re-ran `decode_common_encodings` on the raw content even when the main pass had already decoded it (or found nothing to decode); `ContentPreprocessor.preprocess_with_decoded` (`guard_core/detection_engine/preprocessor.py`) now exposes the main pass's decoded intermediate so the url-decoded view reuses it instead of decoding twice.

## JSON body depth cap

`SecurityConfig.detection_max_json_depth` (default `32`, `ge=1`, `le=1000`) bounds how deep the structural JSON-body walk descends (`guard_core/_security_config_fields.py`). The walk (`_scan_json_value` in `guard_core/_utils/body_content_scan.py`) is an explicit-stack iteration, not recursion: a dict or list reached at this depth is serialized back to text with `json.dumps(value, separators=(",", ":"), ensure_ascii=False)` and scanned as one value through `_scan_body_field` under the same key label the structural walk would have used, so a payload hidden below the cap is still scanned as text, bounded by `detection_max_content_length`. A one-time `logger.warning` (per request, on the `guard_core` logger) names the client IP once the cap is reached, mirroring the scan-value cap's once-per-request mechanism (`_json_depth_cap`/`_json_depth_warned` contextvars in `guard_core/_utils/detection_scan.py`, reset alongside the scan-value budget by `_scan_value_budget`). Before this cap, the walk recursed one Python call per nesting level with no bound (GHSA-f6cf-jjhc-qp85, CWE-674): a deeply nested body raised `RecursionError` out of `detect_penetration_attempt`, and at depths just below the recursion limit the enhanced-detection exception fallback silently swallowed the error and scanned the request as clean instead of failing secure. `_check_value_enhanced` (`guard_core/_utils/detection_scan.py`) no longer treats `RecursionError` as a fallback case, it re-raises so the pipeline's fail-secure handling sees it; every other exception still falls back to the bounded regex scan.

`_check_embedded_json` (`guard_core/_utils/embedded_json_scan.py`) is a separate check: it looks for a JSON object or array embedded inside a single query parameter, header, or form-field value, not the request body, and hands what it parses to the same body walker, `_scan_json_value` (`guard_core/_utils/body_json_scan.py`), the JSON body itself goes through. It catches `json.JSONDecodeError` and `RecursionError` around its own `json.loads(value)` call, treats a `RecursionError` as not-embedded-JSON, and fires the same `detection_max_json_depth` warning; the outer pattern scan of the raw value still runs. This replaces the former `_check_json_fields` and `_try_check_json_value` (`guard_core/_utils/detection_scan.py`): a `dict`-only, one-level-deep scan with no redaction and no array support, which raised the same `RecursionError` around `json.loads(value)` (a value holding around 1000 nested braces, same CWE-674 class as the body-walk issue above, different code path) before gaining the same catch in 3.15.0. The 4.0.0 module split removed both names outright, with no re-export; `_check_embedded_json` took over their role and gained recursion (so a sensitive key's nested object or array value is redacted as a whole, not just its own top-level fields).

## Preprocessing layers

`ContentPreprocessor.preprocess(content)` applies up to 7 decode/normalize layers before matching: Unicode normalization, URL-decode, HTML-entity decode, null-byte removal, whitespace normalization, attack-region-aware truncation to `detection_max_content_length`, plus opportunistic base64 / hex / Unicode-escape / SQL-comment stripping. Match against the preprocessed content, never raw.

## Semantic analysis

`SemanticAnalyzer.analyze(content)` returns a dict with `attack_probability` (per-category 0-1), `obfuscation` (bool), `code_injection_risk` (float), `threat_score`. Scoring is deterministic: keyword-overlap, Shannon entropy, encoding-layer count, obfuscation indicators. It is not machine learning and does not learn from traffic.

## ReDoS safety

`PatternCompiler.validate_pattern_safety(pattern, test_strings=None, max_content_length=None)` (`guard_core/detection_engine/compiler.py`) first rejects a pattern that hits a known-dangerous construct (`(.*)+`, `(.+)+`, nested quantifiers -- `_dangerous_construct_violation`) and one that fails to compile. Past that, it runs in one of two modes:

* With `test_strings` (the `add_pattern`/dynamic-rule/content-filter call sites): a broader structural pre-filter (`_first_structural_safety_violation`, flagging adjacent broad unbounded quantifiers, ambiguous optional tails in quantified groups, unreachable terminator scans, and ambiguous literal boundaries), then a timed probe of the pattern against `test_strings` inside a **killable subprocess** (`subprocess.run(..., timeout=2.0)`, never a thread the caller waits on), rejecting if any probe exceeds a 50ms-per-string budget.
* Without `test_strings` (the default, used to probe a pattern at a caller's real content-length cap): a timed cost arbiter (`_reach_probe_cost_verdict`) builds adversarial probes at four sizes (roughly 4k/8k/16k/32k characters), times each with `time.process_time()` in a killable subprocess (minimum of 5 samples, median drives the verdict), and rejects only if the growth-extrapolated cost at `max_content_length` exceeds 50ms; a structural hit supplies the rejection reason when the arbiter also rejects, but a structural hit measured under budget and linear does not reject on its own, and no probe being buildable forces fail-closed rejection.

This validation subprocess mechanism is unrelated to, and isolated from, the live-scan pool: built-in (compile-time-vetted, never run through `validate_pattern_safety` at runtime) patterns match directly via `pattern.search()` with no per-match timeout; only custom patterns added via `SusPatternsManager.add_pattern(pattern, custom=True)` run through the shared thread-pool safe-matcher (`shared_regex_executor()`, `guard_core/detection_engine/compiler.py`) with a timeout at match time. Four consecutive timeouts recycle the shared pool (stale workers shut down non-blocking) so one pathological pattern cannot wedge every worker. Separately, the enhanced-detection exception fallback (`_fallback_pattern_check`, `guard_core/_utils/detection_scan.py`) routes every pattern through the same bounded matchers the enhanced scan uses (`SusPatternsManager._check_regex_pattern`), so a pattern-level exception on the enhanced path no longer falls through to an unbounded `pattern.search()`.

## Scan-window bounded matchers

`guard_core.detection_engine.scan_window` (`bounded_search`, `bounded_finditer`) bounds the regex *scan window*, not the match length, for built-in patterns shaped `literal_prefix + unbounded_negated_class + terminator`. It locates every prefix and terminator occurrence with two linear `finditer` passes, then runs the pattern's own unmodified, uncapped regex only against the bounded span from each prefix candidate to the farthest reachable terminator, so neither an unbounded quantifier nor a `{0,N}` length cap is needed to stay linear, and outcome (matched or not) agrees with running the pattern unbounded. `_WINDOWED_PATTERN_FINDERS` (`guard_core/handlers/suspatterns_handler.py`) maps specific built-in pattern strings to a `prefix`/`terminator` pair wired through `bounded_finditer`; a pattern not in that mapping matches directly, uncapped.

## Tuning knobs (SecurityConfig)

`detection_max_content_length` (default 10000), `detection_compiler_timeout` (default 2.0s, range 0.1-10.0), `detection_max_scan_seconds` (default 10.0s, range 0.1-60.0; per-request total regex CPU time budget, exhaustion adds a weighted `pattern_timeout` threat `scan_time_budget_exhausted`), `excluded_semantic_detection_headers` (opt-in; header values skip the semantic analyzer only), `detection_threat_score_threshold` (default 1.0), `detection_max_scan_values` (default 512, `ge=2`; see [Request-value scan cap](#request-value-scan-cap) above), `enabled_detection_categories` (`frozenset[str]`, subset of the 19, defaults to all 19). `PatternCompiler.validate_pattern_safety`'s 50ms cost-arbiter budget is a hardcoded constant, not a config field; only `max_content_length` (the caller's real content-length cap) is passed in per call.

## Adding patterns

```python
ok = await SusPatternsManager.add_pattern(r"<script.*?>", custom=True)
```

Custom patterns are ReDoS-validated, compiled with `re.IGNORECASE | re.MULTILINE`, and (when Redis is enabled) persisted under the `patterns` key. `remove_pattern(pattern, custom=False)` removes them. Do not add unvetted patterns as built-in; custom patterns get the timeout safety path.
