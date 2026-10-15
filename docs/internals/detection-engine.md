---

title: Detection Engine
description: PatternCompiler, ContentPreprocessor, SemanticAnalyzer, and PerformanceMonitor internals for guard-core's threat detection
keywords: detection engine, pattern matching, semantic analysis, performance monitoring, guard-core
---

Detection Engine
================

The detection engine (`guard_core.detection_engine`) provides multi-layered threat detection with four components working together: pattern compilation, content preprocessing, semantic analysis, and performance monitoring.

These components are orchestrated by the `SusPatternsManager` handler, which adapter developers do not call directly but may need to understand for tuning and diagnostics.

Architecture
------------

```mermaid
flowchart TD
    DETECT["SusPatternsManager.detect()"]
    PREPROCESS["1. Preprocess content"]
    NORM["Normalize unicode"]
    DECODE["Decode URL + HTML"]
    NULL["Remove null bytes"]
    WHITESPACE["Normalize whitespace"]
    TRUNCATE["Truncate safely"]
    REGEX["2. Regex matching"]
    KIND{"Built-in or custom pattern?"}
    DIRECT["pattern.search() directly, no timeout wrapper"]
    SAFE["Safe matcher: shared thread pool + timeout"]
    PERF["Record performance metrics"]
    SEMANTIC["3. Semantic analysis"]
    PROB["Attack probability scoring"]
    OBFUSC["Obfuscation detection"]
    INJECT["Code injection risk"]
    AGG["4. Aggregate results"]

    DETECT --> PREPROCESS
    PREPROCESS --> NORM --> DECODE --> NULL --> WHITESPACE --> TRUNCATE
    TRUNCATE --> REGEX
    REGEX --> KIND
    KIND -- Built-in --> DIRECT --> PERF
    KIND -- Custom --> SAFE --> PERF
    PERF --> SEMANTIC
    SEMANTIC --> PROB --> OBFUSC --> INJECT
    INJECT --> AGG
```

Built-in (compile-time-vetted) patterns match directly via `pattern.search()`, with no per-match thread or timeout. Only custom patterns (added via `add_pattern(..., custom=True)`) are routed through the safe-matcher timeout wrapper, a custom-pattern match is flagged as timed out once elapsed time reaches `0.9 * compiler.default_timeout` (i.e. `0.9 * detection_compiler_timeout` when a `SecurityConfig` is wired; legacy/no-compiler mode falls back to a hardcoded 2.0s field default).

The async tree awaits each shared-executor future (`_await_regex_future` in `guard_core/detection_engine/compiler.py`) rather than calling `future.result`, so the event loop runs other tasks between patterns; the sync mirror keeps the blocking `future.result` (the unasync script swaps the helper). A per-request regex CPU time budget (`detection_max_scan_seconds`, tracked in request-scoped context variables by `_scan_value_budget`, fed by thread CPU time measured around inline scans and inside the executor worker) stops the pattern loop once spent and emits a weighted `pattern_timeout` threat named `scan_time_budget_exhausted`; `excluded_semantic_detection_headers` skips only the semantic analyzer for the named headers.

When no `SecurityConfig` is wired at construction (legacy mode), `SusPatternsManager` builds neither a `PatternCompiler` nor a `ContentPreprocessor`; content is instead truncated to `detection_max_content_length` (default 10000) via direct slicing before matching, and every pattern, including what would otherwise be a "custom" pattern, runs through the same shared-executor timeout path described above (`_check_pattern_with_timeout`), reporting to the same success/timeout counters. Running detection unconfigured this way is deprecated and will be removed in a future major release: the first time `detect()` actually executes in this state, it raises a `DeprecationWarning` and logs an identical `logger.warning` naming the reason (`_LEGACY_DETECTION_WARNING`, checked by the `_warn_if_legacy_detection` helper in `guard_core/handlers/suspatterns_handler.py`), once per process, a module-level flag shared by every `SusPatternsManager` instance, not a per-instance one. The check runs from inside `detect()` itself, not at construction or at `configure()`, since the module-level singleton is always built unconfigured at import time and only gets a `SecurityConfig` later from the pipeline; a normally initialised pipeline configures the singleton (directly via `sus_patterns_handler.configure(config)`, or implicitly through `detect_penetration_attempt(request, config)`) before it ever runs detection, so it never warns.

___

PatternCompiler
---------------

Manages regex pattern compilation with LRU caching and ReDoS safety validation.

### Constructor

```python
PatternCompiler(default_timeout: float = 5.0, max_cache_size: int = 1000)
```

| Parameter         | Description                                        | Bounds          |
|-------------------|----------------------------------------------------|-----------------|
| `default_timeout` | Timeout for safe matchers in seconds               | N/A             |
| `max_cache_size`  | Maximum compiled patterns to cache                 | Capped at 5000  |

### Key Methods

**`compile_pattern(pattern, flags) -> re.Pattern`** (async)

Thread-safe compilation with LRU eviction. Cache key is `f"{pattern}:{flags}"`.

**`compile_pattern_sync(pattern, flags) -> re.Pattern`**

Synchronous compilation without caching. Used internally by validators and safe matchers.

**`validate_pattern_safety(pattern, test_strings) -> tuple[bool, str]`**

Validates a pattern against ReDoS vulnerability:

1. Checks for known dangerous constructs: `(.*)+`, `(.+)+`, nested quantifiers.
2. Runs the pattern against test strings (default: varying lengths of `'a'`, `'x'+'y'`, `'<'+'>'`) on a dedicated single-worker `validation_regex_executor()`, isolated from the shared `shared_regex_executor()` scan pool used for live request matching, so a busy scan pool can no longer starve or falsely fail a validation probe.
3. Elapsed time is measured *inside* the submitted callable, i.e. execution time only, not time spent queued behind other probes. The outer `future.result(timeout=1.0)` call bounds total wait to 1.0s, but the pattern is flagged unsafe as soon as a probe's own execution exceeds the stricter 50ms threshold.
4. Any timeout (queue-bound or per-probe), exception, or a probe over 50ms rejects the pattern, validation is fail-closed.

`SusPatternsManager.add_pattern` (the async API used by Redis custom-pattern restore and dynamic-rule pattern pushes) runs this validation via `asyncio.to_thread`, so up to ~1s of ReDoS probing never blocks the event loop. The sync API's `add_pattern` calls `validate_pattern_safety` directly on the calling thread.

**`create_safe_matcher(pattern, timeout) -> Callable[[str], Match | None]`**

Returns a closure that submits the regex to the shared `shared_regex_executor()` thread pool (`max_workers=4`) with a timeout. If the match exceeds the timeout, the future is cancelled and `None` is returned.

```python
safe_match = compiler.create_safe_matcher(r"<script.*?>", timeout=2.0)
result = safe_match(user_input)  # None if timed out
```

Every `safe_match` call, and the legacy no-compiler `_check_pattern_with_timeout` path, reports its outcome to module-level success/timeout counters. Four consecutive timed-out submissions replace the shared pool with a fresh one: the stale pool is shut down non-blocking (`shutdown(wait=False)`) and a warning is logged naming the leaked-worker count, so one pathological custom pattern can no longer wedge every worker permanently. Any successful match resets the counter to zero.

**`batch_compile(patterns, validate) -> dict[str, re.Pattern]`** (async)

Compiles multiple patterns, optionally validating each for safety. Unsafe or invalid patterns are silently skipped.

___

ContentPreprocessor
-------------------

Normalizes and sanitizes input before pattern matching.

### Constructor

```python
ContentPreprocessor(
    max_content_length: int = 10000,
    preserve_attack_patterns: bool = True,
    agent_handler: Any = None,
    correlation_id: str | None = None,
)
```

### Preprocessing Pipeline

The `preprocess()` method runs five stages in order:

| Stage                       | Method                      | Purpose                                          |
|-----------------------------|-----------------------------|--------------------------------------------------|
| Unicode normalization       | `normalize_unicode()`       | NFKC normalization + lookalike character replacement |
| Encoding detection          | `decode_common_encodings()` | URL decode + HTML entity decode (up to 3 iterations) |
| Null byte removal           | `remove_null_bytes()`       | Strips `\x00` and control characters except tab/newline/CR |
| Whitespace normalization    | `remove_excessive_whitespace()` | Collapses multiple spaces, strips leading/trailing |
| Safe truncation             | `truncate_safely()`         | Truncates to `max_content_length` preserving attack regions |

### Attack-Preserving Truncation

When content exceeds `max_content_length` and `preserve_attack_patterns` is `True`:

1. `extract_attack_regions()` scans for 25 attack indicator patterns (e.g., `<script`, `SELECT ... FROM`, `eval(`, `../`, plus the shell metacharacters `` ` ``/`$(`/`[;&|]` and a bare dotted-quad IPv4 indicator).
2. Regions around matches (100 characters of context on each side) are extracted.
3. Overlapping regions are merged.
4. Attack regions are included first, then non-attack content fills remaining space.

This ensures that truncated content still contains the attack patterns for detection.

### Unicode Lookalike Map

The preprocessor replaces over 20 Unicode characters used for evasion:

| Unicode     | Replacement | Purpose                      |
|-------------|-------------|------------------------------|
| `\u2044`    | `/`         | Fraction slash evasion       |
| `\uff0f`    | `/`         | Fullwidth solidus            |
| `\u200b`    | (empty)     | Zero-width space             |
| `\uff1c`    | `<`         | Fullwidth less-than          |
| `\uff1e`    | `>`         | Fullwidth greater-than       |
| `\u037e`    | `;`         | Greek question mark          |

___

SemanticAnalyzer
----------------

Performs structural and statistical analysis of content to detect attacks that evade pattern matching.

### Attack Probability Analysis

```python
def analyze_attack_probability(self, content: str) -> dict[str, float]
```

Returns a dictionary mapping attack types to probability scores (0.0 - 1.0):

| Attack Type  | Keywords Checked                                              | Structural Boost |
|-------------|---------------------------------------------------------------|------------------|
| `xss`       | script, javascript, onerror, onload, alert, eval, document...| `<...>` tags     |
| `sql`       | select, union, insert, update, delete, drop, from, where...  | SQL keywords     |
| `command`   | exec, system, shell, cmd, bash, wget, curl, sudo...          | `;&|` operators  |
| `path`      | etc, passwd, shadow, hosts, proc, boot, win, ini             | `../` traversal  |
| `template`  | render, template, jinja, mustache, handlebars...              | N/A              |

The score is computed as: `min(keyword_match_ratio + structural_boost, 1.0)`.

### Entropy Calculation

```python
def calculate_entropy(self, content: str) -> float
```

Shannon entropy of the character distribution. High entropy (> 4.5) indicates potential obfuscation or encoded payloads.

### Obfuscation Detection

`detect_obfuscation()` returns `True` when any of:

- Entropy > 4.5
- More than 2 encoding layers detected
- Special character ratio > 40%
- Contiguous non-space run > 100 characters

### Code Injection Risk

`analyze_code_injection_risk()` scores (0.0 - 1.0) based on:

- Code-like patterns (`{}`, function calls, variable references)
- AST parseability (attempts `ast.parse(content, mode="eval")` with 100ms timeout)
- Injection keywords (`eval`, `exec`, `compile`, `__import__`, `globals`, `locals`)

### Threat Score

```python
def get_threat_score(self, analysis_results: dict) -> float
```

Aggregates all analysis results into a single 0.0 - 1.0 score:

| Component           | Weight |
|---------------------|--------|
| Max attack probability | 30%  |
| Obfuscation detected   | 20%  |
| Encoding layers        | 10-20% (min of layers *10%, 20%) |
| Code injection risk    | 20%  |
| Suspicious patterns    | 5-10% (min of count* 5%, 10%)    |

___

PerformanceMonitor
------------------

Tracks pattern execution performance and detects anomalies.

### Constructor

```python
PerformanceMonitor(
    anomaly_threshold: float = 3.0,
    slow_pattern_threshold: float = 0.1,
    history_size: int = 1000,
    max_tracked_patterns: int = 1000,
    anomaly_emission_cooldown: float = 60.0,
)
```

| Parameter                    | Description                                     | Bounds       |
|-------------------------------|-------------------------------------------------|--------------|
| `anomaly_threshold`           | Z-score threshold for statistical anomalies     | 1.0 - 10.0  |
| `slow_pattern_threshold`      | Seconds to consider a pattern slow              | 0.01 - 10.0 |
| `history_size`                | Recent metrics to retain                        | 100 - 10,000 |
| `max_tracked_patterns`        | Maximum unique patterns to track                | 100 - 5,000  |
| `anomaly_emission_cooldown`   | Seconds a pattern must wait before it can emit another anomaly event | 1.0 - 3,600.0 |

### Metric Recording

Each pattern execution records a `PerformanceMetric` dataclass:

```python
@dataclass
class PerformanceMetric:
    pattern: str
    execution_time: float
    content_length: int
    timestamp: datetime
    matched: bool
    timeout: bool = False
```

### Anomaly Detection

Three types of anomalies are detected after each metric recording:

| Anomaly Type         | Condition                                                       |
|---------------------|-----------------------------------------------------------------|
| `timeout`           | The pattern execution timed out                                 |
| `slow_execution`    | Execution time > `slow_pattern_threshold` (without timeout)     |
| `statistical_anomaly` | Z-score of execution time > `anomaly_threshold` (needs >= 10 samples) |

`statistical_anomaly` only trips when the execution is slower than its pattern's rolling average; a faster-than-usual run is never reported.

Detected anomalies are forwarded to every registered callback on every trip. Sending the anomaly as an event to the agent handler is rate-limited per pattern by `anomaly_emission_cooldown`: once a pattern has emitted an event, it will not emit another until the cooldown elapses, so a host-wide stall (GC pause, cron job, CPU contention) that makes every tracked pattern trip at once produces one event per pattern instead of a burst. A pattern that is genuinely and consistently slow still reports, just at most once per cooldown window.

### Diagnostics

| Method                   | Returns                                              |
|--------------------------|------------------------------------------------------|
| `get_pattern_report(p)`  | Stats for a specific pattern (executions, matches, timeouts, avg/max/min time) |
| `get_slow_patterns(n)`   | Top N slowest patterns by average execution time     |
| `get_problematic_patterns()` | Patterns with >10% timeout rate or consistently slow execution |
| `get_summary_stats()`    | Overall summary (total executions, avg time, timeout rate, match rate) |

`get_summary_stats`, `get_slow_patterns`, and `get_problematic_patterns` are coroutines in the async tree (`await monitor.get_summary_stats()`); `guard_core.sync` calls them as plain methods.

### Callback Registration

```python
monitor.register_anomaly_callback(lambda anomaly: print(anomaly))
```

Callbacks receive a sanitized anomaly dictionary with truncated pattern strings.
