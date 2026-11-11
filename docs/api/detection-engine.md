---

title: Detection Engine
description: API reference for guard-core's detection engine components including PatternCompiler, ContentPreprocessor, SemanticAnalyzer, and PerformanceMonitor
keywords: detection engine, pattern compiler, preprocessor, semantic analyzer, performance monitor, guard-core
---

Detection Engine
================

The `detection_engine` module provides the core components for threat detection: pattern compilation with timeout protection, content preprocessing, semantic analysis, and performance monitoring.

___

PatternCompiler
---------------

```python
class PatternCompiler:
    MAX_CACHE_SIZE = 1000

    def __init__(
        self,
        default_timeout: float = 5.0,
        max_cache_size: int = 1000,
    ):
        """
        Compile and cache regex patterns with timeout protection.
        max_cache_size is clamped to 5000.
        """

    async def compile_pattern(
        self,
        pattern: str,
        flags: int = re.IGNORECASE | re.MULTILINE,
    ) -> re.Pattern:
        """
        Compile a pattern with LRU caching.
        """

    def create_safe_matcher(self, pattern: str) -> Callable[[str], re.Match | None]:
        """
        Return a callable that matches content against the pattern
        with timeout protection.
        """

    async def clear_cache(self) -> None:
        """
        Clear the compiled pattern cache.
        """
```

___

ContentPreprocessor
-------------------

```python
class ContentPreprocessor:
    def __init__(
        self,
        max_content_length: int = 10000,
        preserve_attack_patterns: bool = True,
        agent_handler: AgentHandlerProtocol | None = None,
        correlation_id: str | None = None,
        max_full_scan_bytes: int | None = None,
    ):
        """
        Preprocess request content before pattern matching.
        Truncates to max_content_length while optionally preserving
        sections that contain attack indicators.
        """

    async def preprocess(self, content: str) -> str:
        """
        Normalize and truncate content for detection.
        """
```

___

SemanticAnalyzer
----------------

```python
class SemanticAnalyzer:
    def __init__(self) -> None:
        """
        Analyze content semantics to detect obfuscated attacks
        that evade regex patterns.
        """

    def analyze(self, content: str) -> SemanticAnalysis:
        """
        Perform semantic analysis. Returns a dict with attack_probabilities
        and other analysis metadata.
        """

    def get_threat_score(self, analysis_results: SemanticAnalysis) -> float:
        """
        Calculate an overall threat score from analysis results.
        """
```

___

PerformanceMonitor
------------------

```python
class PerformanceMonitor:
    def __init__(
        self,
        anomaly_threshold: float = 3.0,
        slow_pattern_threshold: float = 0.1,
        history_size: int = 1000,
        max_tracked_patterns: int = 1000,
        anomaly_emission_cooldown: float = 60.0,
    ):
        """
        Track pattern execution performance and detect anomalies.
        anomaly_threshold is clamped to 1.0-10.0.
        A statistical anomaly only fires when execution is slower than
        the pattern's rolling average, never when it is faster.
        anomaly_emission_cooldown (clamped to 1.0-3600.0 seconds) rate-limits,
        per pattern, how often a tripped anomaly is sent as an event to the
        agent handler; registered callbacks still run on every trip.
        """

    async def record_metric(
        self,
        pattern: str,
        execution_time: float,
        content_length: int,
        matched: bool,
        timeout: bool = False,
        agent_handler: AgentHandlerProtocol | None = None,
        correlation_id: str | None = None,
    ) -> None:
        """
        Record a single pattern execution metric.
        """

    async def get_summary_stats(self) -> PerformanceSummary:
        """
        Return aggregate performance statistics.
        """

    async def get_slow_patterns(self, limit: int = 10) -> list[PatternReport]:
        """
        Return the reports of up to ``limit`` patterns, slowest average
        execution time first. Only patterns with recorded execution times
        are ranked; there is no threshold.
        """

    async def get_problematic_patterns(self) -> list[PatternReport]:
        """
        Return patterns with high timeout rates or anomalous execution times.
        """

    async def remove_pattern_stats(self, pattern: str) -> None:
        """
        Remove tracked statistics for a pattern.
        """
```
