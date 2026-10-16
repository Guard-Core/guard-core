import time
from collections import deque
from datetime import datetime, timezone
from functools import cache
from typing import Any, cast
from unittest.mock import MagicMock, patch

from guard_core.sync.detection_engine.monitor import (
    PatternStats,
    PerformanceMetric,
    PerformanceMonitor,
)
from guard_core.sync.detection_engine.monitor_anomalies import (
    detect_statistical_anomaly,
)

_REFERENCE_WORKLOAD_SECONDS = 0.1243


@cache
def _host_cpu_speed_factor() -> float:
    samples: list[float] = []
    for _ in range(3):
        start = time.process_time()
        total = 0
        for i in range(3_000_000):
            total += i * i
        samples.append(time.process_time() - start)
    return max(1.0, min(samples) / _REFERENCE_WORKLOAD_SECONDS)


def test_initialization() -> None:
    monitor = PerformanceMonitor()
    assert monitor.anomaly_threshold == 3.0
    assert monitor.slow_pattern_threshold == 0.1
    assert monitor.history_size == 1000
    assert monitor.max_tracked_patterns == 1000
    assert monitor.anomaly_emission_cooldown == 60.0
    assert monitor.min_samples_for_anomaly == 30
    assert len(monitor.pattern_stats) == 0
    assert len(monitor.recent_metrics) == 0
    assert len(monitor.anomaly_callbacks) == 0

    monitor = PerformanceMonitor(
        anomaly_threshold=5.0,
        slow_pattern_threshold=0.5,
        history_size=500,
        max_tracked_patterns=200,
        anomaly_emission_cooldown=30.0,
        min_samples_for_anomaly=50,
    )
    assert monitor.anomaly_threshold == 5.0
    assert monitor.slow_pattern_threshold == 0.5
    assert monitor.history_size == 500
    assert monitor.max_tracked_patterns == 200
    assert monitor.anomaly_emission_cooldown == 30.0
    assert monitor.min_samples_for_anomaly == 50


def test_initialization_bounds() -> None:
    monitor = PerformanceMonitor(
        anomaly_threshold=0.5,
        slow_pattern_threshold=0.001,
        history_size=50,
        max_tracked_patterns=50,
        anomaly_emission_cooldown=0.1,
        min_samples_for_anomaly=1,
    )
    assert monitor.anomaly_threshold == 1.0
    assert monitor.slow_pattern_threshold == 0.01
    assert monitor.history_size == 100
    assert monitor.max_tracked_patterns == 100
    assert monitor.anomaly_emission_cooldown == 1.0
    assert monitor.min_samples_for_anomaly == 10

    monitor = PerformanceMonitor(
        anomaly_threshold=20.0,
        slow_pattern_threshold=20.0,
        history_size=20000,
        max_tracked_patterns=10000,
        anomaly_emission_cooldown=10000.0,
        min_samples_for_anomaly=5000,
    )
    assert monitor.anomaly_threshold == 10.0
    assert monitor.slow_pattern_threshold == 10.0
    assert monitor.history_size == 10000
    assert monitor.max_tracked_patterns == 5000
    assert monitor.anomaly_emission_cooldown == 3600.0
    assert monitor.min_samples_for_anomaly == 1000


def test_record_metric_pattern_truncation() -> None:
    monitor = PerformanceMonitor()

    long_pattern = "a" * 150
    monitor.record_metric(
        pattern=long_pattern,
        execution_time=0.05,
        content_length=100,
        matched=True,
    )

    stored_pattern = list(monitor.pattern_stats.keys())[0]
    assert len(stored_pattern) == 114
    assert stored_pattern.endswith("...[truncated]")


def test_record_metric_max_patterns_limit() -> None:
    monitor = PerformanceMonitor(max_tracked_patterns=100)

    patterns = [f"pattern_{i:03d}" for i in range(100)]
    for pattern in patterns:
        monitor.record_metric(
            pattern=pattern,
            execution_time=0.01,
            content_length=100,
            matched=False,
        )

    assert len(monitor.pattern_stats) == 100

    monitor.record_metric(
        pattern="pattern_100",
        execution_time=0.01,
        content_length=100,
        matched=False,
    )

    assert len(monitor.pattern_stats) == 100

    assert "pattern_000" not in monitor.pattern_stats
    assert "pattern_100" in monitor.pattern_stats


def test_record_metric_with_timeout() -> None:
    monitor = PerformanceMonitor()

    monitor.record_metric(
        pattern="timeout_pattern",
        execution_time=1.0,
        content_length=1000,
        matched=False,
        timeout=True,
    )

    stats = monitor.pattern_stats["timeout_pattern"]
    assert stats.total_executions == 1
    assert stats.total_timeouts == 1
    assert stats.total_matches == 0
    assert len(stats.recent_times) == 0


def test_check_anomalies_timeout() -> None:
    monitor = PerformanceMonitor()

    anomalies_detected = []

    def anomaly_callback(anomaly: dict[str, Any]) -> None:
        anomalies_detected.append(anomaly)

    monitor.register_anomaly_callback(anomaly_callback)

    monitor.record_metric(
        pattern="timeout_test",
        execution_time=5.0,
        content_length=1000,
        matched=False,
        timeout=True,
    )

    assert len(anomalies_detected) == 1
    assert anomalies_detected[0]["type"] == "timeout"
    assert "timeout_test" in anomalies_detected[0]["pattern"]


def test_check_anomalies_statistical() -> None:
    monitor = PerformanceMonitor(anomaly_threshold=2.0)

    anomalies_detected = []

    def anomaly_callback(anomaly: dict[str, Any]) -> None:
        anomalies_detected.append(anomaly)

    monitor.register_anomaly_callback(anomaly_callback)

    pattern = "stat_pattern"
    for _ in range(35):
        monitor.record_metric(
            pattern=pattern,
            execution_time=0.01,
            content_length=100,
            matched=False,
        )

    anomalies_detected.clear()

    monitor.record_metric(
        pattern=pattern,
        execution_time=0.1,
        content_length=100,
        matched=False,
    )

    assert len(anomalies_detected) == 1
    assert anomalies_detected[0]["type"] == "statistical_anomaly"
    assert anomalies_detected[0]["z_score"] > 2.0


def test_statistical_anomaly_insufficient_data() -> None:
    monitor = PerformanceMonitor(anomaly_threshold=2.0)

    anomalies_detected = []

    def anomaly_callback(anomaly: dict[str, Any]) -> None:
        anomalies_detected.append(anomaly)  # pragma: no cover

    monitor.register_anomaly_callback(anomaly_callback)

    pattern = "insufficient_pattern"
    for _ in range(8):
        monitor.record_metric(
            pattern=pattern,
            execution_time=0.01,
            content_length=100,
            matched=False,
        )

    assert len(anomalies_detected) == 0


def test_statistical_anomaly_zero_std_dev() -> None:
    monitor = PerformanceMonitor(anomaly_threshold=2.0)

    anomalies_detected = []

    def anomaly_callback(anomaly: dict[str, Any]) -> None:
        anomalies_detected.append(anomaly)  # pragma: no cover

    monitor.register_anomaly_callback(anomaly_callback)

    pattern = "zero_std_pattern"
    for _ in range(35):
        monitor.record_metric(
            pattern=pattern,
            execution_time=0.01,
            content_length=100,
            matched=False,
        )

    assert len(anomalies_detected) == 0


def test_statistical_anomaly_zero_std_dev_above_average_metric() -> None:
    pattern = "zero_std_above_average_pattern"
    stats = PatternStats(pattern=pattern)
    stats.recent_times = deque([0.01] * 30, maxlen=100)
    metric = PerformanceMetric(
        pattern=pattern,
        execution_time=0.02,
        content_length=100,
        timestamp=datetime.now(timezone.utc),
        matched=False,
        timeout=False,
    )

    result = detect_statistical_anomaly(
        metric, stats, min_samples_for_anomaly=30, anomaly_threshold=2.0
    )

    assert result is None


def test_statistical_anomaly_negative_threshold_keeps_lower_tail() -> None:
    pattern = "negative_threshold_pattern"
    stats = PatternStats(pattern=pattern)
    stats.recent_times = deque([0.01, 0.02] * 15, maxlen=100)
    metric = PerformanceMetric(
        pattern=pattern,
        execution_time=0.0125,
        content_length=100,
        timestamp=datetime.now(timezone.utc),
        matched=False,
        timeout=False,
    )

    result = detect_statistical_anomaly(
        metric, stats, min_samples_for_anomaly=30, anomaly_threshold=-1.0
    )

    assert result is not None
    assert result["type"] == "statistical_anomaly"
    assert result["z_score"] > -1.0


def test_statistical_anomaly_single_data_point() -> None:
    monitor = PerformanceMonitor(anomaly_threshold=2.0)

    pattern = "single_point_pattern"
    stats = PatternStats(pattern=pattern)
    stats.recent_times.append(0.01)
    monitor.pattern_stats[pattern] = stats

    metric = PerformanceMetric(
        pattern=pattern,
        execution_time=0.5,
        content_length=100,
        timestamp=datetime.now(timezone.utc),
        matched=False,
        timeout=False,
    )

    result = monitor._detect_statistical_anomaly(metric)

    assert result is None


def test_statistical_anomaly_guard_via_monitor_clamp() -> None:
    monitor = PerformanceMonitor(anomaly_threshold=2.0, min_samples_for_anomaly=1)
    pattern = "one_sample_pattern"
    stats = PatternStats(pattern=pattern)
    stats.recent_times.append(0.01)
    monitor.pattern_stats[pattern] = stats

    metric = PerformanceMetric(
        pattern=pattern,
        execution_time=0.5,
        content_length=100,
        timestamp=datetime.now(timezone.utc),
        matched=False,
        timeout=False,
    )

    assert monitor._detect_statistical_anomaly(metric) is None


def test_statistical_anomaly_guard_direct_call() -> None:
    pattern = "one_sample_direct_pattern"
    stats = PatternStats(pattern=pattern)
    stats.recent_times.append(0.01)

    metric = PerformanceMetric(
        pattern=pattern,
        execution_time=0.5,
        content_length=100,
        timestamp=datetime.now(timezone.utc),
        matched=False,
        timeout=False,
    )

    result = detect_statistical_anomaly(
        metric, stats, min_samples_for_anomaly=1, anomaly_threshold=2.0
    )

    assert result is None


def test_statistical_anomaly_within_threshold() -> None:
    monitor = PerformanceMonitor(anomaly_threshold=3.0)

    pattern = "within_threshold_pattern"
    stats = PatternStats(pattern=pattern)

    times = [
        0.008,
        0.009,
        0.010,
        0.011,
        0.012,
        0.009,
        0.010,
        0.011,
        0.010,
        0.009,
        0.010,
        0.011,
        0.012,
        0.009,
        0.010,
        0.011,
        0.010,
        0.009,
        0.010,
        0.011,
        0.009,
        0.010,
        0.011,
        0.012,
        0.009,
        0.010,
        0.011,
        0.010,
        0.009,
        0.010,
        0.011,
    ]
    stats.recent_times = deque(times, maxlen=100)
    monitor.pattern_stats[pattern] = stats

    metric = PerformanceMetric(
        pattern=pattern,
        execution_time=0.012,
        content_length=100,
        timestamp=datetime.now(timezone.utc),
        matched=False,
        timeout=False,
    )

    result = monitor._detect_statistical_anomaly(metric)

    assert result is None


_RECORD_METRIC_CPU_BUDGET_SECONDS = 0.03


def test_record_metric_statistical_anomaly_cpu_budget() -> None:
    monitor = PerformanceMonitor(min_samples_for_anomaly=30)
    pattern = "cpu_budget_pattern"
    for i in range(100):
        monitor.record_metric(
            pattern=pattern,
            execution_time=0.001 + (i % 7) * 1e-6,
            content_length=100,
            matched=False,
        )

    samples: list[float] = []
    for _ in range(5):
        start = time.process_time()
        for i in range(300):
            monitor.record_metric(
                pattern=pattern,
                execution_time=0.001 + (i % 7) * 1e-6,
                content_length=100,
                matched=False,
            )
        samples.append(time.process_time() - start)

    budget_seconds = _RECORD_METRIC_CPU_BUDGET_SECONDS * _host_cpu_speed_factor()

    assert min(samples) < budget_seconds, (
        "record_metric's statistical-anomaly check regressed: min of 5 runs of "
        f"300 calls on a warm 100-sample window took {min(samples):.4f}s, "
        f"budget={budget_seconds:.4f}s (base {_RECORD_METRIC_CPU_BUDGET_SECONDS}s "
        "scaled by this host's _host_cpu_speed_factor(), 2.3x headroom over a "
        "~0.013s float baseline measured on the reference tree; the "
        "pre-fix statistics.mean/stdev implementation cost ~0.047s for the "
        "same 300 calls)"
    )


def test_check_anomalies_with_agent() -> None:
    monitor = PerformanceMonitor()
    agent_handler = MagicMock()
    agent_handler.send_event = MagicMock()

    monitor.record_metric(
        pattern="slow_pattern",
        execution_time=0.5,
        content_length=100,
        matched=False,
        agent_handler=agent_handler,
        correlation_id="test-123",
    )

    agent_handler.send_event.assert_called_once()
    event = agent_handler.send_event.call_args[0][0]
    assert event.event_type == "pattern_anomaly_slow_execution"
    assert event.action_taken == "anomaly_detected"
    assert event.metadata["correlation_id"] == "test-123"


def test_check_anomalies_agent_error() -> None:
    monitor = PerformanceMonitor()
    agent_handler = MagicMock()
    agent_handler.send_event = MagicMock(side_effect=Exception("Agent error"))

    monitor.record_metric(
        pattern="slow_pattern",
        execution_time=0.5,
        content_length=100,
        matched=False,
        agent_handler=agent_handler,
    )


def test_anomaly_callback_error() -> None:
    monitor = PerformanceMonitor()
    agent_handler = MagicMock()
    agent_handler.send_event = MagicMock()

    def failing_callback(anomaly: dict[str, Any]) -> None:
        raise Exception("Callback error")

    monitor.register_anomaly_callback(failing_callback)

    monitor.record_metric(
        pattern="slow_pattern",
        execution_time=0.5,
        content_length=100,
        matched=False,
        agent_handler=agent_handler,
        correlation_id="test-456",
    )

    assert agent_handler.send_event.call_count == 2
    error_event = agent_handler.send_event.call_args_list[1][0][0]
    assert error_event.event_type == "detection_engine_callback_error"
    assert "Callback error" in error_event.reason


def test_anomaly_callback_error_agent_failure() -> None:
    monitor = PerformanceMonitor()
    agent_handler = MagicMock()
    agent_handler.send_event = MagicMock(side_effect=Exception("Agent error"))

    def failing_callback(anomaly: dict[str, Any]) -> None:
        raise Exception("Callback error")

    monitor.register_anomaly_callback(failing_callback)

    monitor.record_metric(
        pattern="slow_pattern",
        execution_time=0.5,
        content_length=100,
        matched=False,
        agent_handler=agent_handler,
    )


def test_get_pattern_report_not_found() -> None:
    monitor = PerformanceMonitor()

    report = monitor.get_pattern_report("non_existent")
    assert report is None


def test_get_pattern_report_truncation() -> None:
    monitor = PerformanceMonitor()

    pattern = "test_pattern"
    stats = PatternStats(
        pattern=pattern,
        total_executions=10,
        total_matches=5,
        total_timeouts=1,
        avg_execution_time=0.05,
        max_execution_time=0.1,
        min_execution_time=0.01,
    )
    monitor.pattern_stats[pattern] = stats

    report = monitor.get_pattern_report(pattern)
    assert report is not None
    assert report["pattern"] == pattern
    assert report["total_executions"] == 10
    assert report["match_rate"] == 0.5
    assert report["timeout_rate"] == 0.1


def test_get_pattern_report_long_pattern_truncation() -> None:
    monitor = PerformanceMonitor()

    stored_pattern = "a" * 100 + "...[truncated]"
    stats = PatternStats(
        pattern=stored_pattern,
        total_executions=10,
        total_matches=5,
        total_timeouts=1,
        avg_execution_time=0.05,
        max_execution_time=0.1,
        min_execution_time=0.01,
    )
    monitor.pattern_stats[stored_pattern] = stats

    long_original_pattern = "a" * 150
    report = monitor.get_pattern_report(long_original_pattern)

    assert report is not None
    assert report["total_executions"] == 10


def test_get_problematic_patterns_empty_stats() -> None:
    monitor = PerformanceMonitor()

    stats = PatternStats(pattern="empty_pattern")
    monitor.pattern_stats["empty_pattern"] = stats

    problematic = monitor.get_problematic_patterns()
    assert len(problematic) == 0


def test_get_problematic_patterns_high_timeout() -> None:
    monitor = PerformanceMonitor()

    for i in range(3):
        pattern = f"pattern_{i}"
        timeout_rate = 0.2 if i == 1 else 0.05

        for j in range(10):
            monitor.record_metric(
                pattern=pattern,
                execution_time=0.05,
                content_length=100,
                matched=False,
                timeout=(j < timeout_rate * 10),
            )

    problematic = monitor.get_problematic_patterns()

    assert len(problematic) == 1
    assert "pattern_1" in problematic[0]["pattern"]
    assert problematic[0]["issue"] == "high_timeout_rate"


def test_get_problematic_patterns_slow() -> None:
    monitor = PerformanceMonitor(slow_pattern_threshold=0.1)

    patterns = [
        ("fast_pattern", 0.05),
        ("slow_pattern", 0.2),
        ("very_slow_pattern", 0.5),
    ]

    for pattern, exec_time in patterns:
        for _ in range(5):
            monitor.record_metric(
                pattern=pattern,
                execution_time=exec_time,
                content_length=100,
                matched=False,
            )

    problematic = monitor.get_problematic_patterns()

    assert len(problematic) == 2
    problematic_patterns = [p["pattern"] for p in problematic]
    assert any("slow_pattern" in p for p in problematic_patterns)
    assert any("very_slow_pattern" in p for p in problematic_patterns)
    assert all(p["issue"] == "consistently_slow" for p in problematic)


def test_get_summary_stats_empty() -> None:
    monitor = PerformanceMonitor()

    stats = monitor.get_summary_stats()
    assert stats["total_executions"] == 0
    assert stats["avg_execution_time"] == 0.0
    assert stats["timeout_rate"] == 0.0
    assert stats["match_rate"] == 0.0


def test_get_summary_stats_with_data() -> None:
    monitor = PerformanceMonitor()

    monitor.record_metric("p1", 0.01, 100, True, False)
    monitor.record_metric("p2", 0.02, 200, False, False)
    monitor.record_metric("p3", 1.0, 300, False, True)
    monitor.record_metric("p4", 0.03, 400, True, False)

    stats = monitor.get_summary_stats()
    assert stats["total_executions"] == 4
    assert stats["match_rate"] == 0.5
    assert stats["timeout_rate"] == 0.25
    assert stats["total_patterns"] == 4


def test_register_anomaly_callback() -> None:
    monitor = PerformanceMonitor()

    def callback(anomaly: dict[str, Any]) -> None:
        pass  # pragma: no cover

    monitor.register_anomaly_callback(callback)
    assert len(monitor.anomaly_callbacks) == 1
    assert monitor.anomaly_callbacks[0] == callback


def test_clear_stats() -> None:
    monitor = PerformanceMonitor()

    monitor.record_metric("pattern1", 0.01, 100, True)
    monitor.record_metric("pattern2", 0.02, 200, False)

    assert len(monitor.pattern_stats) == 2
    assert len(monitor.recent_metrics) == 2

    monitor.clear_stats()

    assert len(monitor.pattern_stats) == 0
    assert len(monitor.recent_metrics) == 0


def test_remove_pattern_stats() -> None:
    monitor = PerformanceMonitor()

    monitor.record_metric("pattern1", 0.01, 100, True)
    monitor.record_metric("pattern2", 0.02, 200, False)

    assert len(monitor.pattern_stats) == 2

    monitor.remove_pattern_stats("pattern1")

    assert len(monitor.pattern_stats) == 1
    assert "pattern1" not in monitor.pattern_stats
    assert "pattern2" in monitor.pattern_stats

    monitor.remove_pattern_stats("non_existent")


def test_get_slow_patterns() -> None:
    monitor = PerformanceMonitor()

    patterns = [
        ("very_slow", 0.5),
        ("slow", 0.2),
        ("medium", 0.1),
        ("fast", 0.01),
        ("very_fast", 0.001),
    ]

    for pattern, exec_time in patterns:
        for _ in range(3):
            monitor.record_metric(
                pattern=pattern,
                execution_time=exec_time,
                content_length=100,
                matched=False,
            )

    slow_patterns = monitor.get_slow_patterns(limit=3)

    assert len(slow_patterns) == 3
    assert "very_slow" in slow_patterns[0]["pattern"]
    assert "slow" in slow_patterns[1]["pattern"]
    assert "medium" in slow_patterns[2]["pattern"]


def test_metric_validation() -> None:
    monitor = PerformanceMonitor()

    monitor.record_metric(
        pattern="test",
        execution_time=-1.0,
        content_length=-100,
        matched=False,
    )

    metric = monitor.recent_metrics[0]
    assert metric.execution_time == 0.0
    assert metric.content_length == 0


def test_pattern_stats_dataclass() -> None:
    stats = PatternStats(pattern="test_pattern")

    assert stats.pattern == "test_pattern"
    assert stats.total_executions == 0
    assert stats.total_matches == 0
    assert stats.total_timeouts == 0
    assert stats.avg_execution_time == 0.0
    assert stats.max_execution_time == 0.0
    assert stats.min_execution_time == float("inf")
    assert isinstance(stats.recent_times, deque)
    assert stats.recent_times.maxlen == 100
    assert stats.last_anomaly_emitted_at is None


def test_performance_metric_dataclass() -> None:
    now = datetime.now(timezone.utc)
    metric = PerformanceMetric(
        pattern="test_pattern",
        execution_time=0.05,
        content_length=1000,
        timestamp=now,
        matched=True,
        timeout=False,
    )

    assert metric.pattern == "test_pattern"
    assert metric.execution_time == 0.05
    assert metric.content_length == 1000
    assert metric.timestamp == now
    assert metric.matched is True
    assert metric.timeout is False


def test_concurrent_access() -> None:
    monitor = PerformanceMonitor()

    def record_metrics(pattern: str, count: int) -> None:
        for i in range(count):
            monitor.record_metric(
                pattern=f"{pattern}_{i % 3}",
                execution_time=0.01 * (i % 5 + 1),
                content_length=100 * (i % 3 + 1),
                matched=i % 2 == 0,
            )

    record_metrics("task1", 10)
    record_metrics("task2", 10)
    record_metrics("task3", 10)

    assert len(monitor.recent_metrics) == 30
    total_patterns = len(monitor.pattern_stats)
    assert total_patterns > 0

    for _, stats in monitor.pattern_stats.items():
        assert stats.total_executions > 0
        assert stats.max_execution_time >= stats.min_execution_time
        if stats.recent_times:
            assert stats.avg_execution_time > 0


def test_record_metric_timeout_skips_recent_times_update() -> None:
    monitor = PerformanceMonitor()
    monitor.record_metric(
        pattern="pat1",
        execution_time=5.0,
        content_length=10,
        matched=False,
        timeout=True,
    )
    assert monitor.pattern_stats["pat1"].total_timeouts == 1
    assert len(monitor.pattern_stats["pat1"].recent_times) == 0


def test_record_metric_with_zero_maxlen_recent_times_skips_avg_update() -> None:
    monitor = PerformanceMonitor()
    stats = PatternStats(pattern="zm")
    stats.recent_times = deque(maxlen=0)
    monitor.pattern_stats["zm"] = stats
    monitor.record_metric(
        pattern="zm",
        execution_time=0.1,
        content_length=10,
        matched=False,
        timeout=False,
    )
    assert len(monitor.pattern_stats["zm"].recent_times) == 0


def test_sanitize_anomaly_data_without_pattern_key() -> None:
    monitor = PerformanceMonitor()
    safe = monitor._sanitize_anomaly_data({"type": "timeout"})
    assert "pattern" not in safe
    assert "pattern_hash" not in safe


def test_notify_callbacks_exception_without_agent_handler() -> None:
    monitor = PerformanceMonitor()
    captured: list[Exception] = []

    def bad_callback(anomaly: dict[str, Any]) -> None:
        captured.append(RuntimeError("boom"))
        raise RuntimeError("boom")

    monitor.anomaly_callbacks.append(bad_callback)
    monitor._notify_callbacks(
        {"pattern": "x", "type": "t"}, agent_handler=None, correlation_id=None
    )
    assert len(captured) == 1


def test_notify_callbacks_skips_sanitizing_without_callbacks() -> None:
    monitor = PerformanceMonitor()
    with patch.object(monitor, "_sanitize_anomaly_data") as sanitize:
        monitor._notify_callbacks(
            {"pattern": "x", "type": "t"}, agent_handler=None, correlation_id=None
        )
    sanitize.assert_not_called()


def test_get_slow_patterns_skips_missing_report() -> None:
    monitor = PerformanceMonitor()
    stats = PatternStats(pattern="gone")
    stats.avg_execution_time = 1.0
    stats.recent_times = deque([1.0], maxlen=10)
    stats.total_executions = 1
    monitor.pattern_stats["gone"] = stats

    real_report = monitor.get_pattern_report

    def returns_none(pattern: str) -> dict[str, Any] | None:
        return None

    cast(Any, monitor).get_pattern_report = returns_none
    try:
        reports = monitor.get_slow_patterns(limit=5)
    finally:
        cast(Any, monitor).get_pattern_report = real_report
    assert reports == []


def test_get_problematic_patterns_skips_when_high_timeout_report_is_none() -> None:
    monitor = PerformanceMonitor()
    stats = PatternStats(pattern="ghost")
    stats.total_executions = 10
    stats.total_timeouts = 5
    monitor.pattern_stats["ghost"] = stats

    real_report = monitor.get_pattern_report
    cast(Any, monitor).get_pattern_report = lambda _p: None
    try:
        result = monitor.get_problematic_patterns()
    finally:
        cast(Any, monitor).get_pattern_report = real_report
    assert result == []


def test_get_problematic_patterns_skips_when_slow_report_is_none() -> None:
    monitor = PerformanceMonitor(slow_pattern_threshold=0.01)
    stats = PatternStats(pattern="ghost2")
    stats.total_executions = 10
    stats.total_timeouts = 0
    stats.avg_execution_time = 1.0
    monitor.pattern_stats["ghost2"] = stats

    real_report = monitor.get_pattern_report
    cast(Any, monitor).get_pattern_report = lambda _p: None
    try:
        result = monitor.get_problematic_patterns()
    finally:
        cast(Any, monitor).get_pattern_report = real_report
    assert result == []


def test_remove_pattern_stats_noop_for_unknown_pattern() -> None:
    monitor = PerformanceMonitor()
    # pattern not in stats, the `if pattern in self.pattern_stats:` False branch.
    monitor.remove_pattern_stats("nonexistent")
    assert "nonexistent" not in monitor.pattern_stats


def test_statistical_anomaly_ignores_faster_than_average_execution() -> None:
    monitor = PerformanceMonitor(anomaly_threshold=2.0)

    pattern = "fast_regression_pattern"
    stats = PatternStats(pattern=pattern)
    stats.recent_times = deque([0.1] * 30 + [0.001], maxlen=100)
    monitor.pattern_stats[pattern] = stats

    metric = PerformanceMetric(
        pattern=pattern,
        execution_time=0.001,
        content_length=100,
        timestamp=datetime.now(timezone.utc),
        matched=False,
        timeout=False,
    )

    result = monitor._detect_statistical_anomaly(metric)

    assert result is None


def test_statistical_anomaly_detects_slower_than_average_execution() -> None:
    monitor = PerformanceMonitor(anomaly_threshold=2.0)

    pattern = "slow_regression_pattern"
    stats = PatternStats(pattern=pattern)
    stats.recent_times = deque([0.001] * 30 + [0.1], maxlen=100)
    monitor.pattern_stats[pattern] = stats

    metric = PerformanceMetric(
        pattern=pattern,
        execution_time=0.1,
        content_length=100,
        timestamp=datetime.now(timezone.utc),
        matched=False,
        timeout=False,
    )

    result = monitor._detect_statistical_anomaly(metric)

    assert result is not None
    assert result["type"] == "statistical_anomaly"
    assert result["z_score"] > 2.0


def test_check_anomalies_statistical_ignores_fast_execution() -> None:
    monitor = PerformanceMonitor(anomaly_threshold=2.0)

    anomalies_detected = []

    def anomaly_callback(anomaly: dict[str, Any]) -> None:
        anomalies_detected.append(anomaly)

    monitor.register_anomaly_callback(anomaly_callback)

    pattern = "fast_stat_pattern"
    for _ in range(35):
        monitor.record_metric(
            pattern=pattern,
            execution_time=0.01,
            content_length=100,
            matched=False,
        )

    anomalies_detected.clear()

    monitor.record_metric(
        pattern=pattern,
        execution_time=0.001,
        content_length=100,
        matched=False,
    )

    assert len(anomalies_detected) == 0


def test_cooldown_suppresses_burst_for_same_pattern() -> None:
    monitor = PerformanceMonitor(
        slow_pattern_threshold=0.05, anomaly_emission_cooldown=60.0
    )
    agent_handler = MagicMock()
    agent_handler.send_event = MagicMock()

    with patch("time.monotonic", return_value=1000.0):
        for _ in range(5):
            monitor.record_metric(
                pattern="stall_pattern",
                execution_time=0.5,
                content_length=100,
                matched=False,
                agent_handler=agent_handler,
            )

    assert agent_handler.send_event.call_count == 1


def test_cooldown_does_not_suppress_a_different_pattern() -> None:
    monitor = PerformanceMonitor(
        slow_pattern_threshold=0.05, anomaly_emission_cooldown=60.0
    )
    agent_handler = MagicMock()
    agent_handler.send_event = MagicMock()

    with patch("time.monotonic", return_value=2000.0):
        monitor.record_metric(
            pattern="pattern_a",
            execution_time=0.5,
            content_length=100,
            matched=False,
            agent_handler=agent_handler,
        )
        monitor.record_metric(
            pattern="pattern_b",
            execution_time=0.5,
            content_length=100,
            matched=False,
            agent_handler=agent_handler,
        )

    assert agent_handler.send_event.call_count == 2


def test_cooldown_allows_emission_again_after_window_elapses() -> None:
    monitor = PerformanceMonitor(
        slow_pattern_threshold=0.05, anomaly_emission_cooldown=60.0
    )
    agent_handler = MagicMock()
    agent_handler.send_event = MagicMock()

    clock = {"now": 3000.0}
    with patch("time.monotonic", side_effect=lambda: clock["now"]):
        monitor.record_metric(
            pattern="stall_pattern",
            execution_time=0.5,
            content_length=100,
            matched=False,
            agent_handler=agent_handler,
        )

        clock["now"] += 10.0
        monitor.record_metric(
            pattern="stall_pattern",
            execution_time=0.5,
            content_length=100,
            matched=False,
            agent_handler=agent_handler,
        )
        assert agent_handler.send_event.call_count == 1

        clock["now"] += 60.0
        monitor.record_metric(
            pattern="stall_pattern",
            execution_time=0.5,
            content_length=100,
            matched=False,
            agent_handler=agent_handler,
        )

    assert agent_handler.send_event.call_count == 2


def test_cooldown_state_does_not_survive_max_tracked_patterns_eviction() -> None:
    monitor = PerformanceMonitor(
        slow_pattern_threshold=0.05,
        anomaly_emission_cooldown=60.0,
        max_tracked_patterns=100,
    )
    agent_handler = MagicMock()
    agent_handler.send_event = MagicMock()

    with patch("time.monotonic", return_value=5000.0):
        monitor.record_metric(
            pattern="evictee",
            execution_time=0.5,
            content_length=100,
            matched=False,
            agent_handler=agent_handler,
        )
        assert agent_handler.send_event.call_count == 1

        for i in range(100):
            monitor.record_metric(
                pattern=f"filler_{i:03d}",
                execution_time=0.01,
                content_length=100,
                matched=False,
            )

        assert "evictee" not in monitor.pattern_stats

        monitor.record_metric(
            pattern="evictee",
            execution_time=0.5,
            content_length=100,
            matched=False,
            agent_handler=agent_handler,
        )

    assert agent_handler.send_event.call_count == 2


def test_reserve_anomaly_emission_allows_untracked_pattern() -> None:
    monitor = PerformanceMonitor()
    assert monitor._reserve_anomaly_emission("never_recorded") is True


def test_min_samples_for_anomaly_suppresses_below_floor() -> None:
    monitor = PerformanceMonitor(
        anomaly_threshold=2.0,
        slow_pattern_threshold=1.0,
        min_samples_for_anomaly=20,
    )

    anomalies_detected = []

    def anomaly_callback(anomaly: dict[str, Any]) -> None:
        anomalies_detected.append(anomaly)  # pragma: no cover

    monitor.register_anomaly_callback(anomaly_callback)

    pattern = "floor_pattern"
    for _ in range(18):
        monitor.record_metric(
            pattern=pattern,
            execution_time=0.01,
            content_length=100,
            matched=False,
        )

    monitor.record_metric(
        pattern=pattern,
        execution_time=0.5,
        content_length=100,
        matched=False,
    )

    assert len(anomalies_detected) == 0


def test_min_samples_for_anomaly_fires_above_floor() -> None:
    monitor = PerformanceMonitor(anomaly_threshold=2.0, min_samples_for_anomaly=20)

    anomalies_detected = []

    def anomaly_callback(anomaly: dict[str, Any]) -> None:
        anomalies_detected.append(anomaly)

    monitor.register_anomaly_callback(anomaly_callback)

    pattern = "above_floor_pattern"
    for _ in range(20):
        monitor.record_metric(
            pattern=pattern,
            execution_time=0.01,
            content_length=100,
            matched=False,
        )

    anomalies_detected.clear()

    monitor.record_metric(
        pattern=pattern,
        execution_time=0.5,
        content_length=100,
        matched=False,
    )

    statistical = [a for a in anomalies_detected if a["type"] == "statistical_anomaly"]
    assert len(statistical) == 1
    assert statistical[0]["z_score"] > 2.0


def test_min_samples_for_anomaly_above_100_still_fires() -> None:
    monitor = PerformanceMonitor(anomaly_threshold=2.0, min_samples_for_anomaly=150)
    assert monitor.min_samples_for_anomaly == 150

    anomalies_detected = []

    def anomaly_callback(anomaly: dict[str, Any]) -> None:
        anomalies_detected.append(anomaly)

    monitor.register_anomaly_callback(anomaly_callback)

    pattern = "above_100_floor_pattern"
    for _ in range(150):
        monitor.record_metric(
            pattern=pattern,
            execution_time=0.01,
            content_length=100,
            matched=False,
        )

    assert monitor.pattern_stats[pattern].recent_times.maxlen == 150

    anomalies_detected.clear()

    monitor.record_metric(
        pattern=pattern,
        execution_time=0.5,
        content_length=100,
        matched=False,
    )

    statistical = [a for a in anomalies_detected if a["type"] == "statistical_anomaly"]
    assert len(statistical) == 1
    assert statistical[0]["z_score"] > 2.0


def test_recent_metrics_deque_uses_clamped_history_size() -> None:
    monitor = PerformanceMonitor(history_size=50)
    assert monitor.history_size == 100
    assert monitor.recent_metrics.maxlen == 100


def test_cooldown_is_configurable_via_constructor() -> None:
    monitor = PerformanceMonitor(
        slow_pattern_threshold=0.05, anomaly_emission_cooldown=5.0
    )
    agent_handler = MagicMock()
    agent_handler.send_event = MagicMock()

    clock = {"now": 1000.0}
    with patch("time.monotonic", side_effect=lambda: clock["now"]):
        monitor.record_metric(
            pattern="stall_pattern",
            execution_time=0.5,
            content_length=100,
            matched=False,
            agent_handler=agent_handler,
        )
        assert agent_handler.send_event.call_count == 1

        clock["now"] += 2.0
        monitor.record_metric(
            pattern="stall_pattern",
            execution_time=0.5,
            content_length=100,
            matched=False,
            agent_handler=agent_handler,
        )
        assert agent_handler.send_event.call_count == 1

        clock["now"] += 5.0
        monitor.record_metric(
            pattern="stall_pattern",
            execution_time=0.5,
            content_length=100,
            matched=False,
            agent_handler=agent_handler,
        )

    assert agent_handler.send_event.call_count == 2
