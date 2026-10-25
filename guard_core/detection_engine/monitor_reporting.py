from collections.abc import Callable, Iterable
from statistics import mean
from typing import Any

from guard_core._utils.detection_scan import _redact_pattern_source

from .monitor_types import PatternStats, PerformanceMetric


def build_pattern_report(
    pattern: str, stats: PatternStats, redaction_names: Any = None
) -> dict[str, Any]:
    redacted_pattern = _redact_pattern_source(pattern, redaction_names)
    safe_pattern = (
        redacted_pattern[:50] + "..."
        if len(redacted_pattern) > 50
        else redacted_pattern
    )

    return {
        "pattern": safe_pattern,
        "pattern_hash": str(hash(redacted_pattern))[:8],
        "total_executions": stats.total_executions,
        "total_matches": stats.total_matches,
        "total_timeouts": stats.total_timeouts,
        "match_rate": stats.total_matches / max(stats.total_executions, 1),
        "timeout_rate": stats.total_timeouts / max(stats.total_executions, 1),
        "avg_execution_time": round(stats.avg_execution_time, 4),
        "max_execution_time": round(stats.max_execution_time, 4),
        "min_execution_time": round(
            stats.min_execution_time
            if stats.min_execution_time != float("inf")
            else 0.0,
            4,
        ),
    }


def collect_slow_patterns(
    pattern_stats: dict[str, PatternStats],
    report_fn: Callable[[str], dict[str, Any] | None],
    limit: int,
) -> list[dict[str, Any]]:
    patterns_with_times = [
        (stats.avg_execution_time, pattern)
        for pattern, stats in pattern_stats.items()
        if stats.recent_times
    ]

    patterns_with_times.sort(reverse=True)

    reports = []
    for _, pattern in patterns_with_times[:limit]:
        report = report_fn(pattern)
        if report is not None:
            reports.append(report)
    return reports


def collect_problematic_patterns(
    pattern_stats: dict[str, PatternStats],
    report_fn: Callable[[str], dict[str, Any] | None],
    slow_pattern_threshold: float,
) -> list[dict[str, Any]]:
    problematic = []

    for pattern, stats in pattern_stats.items():
        if stats.total_executions == 0:
            continue

        timeout_rate = stats.total_timeouts / stats.total_executions

        if timeout_rate > 0.1:
            report = report_fn(pattern)
            if report:
                report["issue"] = "high_timeout_rate"
                problematic.append(report)

        elif stats.avg_execution_time > slow_pattern_threshold:
            report = report_fn(pattern)
            if report:
                report["issue"] = "consistently_slow"
                problematic.append(report)

    return problematic


def empty_summary() -> dict[str, Any]:
    return {
        "total_executions": 0,
        "avg_execution_time": 0.0,
        "timeout_rate": 0.0,
        "match_rate": 0.0,
    }


def extract_metric_components(
    recent_metrics: Iterable[PerformanceMetric],
) -> tuple[list[float], int, int]:
    recent_times = [m.execution_time for m in recent_metrics if not m.timeout]
    timeouts = sum(1 for m in recent_metrics if m.timeout)
    matches = sum(1 for m in recent_metrics if m.matched)
    return recent_times, timeouts, matches


def build_summary_dict(
    total_metrics: int,
    total_patterns: int,
    recent_times: list[float],
    timeouts: int,
    matches: int,
) -> dict[str, Any]:
    return {
        "total_executions": total_metrics,
        "avg_execution_time": mean(recent_times) if recent_times else 0.0,
        "max_execution_time": max(recent_times) if recent_times else 0.0,
        "min_execution_time": min(recent_times) if recent_times else 0.0,
        "timeout_rate": timeouts / total_metrics,
        "match_rate": matches / total_metrics,
        "total_patterns": total_patterns,
    }
