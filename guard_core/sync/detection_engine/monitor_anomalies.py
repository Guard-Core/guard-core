import math
from datetime import datetime, timezone
from typing import Any

from guard_core.sync._utils.detection_scan import _redact_pattern_source

from .monitor_types import PatternStats, PerformanceMetric


def detect_timeout_anomaly(metric: PerformanceMetric) -> dict[str, Any] | None:
    if metric.timeout:
        return {
            "type": "timeout",
            "pattern": metric.pattern,
            "content_length": metric.content_length,
        }
    return None


def detect_slow_execution_anomaly(
    metric: PerformanceMetric, slow_pattern_threshold: float
) -> dict[str, Any] | None:
    if not metric.timeout and metric.execution_time > slow_pattern_threshold:
        return {
            "type": "slow_execution",
            "pattern": metric.pattern,
            "execution_time": metric.execution_time,
            "content_length": metric.content_length,
        }
    return None


def detect_statistical_anomaly(
    metric: PerformanceMetric,
    stats: PatternStats | None,
    min_samples_for_anomaly: int,
    anomaly_threshold: float,
) -> dict[str, Any] | None:
    if not stats or len(stats.recent_times) < min_samples_for_anomaly:
        return None

    recent_times = stats.recent_times
    sample_count = len(recent_times)
    if sample_count < 2:
        return None

    avg_time = math.fsum(recent_times) / sample_count
    if anomaly_threshold >= 0 and metric.execution_time <= avg_time:
        return None

    std_time = math.dist(recent_times, [avg_time] * sample_count) / math.sqrt(
        sample_count - 1
    )

    if std_time <= 0:
        return None

    z_score = (metric.execution_time - avg_time) / std_time
    if z_score > anomaly_threshold:
        return {
            "type": "statistical_anomaly",
            "pattern": metric.pattern,
            "execution_time": metric.execution_time,
            "z_score": z_score,
            "avg_time": avg_time,
            "std_time": std_time,
        }
    return None


def sanitize_anomaly_data(anomaly: dict[str, Any]) -> dict[str, Any]:
    safe_anomaly = anomaly.copy()
    if "pattern" in safe_anomaly:
        pattern = _redact_pattern_source(str(safe_anomaly["pattern"]))
        safe_anomaly["pattern"] = pattern[:50] + "..." if len(pattern) > 50 else pattern
        safe_anomaly["pattern_hash"] = str(hash(pattern))[:8]
    return safe_anomaly


def _anomaly_event_type(anomaly_type: str) -> str:
    from guard_core.sync.core.events.event_types import (
        EVENT_PATTERN_ANOMALY_SLOW_EXECUTION,
        EVENT_PATTERN_ANOMALY_STATISTICAL_ANOMALY,
        EVENT_PATTERN_ANOMALY_TIMEOUT,
    )

    return {
        "timeout": EVENT_PATTERN_ANOMALY_TIMEOUT,
        "slow_execution": EVENT_PATTERN_ANOMALY_SLOW_EXECUTION,
        "statistical_anomaly": EVENT_PATTERN_ANOMALY_STATISTICAL_ANOMALY,
    }[anomaly_type]


def build_anomaly_event_data(
    anomaly: dict[str, Any], correlation_id: str | None
) -> dict[str, Any]:
    event_type = _anomaly_event_type(anomaly["type"])
    safe_anomaly = anomaly.copy()
    if "pattern" in safe_anomaly:
        safe_anomaly["pattern"] = _redact_pattern_source(str(safe_anomaly["pattern"]))
    return {
        "timestamp": datetime.now(timezone.utc),
        "event_type": event_type,
        "ip_address": "system",
        "action_taken": "anomaly_detected",
        "reason": f"Pattern performance anomaly: {anomaly['type']}",
        "metadata": {
            "component": "PerformanceMonitor",
            "correlation_id": correlation_id,
            **safe_anomaly,
        },
    }


def build_callback_error_event_data(
    error: Exception,
    safe_anomaly: dict[str, Any],
    correlation_id: str | None,
) -> dict[str, Any]:
    from guard_core.sync.core.events.event_types import (
        EVENT_DETECTION_ENGINE_CALLBACK_ERROR,
    )

    return {
        "timestamp": datetime.now(timezone.utc),
        "event_type": EVENT_DETECTION_ENGINE_CALLBACK_ERROR,
        "ip_address": "system",
        "action_taken": "logged",
        "reason": f"Anomaly callback failed: {str(error)}",
        "metadata": {
            "component": "PerformanceMonitor",
            "correlation_id": correlation_id,
            "callback_error": str(error),
            "anomaly_type": safe_anomaly.get("type", "unknown"),
        },
    }
