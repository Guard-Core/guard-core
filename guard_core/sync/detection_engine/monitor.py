import logging
import math
import threading
import time
from collections import deque
from collections.abc import Callable
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from guard_core.sync._utils.pattern_source_redaction import _SensitiveNameSets

from .monitor_anomalies import (
    build_anomaly_event_data,
    build_callback_error_event_data,
    detect_slow_execution_anomaly,
    detect_statistical_anomaly,
    detect_timeout_anomaly,
    sanitize_anomaly_data,
)
from .monitor_reporting import (
    PatternReport,
    PerformanceSummary,
    build_pattern_report,
    build_summary_dict,
    collect_problematic_patterns,
    collect_slow_patterns,
    empty_summary,
    extract_metric_components,
)
from .monitor_types import DEFAULT_RECENT_TIMES_WINDOW, PatternStats, PerformanceMetric

if TYPE_CHECKING:
    from guard_core.sync.protocols.agent_protocol import SyncAgentHandlerProtocol

AnomalyCallback = Callable[[dict[str, object]], object]

_DEFAULT_RECENT_TIMES_WINDOW = DEFAULT_RECENT_TIMES_WINDOW

__all__ = [
    "PatternStats",
    "PerformanceMetric",
    "PerformanceMonitor",
    "DEFAULT_RECENT_TIMES_WINDOW",
    "_DEFAULT_RECENT_TIMES_WINDOW",
]

logger = logging.getLogger("guard_core.sync.detection_engine.monitor")


class PerformanceMonitor:
    def __init__(
        self,
        anomaly_threshold: float = 3.0,
        slow_pattern_threshold: float = 0.1,
        history_size: int = 1000,
        max_tracked_patterns: int = 1000,
        anomaly_emission_cooldown: float = 60.0,
        min_samples_for_anomaly: int = 30,
        redaction_names: _SensitiveNameSets | None = None,
    ):
        self.redaction_names = redaction_names
        self.anomaly_threshold = max(1.0, min(10.0, float(anomaly_threshold)))
        self.slow_pattern_threshold = max(
            0.01, min(10.0, float(slow_pattern_threshold))
        )
        self.history_size = max(100, min(10000, int(history_size)))
        self.max_tracked_patterns = max(100, min(5000, int(max_tracked_patterns)))
        self.anomaly_emission_cooldown = max(
            1.0, min(3600.0, float(anomaly_emission_cooldown))
        )
        self.min_samples_for_anomaly = max(10, min(1000, int(min_samples_for_anomaly)))
        self._recent_times_maxlen = max(
            self.min_samples_for_anomaly, DEFAULT_RECENT_TIMES_WINDOW
        )

        self.pattern_stats: dict[str, PatternStats] = {}
        self.recent_metrics: deque[PerformanceMetric] = deque(maxlen=self.history_size)
        self.anomaly_callbacks: list[AnomalyCallback] = []
        self._lock = threading.Lock()

    def _track_metric(
        self,
        pattern: str,
        execution_time: float,
        content_length: int,
        matched: bool,
        timeout: bool,
    ) -> tuple[PerformanceMetric, dict[str, object] | None]:
        MAX_PATTERN_LENGTH = 100
        if len(pattern) > MAX_PATTERN_LENGTH:
            pattern = pattern[:MAX_PATTERN_LENGTH] + "...[truncated]"

        execution_time = max(0.0, float(execution_time))
        content_length = max(0, int(content_length))

        metric = PerformanceMetric(
            pattern=pattern,
            execution_time=execution_time,
            content_length=content_length,
            timestamp=datetime.now(timezone.utc),
            matched=matched,
            timeout=timeout,
        )

        self.recent_metrics.append(metric)

        if pattern not in self.pattern_stats:
            if len(self.pattern_stats) >= self.max_tracked_patterns:
                oldest_pattern = next(iter(self.pattern_stats))
                del self.pattern_stats[oldest_pattern]
            self.pattern_stats[pattern] = PatternStats(
                pattern=pattern,
                recent_times=deque(maxlen=self._recent_times_maxlen),
            )

        stats = self.pattern_stats[pattern]
        stats.total_executions += 1
        if matched:
            stats.total_matches += 1
        if timeout:
            stats.total_timeouts += 1
        else:
            stats.recent_times.append(execution_time)
            stats.max_execution_time = max(stats.max_execution_time, execution_time)
            stats.min_execution_time = min(stats.min_execution_time, execution_time)
            stats.avg_execution_time = (
                math.fsum(stats.recent_times) / len(stats.recent_times)
                if stats.recent_times
                else stats.avg_execution_time
            )

        return metric, self._detect_statistical_anomaly(
            metric, None if timeout else stats.avg_execution_time
        )

    def _anomaly_check_needed(
        self, metric: PerformanceMetric, statistical_anomaly: dict[str, object] | None
    ) -> bool:
        return bool(
            metric.timeout
            or metric.execution_time > self.slow_pattern_threshold
            or statistical_anomaly
        )

    def record_metric(
        self,
        pattern: str,
        execution_time: float,
        content_length: int,
        matched: bool,
        timeout: bool = False,
        agent_handler: "SyncAgentHandlerProtocol | None" = None,
        correlation_id: str | None = None,
    ) -> None:
        with self._lock:
            metric, statistical_anomaly = self._track_metric(
                pattern, execution_time, content_length, matched, timeout
            )

        if self._anomaly_check_needed(metric, statistical_anomaly):
            self._check_anomalies(
                metric, statistical_anomaly, agent_handler, correlation_id
            )

    def record_metrics(
        self,
        rows: list[tuple[str, float, int, bool, bool]],
        agent_handler: "SyncAgentHandlerProtocol | None" = None,
        correlation_id: str | None = None,
    ) -> None:
        with self._lock:
            tracked = [self._track_metric(*row) for row in rows]

        for metric, statistical_anomaly in tracked:
            if self._anomaly_check_needed(metric, statistical_anomaly):
                self._check_anomalies(
                    metric, statistical_anomaly, agent_handler, correlation_id
                )

    def _detect_timeout_anomaly(
        self, metric: PerformanceMetric
    ) -> dict[str, object] | None:
        return detect_timeout_anomaly(metric)

    def _detect_slow_execution_anomaly(
        self, metric: PerformanceMetric
    ) -> dict[str, object] | None:
        return detect_slow_execution_anomaly(metric, self.slow_pattern_threshold)

    def _detect_statistical_anomaly(
        self, metric: PerformanceMetric, avg_time: float | None = None
    ) -> dict[str, object] | None:
        stats = self.pattern_stats.get(metric.pattern)
        return detect_statistical_anomaly(
            metric,
            stats,
            self.min_samples_for_anomaly,
            self.anomaly_threshold,
            avg_time,
        )

    def _send_anomaly_event(
        self,
        anomaly: dict[str, object],
        agent_handler: "SyncAgentHandlerProtocol",
        correlation_id: str | None,
    ) -> None:
        event_data = build_anomaly_event_data(
            anomaly, correlation_id, self.redaction_names
        )
        event = type("SecurityEvent", (), event_data)()
        try:
            agent_handler.send_event(event)
        except Exception as e:
            logger.error("Failed to send anomaly event to agent: %s", e)

    def _sanitize_anomaly_data(self, anomaly: dict[str, object]) -> dict[str, object]:
        return sanitize_anomaly_data(anomaly, self.redaction_names)

    def _send_callback_error_event(
        self,
        error: Exception,
        safe_anomaly: dict[str, object],
        agent_handler: "SyncAgentHandlerProtocol",
        correlation_id: str | None,
    ) -> None:
        event_data = build_callback_error_event_data(
            error, safe_anomaly, correlation_id
        )
        event = type("SecurityEvent", (), event_data)()
        try:
            agent_handler.send_event(event)
        except Exception as e:
            logger.error("Failed to send callback-error event to agent: %s", e)

    def _notify_callbacks(
        self,
        anomaly: dict[str, object],
        agent_handler: "SyncAgentHandlerProtocol | None",
        correlation_id: str | None,
    ) -> None:
        if not self.anomaly_callbacks:
            return
        safe_anomaly = self._sanitize_anomaly_data(anomaly)

        for callback in self.anomaly_callbacks:
            try:
                callback(safe_anomaly)
            except Exception as e:
                if agent_handler:
                    self._send_callback_error_event(
                        e, safe_anomaly, agent_handler, correlation_id
                    )

    def _reserve_anomaly_emission(self, pattern: str) -> bool:
        now = time.monotonic()
        with self._lock:
            stats = self.pattern_stats.get(pattern)
            if stats is None:
                return True
            last_emitted_at = stats.last_anomaly_emitted_at
            if (
                last_emitted_at is not None
                and now - last_emitted_at < self.anomaly_emission_cooldown
            ):
                return False
            stats.last_anomaly_emitted_at = now
            return True

    def _check_anomalies(
        self,
        metric: PerformanceMetric,
        statistical_anomaly: dict[str, object] | None,
        agent_handler: "SyncAgentHandlerProtocol | None" = None,
        correlation_id: str | None = None,
    ) -> None:
        anomalies: list[dict[str, object]] = []

        timeout_anomaly = self._detect_timeout_anomaly(metric)
        if timeout_anomaly:
            anomalies.append(timeout_anomaly)
        else:
            slow_anomaly = self._detect_slow_execution_anomaly(metric)
            if slow_anomaly:
                anomalies.append(slow_anomaly)

        if statistical_anomaly:
            anomalies.append(statistical_anomaly)

        if agent_handler and anomalies:
            if self._reserve_anomaly_emission(metric.pattern):
                for anomaly in anomalies:
                    self._send_anomaly_event(anomaly, agent_handler, correlation_id)

        for anomaly in anomalies:
            self._notify_callbacks(anomaly, agent_handler, correlation_id)

    def get_pattern_report(self, pattern: str) -> PatternReport | None:
        MAX_PATTERN_LENGTH = 100
        if len(pattern) > MAX_PATTERN_LENGTH:
            pattern = pattern[:MAX_PATTERN_LENGTH] + "...[truncated]"

        stats = self.pattern_stats.get(pattern)
        if not stats:
            return None

        return build_pattern_report(pattern, stats, self.redaction_names)

    def get_slow_patterns(self, limit: int = 10) -> list[PatternReport]:
        with self._lock:
            pattern_stats_snapshot = dict(self.pattern_stats)
        return collect_slow_patterns(
            pattern_stats_snapshot, self.get_pattern_report, limit
        )

    def get_problematic_patterns(self) -> list[PatternReport]:
        with self._lock:
            pattern_stats_snapshot = dict(self.pattern_stats)
        return collect_problematic_patterns(
            pattern_stats_snapshot, self.get_pattern_report, self.slow_pattern_threshold
        )

    def _get_empty_summary(self) -> PerformanceSummary:
        return empty_summary()

    def _extract_metric_components(
        self, recent_metrics: list[PerformanceMetric]
    ) -> tuple[list[float], int, int]:
        return extract_metric_components(recent_metrics)

    def _build_summary_dict(
        self,
        total_metrics: int,
        total_patterns: int,
        recent_times: list[float],
        timeouts: int,
        matches: int,
    ) -> PerformanceSummary:
        return build_summary_dict(
            total_metrics, total_patterns, recent_times, timeouts, matches
        )

    def get_summary_stats(self) -> PerformanceSummary:
        with self._lock:
            if not self.recent_metrics:
                return self._get_empty_summary()
            recent_metrics_snapshot = list(self.recent_metrics)
            total_patterns = len(self.pattern_stats)

        recent_times, timeouts, matches = self._extract_metric_components(
            recent_metrics_snapshot
        )
        return self._build_summary_dict(
            len(recent_metrics_snapshot),
            total_patterns,
            recent_times,
            timeouts,
            matches,
        )

    def register_anomaly_callback(self, callback: AnomalyCallback) -> None:
        self.anomaly_callbacks.append(callback)

    def clear_stats(self) -> None:
        with self._lock:
            self.pattern_stats.clear()
            self.recent_metrics.clear()

    def remove_pattern_stats(self, pattern: str) -> None:
        with self._lock:
            self.pattern_stats.pop(pattern, None)
