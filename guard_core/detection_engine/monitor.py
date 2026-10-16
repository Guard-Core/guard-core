import asyncio
import logging
import math
import time
from collections import deque
from datetime import datetime, timezone
from typing import Any

from .monitor_anomalies import (
    build_anomaly_event_data,
    build_callback_error_event_data,
    detect_slow_execution_anomaly,
    detect_statistical_anomaly,
    detect_timeout_anomaly,
    sanitize_anomaly_data,
)
from .monitor_reporting import (
    build_pattern_report,
    build_summary_dict,
    collect_problematic_patterns,
    collect_slow_patterns,
    empty_summary,
    extract_metric_components,
)
from .monitor_types import DEFAULT_RECENT_TIMES_WINDOW, PatternStats, PerformanceMetric

_DEFAULT_RECENT_TIMES_WINDOW = DEFAULT_RECENT_TIMES_WINDOW

__all__ = [
    "PatternStats",
    "PerformanceMetric",
    "PerformanceMonitor",
    "DEFAULT_RECENT_TIMES_WINDOW",
    "_DEFAULT_RECENT_TIMES_WINDOW",
]

logger = logging.getLogger("guard_core.detection_engine.monitor")


class PerformanceMonitor:
    def __init__(
        self,
        anomaly_threshold: float = 3.0,
        slow_pattern_threshold: float = 0.1,
        history_size: int = 1000,
        max_tracked_patterns: int = 1000,
        anomaly_emission_cooldown: float = 60.0,
        min_samples_for_anomaly: int = 30,
    ):
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
        self.anomaly_callbacks: list[Any] = []
        self._lock = asyncio.Lock()

    async def record_metric(
        self,
        pattern: str,
        execution_time: float,
        content_length: int,
        matched: bool,
        timeout: bool = False,
        agent_handler: Any = None,
        correlation_id: str | None = None,
    ) -> None:
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

        async with self._lock:
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

            statistical_anomaly = self._detect_statistical_anomaly(metric)

        await self._check_anomalies(
            metric, statistical_anomaly, agent_handler, correlation_id
        )

    def _detect_timeout_anomaly(
        self, metric: PerformanceMetric
    ) -> dict[str, Any] | None:
        return detect_timeout_anomaly(metric)

    def _detect_slow_execution_anomaly(
        self, metric: PerformanceMetric
    ) -> dict[str, Any] | None:
        return detect_slow_execution_anomaly(metric, self.slow_pattern_threshold)

    def _detect_statistical_anomaly(
        self, metric: PerformanceMetric
    ) -> dict[str, Any] | None:
        stats = self.pattern_stats.get(metric.pattern)
        return detect_statistical_anomaly(
            metric, stats, self.min_samples_for_anomaly, self.anomaly_threshold
        )

    async def _send_anomaly_event(
        self,
        anomaly: dict[str, Any],
        agent_handler: Any,
        correlation_id: str | None,
    ) -> None:
        event_data = build_anomaly_event_data(anomaly, correlation_id)
        event = type("SecurityEvent", (), event_data)()
        try:
            await agent_handler.send_event(event)
        except Exception as e:
            logger.error("Failed to send anomaly event to agent: %s", e)

    def _sanitize_anomaly_data(self, anomaly: dict[str, Any]) -> dict[str, Any]:
        return sanitize_anomaly_data(anomaly)

    async def _send_callback_error_event(
        self,
        error: Exception,
        safe_anomaly: dict[str, Any],
        agent_handler: Any,
        correlation_id: str | None,
    ) -> None:
        event_data = build_callback_error_event_data(
            error, safe_anomaly, correlation_id
        )
        event = type("SecurityEvent", (), event_data)()
        try:
            await agent_handler.send_event(event)
        except Exception as e:
            logger.error("Failed to send callback-error event to agent: %s", e)

    async def _notify_callbacks(
        self,
        anomaly: dict[str, Any],
        agent_handler: Any,
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
                    await self._send_callback_error_event(
                        e, safe_anomaly, agent_handler, correlation_id
                    )

    async def _reserve_anomaly_emission(self, pattern: str) -> bool:
        now = time.monotonic()
        async with self._lock:
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

    async def _check_anomalies(
        self,
        metric: PerformanceMetric,
        statistical_anomaly: dict[str, Any] | None,
        agent_handler: Any = None,
        correlation_id: str | None = None,
    ) -> None:
        anomalies: list[dict[str, Any]] = []

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
            if await self._reserve_anomaly_emission(metric.pattern):
                for anomaly in anomalies:
                    await self._send_anomaly_event(
                        anomaly, agent_handler, correlation_id
                    )

        for anomaly in anomalies:
            await self._notify_callbacks(anomaly, agent_handler, correlation_id)

    def get_pattern_report(self, pattern: str) -> dict[str, Any] | None:
        MAX_PATTERN_LENGTH = 100
        if len(pattern) > MAX_PATTERN_LENGTH:
            pattern = pattern[:MAX_PATTERN_LENGTH] + "...[truncated]"

        stats = self.pattern_stats.get(pattern)
        if not stats:
            return None

        return build_pattern_report(pattern, stats)

    async def get_slow_patterns(self, limit: int = 10) -> list[dict[str, Any]]:
        async with self._lock:
            pattern_stats_snapshot = dict(self.pattern_stats)
        return collect_slow_patterns(
            pattern_stats_snapshot, self.get_pattern_report, limit
        )

    async def get_problematic_patterns(self) -> list[dict[str, Any]]:
        async with self._lock:
            pattern_stats_snapshot = dict(self.pattern_stats)
        return collect_problematic_patterns(
            pattern_stats_snapshot, self.get_pattern_report, self.slow_pattern_threshold
        )

    def _get_empty_summary(self) -> dict[str, Any]:
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
    ) -> dict[str, Any]:
        return build_summary_dict(
            total_metrics, total_patterns, recent_times, timeouts, matches
        )

    async def get_summary_stats(self) -> dict[str, Any]:
        async with self._lock:
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

    def register_anomaly_callback(self, callback: Any) -> None:
        self.anomaly_callbacks.append(callback)

    async def clear_stats(self) -> None:
        async with self._lock:
            self.pattern_stats.clear()
            self.recent_metrics.clear()

    async def remove_pattern_stats(self, pattern: str) -> None:
        async with self._lock:
            self.pattern_stats.pop(pattern, None)
