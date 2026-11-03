from collections.abc import Callable
from typing import Any
from unittest.mock import patch

from guard_core.models import SyncSecurityConfig
from guard_core.sync.detection_engine.monitor import (
    PerformanceMetric,
    PerformanceMonitor,
)
from guard_core.sync.handlers import _suspatterns_applicable
from guard_core.sync.utils import detect_penetration_attempt
from tests.test_sync.conftest import SyncMockGuardRequest


def _scan_benign_request(config: SyncSecurityConfig) -> None:
    request = SyncMockGuardRequest(
        path="/", query_params={"q": "red shoes"}, headers={"x-a": "blue boots"}
    )
    result = detect_penetration_attempt(request, config)
    assert result.is_threat is False


def test_benign_scan_never_enters_the_anomaly_check() -> None:
    config = SyncSecurityConfig(
        detection_slow_pattern_threshold=1.0, detection_min_samples_for_anomaly=1000
    )
    _scan_benign_request(config)
    calls: list[tuple[object, ...]] = []
    original: Callable[..., None] = PerformanceMonitor._check_anomalies

    def spy(self: PerformanceMonitor, *args: object, **kwargs: object) -> None:
        calls.append(args)
        original(self, *args, **kwargs)

    with patch.object(PerformanceMonitor, "_check_anomalies", spy):
        _scan_benign_request(config)

    assert calls == []


def test_repeated_scan_does_not_refilter_the_pattern_table() -> None:
    config = SyncSecurityConfig()
    _scan_benign_request(config)
    calls: list[int] = []
    original: Callable[..., bool] = _suspatterns_applicable._pattern_should_be_skipped

    def spy(*args: object, **kwargs: object) -> bool:
        calls.append(1)
        return original(*args, **kwargs)

    with patch.object(_suspatterns_applicable, "_pattern_should_be_skipped", spy):
        _scan_benign_request(config)

    assert calls == []


def test_pattern_table_filter_is_reused_and_bounded() -> None:
    import re

    table = [
        (re.compile("a"), frozenset({"query_param"}), "xss"),
        (re.compile("b"), frozenset({"header"}), "xss"),
    ]
    arguments: dict[str, Any] = {
        "raw_view_only": None,
        "url_decoded_view_only": None,
        "skip_filter": False,
        "normalized_context": "query_param",
        "enabled_categories": None,
    }
    _suspatterns_applicable._applicable_pattern_cache.clear()
    first, first_tail = _suspatterns_applicable._applicable_patterns(table, **arguments)
    again, again_tail = _suspatterns_applicable._applicable_patterns(table, **arguments)
    assert first == [table[0]] and first_tail is True
    assert again is first and again_tail is True

    grown = [*table, (re.compile("c"), frozenset({"query_param"}), "xss")]
    regrown, regrown_tail = _suspatterns_applicable._applicable_patterns(
        grown, **arguments
    )
    assert regrown == [grown[0], grown[2]] and regrown_tail is False

    with patch.object(
        _suspatterns_applicable, "_APPLICABLE_PATTERN_CACHE_MAX_ENTRIES", 1
    ):
        _suspatterns_applicable._applicable_patterns(
            table, **{**arguments, "normalized_context": "header"}
        )
    assert len(_suspatterns_applicable._applicable_pattern_cache) == 1


def test_exhausted_time_budget_still_flags_a_pass_with_no_applicable_row() -> None:
    from guard_core.sync._utils.detection_scan import _scan_value_budget
    from guard_core.sync.handlers.suspatterns_handler import sus_patterns_handler

    sus_patterns_handler.configure(SyncSecurityConfig())
    with _scan_value_budget(512, max_scan_seconds=0.0):
        threats, matched, timeouts = sus_patterns_handler._check_regex_patterns(
            "red shoes", "203.0.113.7", None, "query_param", set()
        )

    assert [threat["type"] for threat in threats] == ["pattern_timeout"]
    assert matched == timeouts == ["scan_time_budget_exhausted"]


def test_batched_metrics_match_one_by_one_recording() -> None:
    sequential = PerformanceMonitor()
    batched = PerformanceMonitor()
    rows = [("p1", 0.001, 10, False, False), ("p1", 0.002, 10, True, False)]
    rows.append(("p2", 0.0, 5, False, True))
    for row in rows:
        sequential.record_metric(*row)
    batched.record_metrics(rows)

    assert batched.pattern_stats == sequential.pattern_stats
    assert [m.pattern for m in batched.recent_metrics] == ["p1", "p1", "p2"]


def test_batched_timeout_row_reaches_the_anomaly_check() -> None:
    monitor = PerformanceMonitor()
    seen: list[str] = []

    def spy(metric: PerformanceMetric, *_args: object) -> None:
        seen.append(metric.pattern)

    with patch.object(monitor, "_check_anomalies", spy):
        monitor.record_metrics([("quick", 0.0, 1, False, False)])
        monitor.record_metrics([("slow", 0.0, 1, False, True)])

    assert seen == ["slow"]
