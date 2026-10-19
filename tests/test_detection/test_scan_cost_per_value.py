from typing import Any
from unittest.mock import patch

from guard_core.detection_engine.monitor import PerformanceMonitor
from guard_core.handlers import _suspatterns_applicable
from guard_core.models import SecurityConfig
from guard_core.utils import detect_penetration_attempt
from tests.conftest import MockGuardRequest


async def _scan_benign_request(config: SecurityConfig) -> None:
    request = MockGuardRequest(
        path="/", query_params={"q": "red shoes"}, headers={"x-a": "blue boots"}
    )
    result = await detect_penetration_attempt(request, config)
    assert result.is_threat is False


async def test_benign_scan_never_enters_the_anomaly_check() -> None:
    config = SecurityConfig(
        detection_slow_pattern_threshold=1.0, detection_min_samples_for_anomaly=1000
    )
    await _scan_benign_request(config)
    calls: list[Any] = []
    original = PerformanceMonitor._check_anomalies

    async def spy(self: PerformanceMonitor, *args: Any, **kwargs: Any) -> None:
        calls.append(args)
        await original(self, *args, **kwargs)

    with patch.object(PerformanceMonitor, "_check_anomalies", spy):
        await _scan_benign_request(config)

    assert calls == []


async def test_repeated_scan_does_not_refilter_the_pattern_table() -> None:
    config = SecurityConfig()
    await _scan_benign_request(config)
    calls: list[int] = []
    original = _suspatterns_applicable._pattern_should_be_skipped

    def spy(*args: Any, **kwargs: Any) -> bool:
        calls.append(1)
        return original(*args, **kwargs)

    with patch.object(_suspatterns_applicable, "_pattern_should_be_skipped", spy):
        await _scan_benign_request(config)

    assert calls == []


async def test_pattern_table_filter_is_reused_and_bounded() -> None:
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


async def test_exhausted_time_budget_still_flags_a_pass_with_no_applicable_row() -> (
    None
):
    from guard_core._utils.detection_scan import _scan_value_budget
    from guard_core.handlers.suspatterns_handler import sus_patterns_handler

    sus_patterns_handler.configure(SecurityConfig())
    with _scan_value_budget(512, max_scan_seconds=0.0):
        threats, matched, timeouts = await sus_patterns_handler._check_regex_patterns(
            "red shoes", "203.0.113.7", None, "query_param", set()
        )

    assert [threat["type"] for threat in threats] == ["pattern_timeout"]
    assert matched == timeouts == ["scan_time_budget_exhausted"]


async def test_batched_metrics_match_one_by_one_recording() -> None:
    sequential = PerformanceMonitor()
    batched = PerformanceMonitor()
    rows = [("p1", 0.001, 10, False, False), ("p1", 0.002, 10, True, False)]
    rows.append(("p2", 0.0, 5, False, True))
    for row in rows:
        await sequential.record_metric(*row)
    await batched.record_metrics(rows)

    assert batched.pattern_stats == sequential.pattern_stats
    assert [m.pattern for m in batched.recent_metrics] == ["p1", "p1", "p2"]


async def test_batched_timeout_row_reaches_the_anomaly_check() -> None:
    monitor = PerformanceMonitor()
    seen: list[str] = []

    async def spy(metric: Any, *_args: Any) -> None:
        seen.append(metric.pattern)

    with patch.object(monitor, "_check_anomalies", spy):
        await monitor.record_metrics([("quick", 0.0, 1, False, False)])
        await monitor.record_metrics([("slow", 0.0, 1, False, True)])

    assert seen == ["slow"]
