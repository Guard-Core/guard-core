import threading
import time
from collections.abc import Generator, Iterator
from typing import Any
from unittest.mock import patch

import pytest
from pydantic import ValidationError

from guard_core.models import SecurityConfig
from guard_core.sync._utils import detection_scan
from guard_core.sync._utils.detection_scan import (
    _scan_time_budget_exhausted,
    _scan_value_budget,
)
from guard_core.sync.handlers.suspatterns_handler import SusPatternsManager
from guard_core.sync.utils import detect_penetration_attempt
from tests.test_sync.conftest import SyncMockGuardRequest


@pytest.fixture(autouse=True)
def _reset_suspatterns_singleton() -> Generator[None, None]:
    original_instance = SusPatternsManager._instance
    original_config = SusPatternsManager._config

    SusPatternsManager._instance = None
    SusPatternsManager._config = None

    yield

    SusPatternsManager._instance = original_instance
    SusPatternsManager._config = original_config


class _FakeClock:
    def __init__(self, step: float) -> None:
        self.now = 0.0
        self.step = step

    def cpu_seconds(self) -> float:
        self.now += self.step
        return self.now


@pytest.fixture
def fake_regex_clock() -> Iterator[_FakeClock]:
    clock = _FakeClock(step=1.0)
    with patch.object(detection_scan, "_thread_cpu_seconds", clock.cpu_seconds):
        yield clock


def test_field_default_and_bounds() -> None:
    assert SecurityConfig().detection_max_scan_seconds == 10.0
    assert SecurityConfig(detection_max_scan_seconds=0.1)
    assert SecurityConfig(detection_max_scan_seconds=60.0)
    for bad in (0.0, 0.09, 60.1):
        with pytest.raises(ValidationError):
            SecurityConfig(detection_max_scan_seconds=bad)


def test_budget_is_unbounded_outside_a_request() -> None:
    assert _scan_time_budget_exhausted() is False


def test_budget_tracks_recorded_time_and_resets() -> None:
    with _scan_value_budget(512, max_scan_seconds=1.0):
        assert _scan_time_budget_exhausted() is False
        detection_scan._record_scan_time(0.4)
        assert _scan_time_budget_exhausted() is False
        detection_scan._record_scan_time(0.6)
        assert _scan_time_budget_exhausted() is True
    assert _scan_time_budget_exhausted() is False
    with _scan_value_budget(512, max_scan_seconds=1.0):
        assert _scan_time_budget_exhausted() is False


def test_default_budget_does_not_flag_benign_request() -> None:
    request = SyncMockGuardRequest(
        path="/items?page=2", headers={"accept-language": "en-US,en;q=0.9"}
    )

    result = detect_penetration_attempt(request, SecurityConfig())

    assert result.is_threat is False


def test_exhausted_budget_stops_scan_and_flags_request(
    fake_regex_clock: _FakeClock,
) -> None:
    request = SyncMockGuardRequest(
        path="/items", headers={"x-pad": "benign filler value"}
    )
    manager = SusPatternsManager()
    seen: list[str] = []
    real = manager._check_regex_pattern

    def counting(pattern: Any, *args: Any, **kwargs: Any) -> Any:
        seen.append(pattern.pattern)
        return real(pattern, *args, **kwargs)

    with patch.object(manager, "_check_regex_pattern", counting):
        result = detect_penetration_attempt(
            request, SecurityConfig(detection_max_scan_seconds=0.1)
        )

    all_patterns = manager.get_all_compiled_patterns()
    assert result.is_threat is True
    assert "Pattern exceeded scan time budget" in result.trigger_info
    assert len(seen) < len(all_patterns)
    assert fake_regex_clock.now > 0


def test_budget_threat_is_weighted_and_reported_as_timeout(
    fake_regex_clock: _FakeClock,
) -> None:
    config = SecurityConfig(detection_max_scan_seconds=0.1)
    manager = SusPatternsManager()
    manager.configure(config)

    with _scan_value_budget(512, max_scan_seconds=0.1):
        result = manager.detect("hello world", "127.0.0.1", "query_param:q")

    budget_threats = [
        t for t in result["threats"] if t["pattern"] == "scan_time_budget_exhausted"
    ]
    assert budget_threats
    assert budget_threats[0]["type"] == "pattern_timeout"
    assert budget_threats[0]["weight"] >= config.detection_threat_score_threshold
    assert "scan_time_budget_exhausted" in result["timeouts"]
    assert result["is_threat"] is True


def test_budget_is_shared_across_fields_of_one_request(
    fake_regex_clock: _FakeClock,
) -> None:
    manager = SusPatternsManager()
    manager.configure(SecurityConfig(detection_max_scan_seconds=2.5))

    with _scan_value_budget(512, max_scan_seconds=2.5):
        first = manager.detect("hello", "127.0.0.1", "query_param:a")
        second = manager.detect("world", "127.0.0.1", "query_param:b")

    names = [t["pattern"] for t in first["threats"] + second["threats"]]
    assert "scan_time_budget_exhausted" in names
    assert second["is_threat"] is True


def test_fallback_check_honours_budget() -> None:
    with _scan_value_budget(512, max_scan_seconds=0.1):
        detection_scan._record_scan_time(1.0)
        detected, trigger = detection_scan._fallback_pattern_check(
            "hello", "127.0.0.1", "query_param:q"
        )

    assert detected is True
    assert "budget" in trigger


def test_trigger_names_the_budget_when_it_tips_the_request(
    fake_regex_clock: _FakeClock,
) -> None:
    request = SyncMockGuardRequest(path="/items", headers={"x-pad": "select a from b"})

    result = detect_penetration_attempt(
        request, SecurityConfig(detection_max_scan_seconds=0.1)
    )

    assert result.is_threat is True
    assert "Pattern exceeded scan time budget" in result.trigger_info
    assert "scan_time_budget_exhausted" in result.trigger_info


def test_threats_message_appends_the_first_later_timeout() -> None:
    regex = {"type": "regex", "pattern": "a"}
    timeout = {"type": "pattern_timeout", "pattern": "slow"}
    other = {"type": "pattern_timeout", "pattern": "later"}

    message = detection_scan._build_threats_message([regex, timeout, other])

    assert message == (
        "Value matched pattern 'a'; Pattern exceeded scan time budget: 'slow'"
    )
    assert detection_scan._build_threats_message([regex]) == (
        "Value matched pattern 'a'"
    )
    assert detection_scan._build_threats_message([timeout, regex]) == (
        "Pattern exceeded scan time budget: 'slow'"
    )


def test_wall_slow_but_cpu_cheap_scan_does_not_exhaust_the_budget() -> None:
    manager = SusPatternsManager()
    manager.configure(SecurityConfig())
    real = manager._check_regex_pattern

    def slow_wall(*args: Any, **kwargs: Any) -> Any:
        time.sleep(0.01)
        return real(*args, **kwargs)

    with (
        patch.object(manager, "_check_regex_pattern", slow_wall),
        _scan_value_budget(512, max_scan_seconds=0.1),
    ):
        result = manager.detect("hello world", "127.0.0.1", "query_param:q")

    assert all(t["pattern"] != "scan_time_budget_exhausted" for t in result["threats"])
    assert result["is_threat"] is False


def test_worker_scan_cpu_is_recorded_from_the_worker_thread(
    fake_regex_clock: _FakeClock,
) -> None:
    manager = SusPatternsManager()
    manager.configure(SecurityConfig())
    manager.add_pattern("zzzworker[a-z]+q")

    with _scan_value_budget(512, max_scan_seconds=1000.0):
        manager.detect("hello", "127.0.0.1", "query_param:q")
        remaining = detection_scan._scan_time_remaining()

    assert remaining is not None
    assert remaining < 1000.0


def test_inline_cpu_is_accounted_per_pass_not_per_pattern() -> None:
    manager = SusPatternsManager()
    manager.configure(SecurityConfig())
    calls = {"clock": 0, "patterns": 0}
    real = manager._check_regex_pattern

    scan_thread = threading.get_ident()

    def counting_clock() -> float:
        if threading.get_ident() == scan_thread:
            calls["clock"] += 1
        return 0.0

    def counting(*args: Any, **kwargs: Any) -> Any:
        calls["patterns"] += 1
        return real(*args, **kwargs)

    with (
        patch.object(detection_scan, "_thread_cpu_seconds", counting_clock),
        patch.object(manager, "_check_regex_pattern", counting),
        _scan_value_budget(512, max_scan_seconds=1000.0),
    ):
        manager.detect("hello world", "127.0.0.1", "query_param:q")

    assert calls["patterns"] > 50
    assert 0 < calls["clock"] < calls["patterns"] * 0.2


def test_no_cpu_clock_reads_outside_a_request_scope() -> None:
    manager = SusPatternsManager()
    manager.configure(SecurityConfig())
    calls = {"clock": 0}

    scan_thread = threading.get_ident()

    def counting_clock() -> float:
        if threading.get_ident() == scan_thread:
            calls["clock"] += 1
        return 0.0

    with patch.object(detection_scan, "_thread_cpu_seconds", counting_clock):
        manager.detect("hello world", "127.0.0.1", "query_param:q")

    assert calls["clock"] == 0
