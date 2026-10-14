from collections.abc import AsyncGenerator, Iterator
from typing import Any
from unittest.mock import patch

import pytest
from pydantic import ValidationError

from guard_core._utils import detection_scan
from guard_core._utils.detection_scan import (
    _scan_time_budget_exhausted,
    _scan_value_budget,
)
from guard_core.handlers.suspatterns_handler import SusPatternsManager
from guard_core.models import SecurityConfig
from guard_core.utils import detect_penetration_attempt
from tests.conftest import MockGuardRequest


@pytest.fixture(autouse=True)
async def _reset_suspatterns_singleton() -> AsyncGenerator[None, None]:
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

    def monotonic(self) -> float:
        self.now += self.step
        return self.now


@pytest.fixture
def fake_regex_clock() -> Iterator[_FakeClock]:
    clock = _FakeClock(step=1.0)
    with patch("guard_core.handlers._suspatterns_regex.time") as fake_time:
        fake_time.monotonic = clock.monotonic
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


async def test_default_budget_does_not_flag_benign_request() -> None:
    request = MockGuardRequest(
        path="/items?page=2", headers={"accept-language": "en-US,en;q=0.9"}
    )

    result = await detect_penetration_attempt(request, SecurityConfig())

    assert result.is_threat is False


async def test_exhausted_budget_stops_scan_and_flags_request(
    fake_regex_clock: _FakeClock,
) -> None:
    request = MockGuardRequest(path="/items", headers={"x-pad": "benign filler value"})
    manager = SusPatternsManager()
    seen: list[str] = []
    real = manager._check_regex_pattern

    async def counting(pattern: Any, *args: Any, **kwargs: Any) -> Any:
        seen.append(pattern.pattern)
        return await real(pattern, *args, **kwargs)

    with patch.object(manager, "_check_regex_pattern", counting):
        result = await detect_penetration_attempt(
            request, SecurityConfig(detection_max_scan_seconds=0.1)
        )

    all_patterns = await manager.get_all_compiled_patterns()
    assert result.is_threat is True
    assert "Pattern exceeded scan time budget" in result.trigger_info
    assert len(seen) < len(all_patterns)
    assert fake_regex_clock.now > 0


async def test_budget_threat_is_weighted_and_reported_as_timeout(
    fake_regex_clock: _FakeClock,
) -> None:
    config = SecurityConfig(detection_max_scan_seconds=0.1)
    manager = SusPatternsManager()
    manager.configure(config)

    with _scan_value_budget(512, max_scan_seconds=0.1):
        result = await manager.detect("hello world", "127.0.0.1", "query_param:q")

    budget_threats = [
        t for t in result["threats"] if t["pattern"] == "scan_time_budget_exhausted"
    ]
    assert budget_threats
    assert budget_threats[0]["type"] == "pattern_timeout"
    assert budget_threats[0]["weight"] >= config.detection_threat_score_threshold
    assert "scan_time_budget_exhausted" in result["timeouts"]
    assert result["is_threat"] is True


async def test_budget_is_shared_across_fields_of_one_request(
    fake_regex_clock: _FakeClock,
) -> None:
    manager = SusPatternsManager()
    manager.configure(SecurityConfig(detection_max_scan_seconds=2.5))

    with _scan_value_budget(512, max_scan_seconds=2.5):
        first = await manager.detect("hello", "127.0.0.1", "query_param:a")
        second = await manager.detect("world", "127.0.0.1", "query_param:b")

    names = [t["pattern"] for t in first["threats"] + second["threats"]]
    assert "scan_time_budget_exhausted" in names
    assert second["is_threat"] is True


async def test_fallback_check_honours_budget() -> None:
    with _scan_value_budget(512, max_scan_seconds=0.1):
        detection_scan._record_scan_time(1.0)
        detected, trigger = await detection_scan._fallback_pattern_check(
            "hello", "127.0.0.1", "query_param:q"
        )

    assert detected is True
    assert "budget" in trigger
