import asyncio
import re
import threading
from collections.abc import AsyncGenerator, Awaitable, Callable, Iterator
from unittest.mock import patch

import pytest
from pydantic import ValidationError

from guard_core._utils import detection_scan
from guard_core._utils.detection_scan import (
    _scan_time_budget_exhausted,
    _scan_value_budget,
)
from guard_core.handlers import (
    _suspatterns_inline_matches,
    _suspatterns_lazy_rows,
    _suspatterns_regex,
)
from guard_core.handlers._suspatterns_lazy_rows import PatternSource
from guard_core.handlers.suspatterns_handler import (
    SusPatternsManager,
    sus_patterns_handler,
)
from guard_core.models import SecurityConfig
from guard_core.protocols.agent_protocol import JsonValue
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
    real: Callable[..., Awaitable[tuple[dict | None, bool]]] = (
        manager._check_regex_pattern
    )

    async def counting(
        pattern: PatternSource, *args: object, **kwargs: object
    ) -> tuple[dict | None, bool]:
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
    weight = budget_threats[0]["weight"]
    assert isinstance(weight, (int, float))
    assert weight >= config.detection_threat_score_threshold
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


async def test_fallback_check_charges_its_inline_scan_cpu(
    fake_regex_clock: _FakeClock,
) -> None:
    async def inline_only(*_args: object, **_kwargs: object) -> tuple[None, bool]:
        return None, False

    with (
        patch.object(sus_patterns_handler, "_check_regex_pattern", inline_only),
        _scan_value_budget(512, max_scan_seconds=2.5),
    ):
        detected, trigger = await detection_scan._fallback_pattern_check(
            "hello", "127.0.0.1", "query_param:q"
        )

    assert detected is True
    assert "budget" in trigger


async def test_trigger_names_the_budget_when_it_tips_the_request(
    fake_regex_clock: _FakeClock,
) -> None:
    request = MockGuardRequest(path="/items", headers={"x-pad": "select a from b"})

    result = await detect_penetration_attempt(
        request, SecurityConfig(detection_max_scan_seconds=0.1)
    )

    assert result.is_threat is True
    assert "Pattern exceeded scan time budget" in result.trigger_info
    assert "scan_time_budget_exhausted" in result.trigger_info


def test_threats_message_appends_the_first_later_timeout() -> None:
    regex: dict[str, JsonValue] = {"type": "regex", "pattern": "a"}
    timeout: dict[str, JsonValue] = {"type": "pattern_timeout", "pattern": "slow"}
    other: dict[str, JsonValue] = {"type": "pattern_timeout", "pattern": "later"}

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


async def test_wall_slow_but_cpu_cheap_scan_does_not_exhaust_the_budget() -> None:
    manager = SusPatternsManager()
    manager.configure(SecurityConfig())
    real: Callable[..., Awaitable[tuple[dict | None, bool]]] = (
        manager._check_regex_pattern
    )

    async def slow_wall(*args: object, **kwargs: object) -> tuple[dict | None, bool]:
        await asyncio.sleep(0.01)
        return await real(*args, **kwargs)

    with (
        patch.object(manager, "_check_regex_pattern", slow_wall),
        _scan_value_budget(512, max_scan_seconds=0.1),
    ):
        result = await manager.detect("hello world", "127.0.0.1", "query_param:q")

    assert all(t["pattern"] != "scan_time_budget_exhausted" for t in result["threats"])
    assert result["is_threat"] is False


async def test_first_scan_lazy_pattern_builds_are_not_charged_to_the_budget() -> None:
    manager = SusPatternsManager()
    manager.configure(SecurityConfig())
    builtin_sources = {row[0] for row in manager._pattern_definitions}
    clock = _FakeClock(step=0.0)
    real_compile = re.compile
    real_linear_finder = _suspatterns_inline_matches.linear_path_finder

    def costly_compile(source: str, flags: int = 0) -> re.Pattern[str]:
        if source in builtin_sources:
            clock.now += 1000.0
        return real_compile(source, flags)

    def costly_linear_finder(
        pattern: re.Pattern,
    ) -> Callable[[str], Iterator[re.Match]] | None:
        clock.now += 1000.0
        return real_linear_finder(pattern)

    with (
        patch.object(detection_scan, "_thread_cpu_seconds", clock.cpu_seconds),
        patch.object(re, "compile", costly_compile),
        patch.object(
            _suspatterns_inline_matches, "linear_path_finder", costly_linear_finder
        ),
        patch.object(
            _suspatterns_regex,
            "_INLINE_FINDERS",
            _suspatterns_inline_matches._InlineFinders(),
        ),
        patch.dict(_suspatterns_lazy_rows.COMPILED_BUILTIN_PATTERNS, clear=True),
        _scan_value_budget(512, max_scan_seconds=0.1),
    ):
        result = await manager.detect("hello world", "127.0.0.1", "query_param:q")

    assert clock.now >= 1000.0
    assert all(t["pattern"] != "scan_time_budget_exhausted" for t in result["threats"])
    assert result["is_threat"] is False


async def test_worker_scan_cpu_is_recorded_from_the_worker_thread(
    fake_regex_clock: _FakeClock,
) -> None:
    manager = SusPatternsManager()
    manager.configure(SecurityConfig())
    await manager.add_pattern("zzzworker[a-z]+q")

    with _scan_value_budget(512, max_scan_seconds=1000.0):
        await manager.detect("hello", "127.0.0.1", "query_param:q")
        remaining = detection_scan._scan_time_remaining()

    assert remaining is not None
    assert remaining < 1000.0


async def test_inline_cpu_is_accounted_per_pass_not_per_pattern() -> None:
    manager = SusPatternsManager()
    manager.configure(SecurityConfig())
    calls = {"clock": 0, "patterns": 0}
    real: Callable[..., Awaitable[tuple[dict | None, bool]]] = (
        manager._check_regex_pattern
    )

    scan_thread = threading.get_ident()

    def counting_clock() -> float:
        if threading.get_ident() == scan_thread:
            calls["clock"] += 1
        return 0.0

    async def counting(*args: object, **kwargs: object) -> tuple[dict | None, bool]:
        calls["patterns"] += 1
        return await real(*args, **kwargs)

    # The 2 ms event-loop slice yields on wall time, and each yield reads the
    # clock, so a loaded machine adds reads; switch slicing off to count passes only.
    with (
        patch.object(detection_scan, "_thread_cpu_seconds", counting_clock),
        patch.object(manager, "_check_regex_pattern", counting),
        patch.object(_suspatterns_regex, "_EVENT_LOOP_SLICE_SECONDS", float("inf")),
        patch.object(
            _suspatterns_regex,
            "rows_with_required_literal",
            lambda rows, *_args: iter(rows),
        ),
        _scan_value_budget(512, max_scan_seconds=1000.0),
    ):
        # Steady state only: the one-time lazy compile of each built-in row reads
        # the clock twice (to exclude its CPU from the budget), so scan once to
        # warm every row, then count the second scan.
        await manager.detect("hello world", "127.0.0.1", "query_param:q")
        calls["clock"] = calls["patterns"] = 0
        await manager.detect("hello world", "127.0.0.1", "query_param:q")

    assert calls["patterns"] > 50
    assert 0 < calls["clock"] < calls["patterns"] * 0.2


async def test_no_cpu_clock_reads_outside_a_request_scope() -> None:
    manager = SusPatternsManager()
    manager.configure(SecurityConfig())
    calls = {"clock": 0}

    scan_thread = threading.get_ident()

    def counting_clock() -> float:
        if threading.get_ident() == scan_thread:
            calls["clock"] += 1
        return 0.0

    with patch.object(detection_scan, "_thread_cpu_seconds", counting_clock):
        await manager.detect("hello world", "127.0.0.1", "query_param:q")

    assert calls["clock"] == 0


def test_attack_region_extraction_charges_its_cpu_to_the_budget(
    fake_regex_clock: _FakeClock,
) -> None:
    from guard_core.detection_engine.preprocessor import ContentPreprocessor
    from guard_core.detection_engine.truncation import _collect_regions

    preprocessor = ContentPreprocessor()
    with _scan_value_budget(512, max_scan_seconds=100.0):
        before = detection_scan._scan_time_remaining()
        _collect_regions(preprocessor, "quiet text " * 50, 10)
        after = detection_scan._scan_time_remaining()

    assert before is not None
    assert after is not None
    assert after < before


class _RaisedRouteBodyRequest(MockGuardRequest):
    async def read_body_prefix(self, max_bytes: int) -> bytes:
        return self._body[:max_bytes]


async def test_clean_route_raised_json_ends_in_the_budget_outcome() -> None:
    import json

    from guard_core.decorators.base import RouteConfig

    words = "quarterly onboarding metrics for the regional sales team include revenue "
    size = 20_000_000
    data = json.dumps({"k": (words * (size // len(words) + 1))[:size]}).encode()
    route = RouteConfig()
    route.max_request_size = 2 * size
    request = _RaisedRouteBodyRequest(
        method="POST",
        body_content=data,
        headers={
            "content-type": "application/json",
            "content-length": str(len(data)),
        },
    )
    cap = 1.0
    charged = [0.0]
    longest_pass = [0.0]
    real_record = detection_scan._record_scan_time

    def recording(elapsed: float) -> None:
        charged[0] += elapsed
        longest_pass[0] = max(longest_pass[0], elapsed)
        real_record(elapsed)

    with (
        patch.object(detection_scan, "_record_scan_time", recording),
        patch.object(_suspatterns_regex, "_record_scan_time", recording),
        patch.object(detection_scan.LazyPreview, "resolve", lambda self: None),
    ):
        result = await detect_penetration_attempt(
            request, SecurityConfig(detection_max_scan_seconds=cap), route
        )

    assert result.is_threat is True
    assert "Pattern exceeded scan time budget" in result.trigger_info
    assert charged[0] <= cap + longest_pass[0]


async def test_a_pass_that_starts_with_the_budget_spent_charges_no_cpu() -> None:
    # LEDGER 6.694: such a pass folded its whole content for the literal prefilter
    # inside the charged window, so each late pass added milliseconds past the cap.
    manager = SusPatternsManager()
    manager.configure(SecurityConfig(detection_max_scan_seconds=1.0))
    charged = [0.0]
    real_record = detection_scan._record_scan_time

    def recording(elapsed: float) -> None:
        charged[0] += elapsed
        real_record(elapsed)

    with (
        _scan_value_budget(512, max_scan_seconds=1.0),
        patch.object(detection_scan, "_record_scan_time", recording),
    ):
        real_record(1.5)
        threats, matched, timeouts = await manager._check_regex_patterns(
            "quarterly onboarding metrics " * 100_000, "127.0.0.1", None
        )

    assert charged[0] == 0.0
    assert matched == timeouts == ["scan_time_budget_exhausted"]
    assert [threat["pattern"] for threat in threats] == matched
