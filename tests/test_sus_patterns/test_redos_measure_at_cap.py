import re
from collections.abc import Iterator
from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest

from guard_core._utils.detection_scan import (
    _MAX_USER_AGENT_MATCH_LENGTH,
    _search_user_agent_windows,
)
from guard_core.decorators.content_filtering import ContentFilteringMixin
from guard_core.detection_engine._redos_cost_arbiter import (
    ReachProbeTiming,
    _first_over_budget_reason,
    _reach_probe_cost_reason,
    _reach_probe_sizes_for_strategy,
    _reach_probe_verdict_from_samples,
)
from guard_core.detection_engine._redos_cpu_budget import ReachProbeCpuBudget
from guard_core.detection_engine.compiler import PatternCompiler
from guard_core.handlers import suspatterns_handler as sph
from guard_core.handlers._dynamic_rule_plan import (
    DynamicRulePlan,
    DynamicRulePlanMixin,
)
from guard_core.handlers.suspatterns_handler import SusPatternsManager
from guard_core.models import DynamicRules, SecurityConfig

_ARBITER = "guard_core.detection_engine._redos_cost_arbiter"
_MIN_BODY_INSPECT_BYTES = 1024


def _timing(rows: list[list[float]]) -> ReachProbeTiming:
    return ReachProbeTiming(rows, 1.0)


def _size_echo_builder(size: int) -> str:
    return f"probe-{size}"


def _recorded_probe_sets(
    monkeypatch: pytest.MonkeyPatch,
    cap: int,
    cost_at_cap: float,
    structural_violation: str | None = None,
) -> tuple[list[list[str]], str | None]:
    calls: list[list[str]] = []

    def fake_timing(
        _pattern: str, probes: list[str], _budget: ReachProbeCpuBudget, _flags: int
    ) -> ReachProbeTiming:
        calls.append(probes)
        return _timing([[0.001] * 5, [cost_at_cap] * 5])

    monkeypatch.setattr(f"{_ARBITER}._time_reach_probes_subprocess", fake_timing)
    monkeypatch.setattr(f"{_ARBITER}._time_reach_probes_ascending", fake_timing)
    reason = _first_over_budget_reason(
        "pattern",
        [_size_echo_builder],
        cap,
        structural_violation,
        ReachProbeCpuBudget(100.0),
    )
    return calls, reason


def test_cap_12000_verdict_uses_the_6000_and_12000_measurements_unextrapolated() -> (
    None
):
    samples = [[0.03] * 5, [0.06] * 5]

    over, cost, ratio, min_at_cap, median_at_cap = _reach_probe_verdict_from_samples(
        samples, 12000
    )

    assert over is True
    assert cost == pytest.approx(0.06)
    assert min_at_cap == pytest.approx(0.06)
    assert median_at_cap == pytest.approx(0.06)
    assert ratio == pytest.approx(2.0)


@pytest.mark.parametrize("cap", [1, 512, 12000, 16000, 31999])
def test_below_32000_a_cost_just_under_the_budget_is_accepted(cap: int) -> None:
    over, cost, _ratio, _min, _median = _reach_probe_verdict_from_samples(
        [[0.01] * 5, [0.0499] * 5], cap
    )
    assert over is False
    assert cost == pytest.approx(0.0499)


@pytest.mark.parametrize("cap", [1, 512, 12000, 16000, 31999])
def test_below_32000_a_cost_just_over_the_budget_is_rejected(cap: int) -> None:
    over, cost, _ratio, _min, _median = _reach_probe_verdict_from_samples(
        [[0.01] * 5, [0.0501] * 5], cap
    )
    assert over is True
    assert cost == pytest.approx(0.0501)


def test_below_32000_the_load_factor_normalizes_the_cost_measured_at_the_cap() -> None:
    samples = [[0.04] * 5, [0.08] * 5]
    assert _reach_probe_verdict_from_samples(samples, 12000, 1.0)[0] is True
    over, cost, _ratio, _min, _median = _reach_probe_verdict_from_samples(
        samples, 12000, 2.0
    )
    assert over is False
    assert cost == pytest.approx(0.04)


@pytest.mark.parametrize(
    ("cap", "expected"),
    [
        (
            262144,
            (True, 0.32768, 2.0, 0.04, 0.04),
        ),
        (
            32000,
            (False, 0.04, 2.0, 0.04, 0.04),
        ),
    ],
)
def test_cap_32000_and_above_verdicts_equal_the_base_tuples(
    cap: int, expected: tuple[bool, float, float, float, float]
) -> None:
    assert _reach_probe_verdict_from_samples([[0.02] * 5, [0.04] * 5], cap) == expected


def test_cap_262144_reason_is_the_base_text() -> None:
    assert _reach_probe_cost_reason(None, 0.32768, 2.0, 262144, 0.04, 0.04) == (
        "Pattern extrapolated CPU cost at cap (262144 chars) is 0.328s, exceeding "
        "the 0.05s safety budget (growth ratio 2.00x per doubling, CPU time at "
        "32000 chars: min 0.0400s, median 0.0400s over 5 runs, normalized by host "
        "load factor 1.00)"
    )


def test_cap_32000_reason_is_the_base_text() -> None:
    assert _reach_probe_cost_reason(None, 0.0501, 5.01, 32000, 0.0501, 0.0501) == (
        "Pattern extrapolated CPU cost at cap (32000 chars) is 0.050s, exceeding "
        "the 0.05s safety budget (growth ratio 5.01x per doubling, CPU time at "
        "32000 chars: min 0.0501s, median 0.0501s over 5 runs, normalized by host "
        "load factor 1.00)"
    )


@pytest.mark.parametrize("cap", [12000, 20000, 512])
def test_below_32000_the_reason_names_the_size_actually_measured(cap: int) -> None:
    reason = _reach_probe_cost_reason(None, 0.06, 2.0, cap, 0.06, 0.06)
    assert f"CPU time at {cap} chars" in reason
    assert "32000" not in reason
    assert "extrapolated" not in reason


@pytest.mark.parametrize("structural_violation", [None, "nested quantifier"])
def test_below_32000_only_cap_over_2_and_cap_are_timed(
    monkeypatch: pytest.MonkeyPatch, structural_violation: str | None
) -> None:
    calls, reason = _recorded_probe_sets(monkeypatch, 12000, 0.06, structural_violation)

    assert calls == [["probe-6000", "probe-12000"]] * 2
    assert reason is not None


@pytest.mark.parametrize("cap", [32000, 262144])
def test_cap_32000_and_above_time_the_16000_and_32000_probes(
    monkeypatch: pytest.MonkeyPatch, cap: int
) -> None:
    calls, reason = _recorded_probe_sets(monkeypatch, cap, 0.001)

    assert calls == [["probe-16000", "probe-32000"]]
    assert reason is None


@pytest.mark.parametrize("structural_violation", [None, "nested quantifier"])
@pytest.mark.parametrize("bounded_repeat_risk", [False, True])
def test_probe_sizes_below_32000_never_exceed_the_cap(
    structural_violation: str | None, bounded_repeat_risk: bool
) -> None:
    sizes = _reach_probe_sizes_for_strategy(
        structural_violation, bounded_repeat_risk, 12000
    )
    assert sizes == (6000, 12000)


def test_probe_sizes_at_32000_and_above_are_unchanged() -> None:
    assert _reach_probe_sizes_for_strategy(None, False, 32000) == (16000, 32000)
    assert _reach_probe_sizes_for_strategy("x", False, 262144) == (
        4000,
        8000,
        16000,
        32000,
    )
    assert _reach_probe_sizes_for_strategy(None, True, 262144) == (
        4000,
        8000,
        16000,
        32000,
    )


def test_below_32000_the_budget_decides_at_the_cap_through_the_arbiter(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _calls, accepted = _recorded_probe_sets(monkeypatch, 12000, 0.0499)
    _calls, rejected = _recorded_probe_sets(monkeypatch, 12000, 0.0501)

    assert accepted is None
    assert rejected is not None
    assert "CPU time at 12000 chars" in rejected


def _spans_handed_to(recorder: MagicMock) -> list[int]:
    return [
        call.args[2] - call.args[1]
        for call in recorder.search.call_args_list + recorder.match.call_args_list
    ]


@pytest.mark.parametrize("length", [100, 511, 512, 513, 5000, 262144])
@pytest.mark.parametrize("pattern", [r"a+", r"zzz", r"a{600}"])
def test_user_agent_scan_never_hands_the_pattern_more_than_the_validated_cap(
    pattern: str, length: int
) -> None:
    recorder = MagicMock(spec=re.Pattern, wraps=re.compile(pattern))

    _search_user_agent_windows(recorder, "a" * length)

    spans = _spans_handed_to(recorder)
    assert spans
    assert max(spans) <= _MAX_USER_AGENT_MATCH_LENGTH


class _CapRecorder:
    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.caps: list[int | None] = []

        def record(
            _compiler: PatternCompiler,
            _pattern: str,
            test_strings: list[str] | None = None,
            max_content_length: int | None = None,
            flags: int = 0,
        ) -> tuple[bool, str]:
            self.caps.append(max_content_length)
            return True, "ok"

        monkeypatch.setattr(PatternCompiler, "validate_pattern_safety", record)


class _Decorators(ContentFilteringMixin):
    def __init__(self, config: SecurityConfig) -> None:
        self.config = config


def test_block_user_agents_decorator_cap_covers_the_user_agent_scan_window(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    recorder = _CapRecorder(monkeypatch)
    config = SecurityConfig(detection_max_body_inspect_bytes=_MIN_BODY_INSPECT_BYTES)

    _Decorators(config).block_user_agents(["abc"])

    assert recorder.caps == [config.detection_max_body_inspect_bytes]
    assert _MAX_USER_AGENT_MATCH_LENGTH <= _MIN_BODY_INSPECT_BYTES
    with pytest.raises(ValueError, match="detection_max_body_inspect_bytes"):
        SecurityConfig(detection_max_body_inspect_bytes=_MIN_BODY_INSPECT_BYTES - 1)


class _DynamicRules(DynamicRulePlanMixin):
    def __init__(self) -> None:
        self.config = SecurityConfig()


async def test_dynamic_rule_user_agent_validation_cap_covers_the_scan_window(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    recorder = _CapRecorder(monkeypatch)

    valid = await _DynamicRules()._validate_user_agents(
        DynamicRulePlan(state={}),
        DynamicRules(
            rule_id="r",
            version=1,
            timestamp=datetime.now(timezone.utc),
            blocked_user_agents=["abc"],
        ),
    )

    assert valid == ["abc"]
    assert recorder.caps == [_MAX_USER_AGENT_MATCH_LENGTH]


@pytest.fixture(params=[True, False])
def body_cap_manager(request: pytest.FixtureRequest) -> Iterator[SusPatternsManager]:
    saved_instance = SusPatternsManager._instance
    saved_config = SusPatternsManager._config
    saved_global = sph.sus_patterns_handler

    SusPatternsManager._instance = None
    manager = SusPatternsManager(
        SecurityConfig(
            detection_max_body_inspect_bytes=_MIN_BODY_INSPECT_BYTES,
            detection_max_file_inspect_bytes=_MIN_BODY_INSPECT_BYTES,
            detection_preserve_attack_patterns=request.param,
        )
    )
    sph.sus_patterns_handler = manager

    yield manager

    SusPatternsManager._instance = saved_instance
    SusPatternsManager._config = saved_config
    sph.sus_patterns_handler = saved_global


_HOSTILE_BODIES = (
    "A" * 50000,
    "<script>alert(1)</script> " * 4000,
    " ".join(["UNION SELECT 1,2,3 -- x"] * 3000),
    "QUJDREVGR0hJSktM " * 5000,
    "%3Cscript%3E" * 8000,
    ("/* c */ SELECT " + "x" * 90) * 600,
)


async def test_add_pattern_cap_covers_every_view_the_scan_hands_to_patterns(
    monkeypatch: pytest.MonkeyPatch, body_cap_manager: SusPatternsManager
) -> None:
    recorder = _CapRecorder(monkeypatch)
    await body_cap_manager.add_pattern(r"abc", custom=True)
    assert recorder.caps == [_MIN_BODY_INSPECT_BYTES]
    cap = recorder.caps[0]
    assert cap is not None

    preprocessor = body_cap_manager._preprocessor
    assert preprocessor is not None
    for body in _HOSTILE_BODIES:
        processed, decoded = await preprocessor.preprocess_with_decoded(body)
        views = [
            processed,
            preprocessor.preprocess_signal_preserving(body),
            await preprocessor.preprocess_url_decoded_newline_preserving(body),
            preprocessor.truncate_safely(decoded),
            preprocessor.preprocess_comment_dropped_view(decoded, processed) or "",
            preprocessor.preprocess_short_base64_additive_view(body),
        ]
        assert [len(view) for view in views if len(view) > cap] == []


async def test_batch_compile_forwards_the_callers_cap_to_the_validator(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    recorder = _CapRecorder(monkeypatch)

    await PatternCompiler().batch_compile(["abc", "def"], max_content_length=12000)

    assert recorder.caps == [12000, 12000]


async def test_add_pattern_cap_follows_a_raised_file_inspect_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    saved_instance = SusPatternsManager._instance
    saved_config = SusPatternsManager._config
    SusPatternsManager._instance = None
    raised = _MIN_BODY_INSPECT_BYTES * 8
    manager = SusPatternsManager(
        SecurityConfig(
            detection_max_body_inspect_bytes=_MIN_BODY_INSPECT_BYTES,
            detection_max_file_inspect_bytes=raised,
        )
    )
    recorder = _CapRecorder(monkeypatch)

    try:
        await manager.add_pattern(r"abc", custom=True)
        window = manager._preprocessor
    finally:
        SusPatternsManager._instance = saved_instance
        SusPatternsManager._config = saved_config

    assert recorder.caps == [raised]
    assert window is not None
    assert window._MAX_FULL_SCAN_BYTES == raised
