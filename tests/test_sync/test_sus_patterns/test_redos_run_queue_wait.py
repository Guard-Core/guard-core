import time
from types import SimpleNamespace

import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.sync.detection_engine import _redos_cost_arbiter as arbiter
from guard_core.sync.detection_engine.compiler import PatternCompiler

_QUADRATIC_UA_PATTERN = r"(?:foo|bar)+$"
_USER_AGENT_CAP = 512
_SECONDS_THE_RUN_QUEUE_KEEPS_THE_PROBES_WAITING = 1000.0


def _wall_clock_jumps_once_the_probes_start_waiting(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    skew = [0.0]
    real_monotonic = time.monotonic
    real_remaining_budget = arbiter._remaining_budget
    monkeypatch.setattr(
        arbiter,
        "time",
        SimpleNamespace(monotonic=lambda: real_monotonic() + skew[0]),
    )

    def remaining_budget_then_wait(deadline: float) -> float:
        remaining = real_remaining_budget(deadline)
        skew[0] += _SECONDS_THE_RUN_QUEUE_KEEPS_THE_PROBES_WAITING
        return remaining

    monkeypatch.setattr(arbiter, "_remaining_budget", remaining_budget_then_wait)


@pytest.mark.redos_timing
def test_validator_accepts_a_valid_pattern_when_the_run_queue_eats_the_wall_clock(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _wall_clock_jumps_once_the_probes_start_waiting(monkeypatch)
    is_safe, reason = PatternCompiler().validate_pattern_safety(
        _QUADRATIC_UA_PATTERN, max_content_length=_USER_AGENT_CAP
    )
    assert is_safe is True, reason


@pytest.mark.redos_timing
def test_security_config_builds_when_the_run_queue_eats_the_wall_clock(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _wall_clock_jumps_once_the_probes_start_waiting(monkeypatch)
    config = SyncSecurityConfig(blocked_user_agents=[_QUADRATIC_UA_PATTERN])
    assert config.blocked_user_agents == [_QUADRATIC_UA_PATTERN]
