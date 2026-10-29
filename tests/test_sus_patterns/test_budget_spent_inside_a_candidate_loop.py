import re
import time
from collections.abc import AsyncGenerator
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

import pytest

from guard_core._utils import detection_scan
from guard_core._utils.detection_scan import _scan_value_budget
from guard_core.handlers import _suspatterns_regex as regex_module
from guard_core.handlers._suspatterns_shell_sources import (
    _GLUED_DOLLAR_SUBSTITUTION_CANDIDATE_RE,
)
from guard_core.handlers.suspatterns_handler import SusPatternsManager
from guard_core.models import SecurityConfig

_DOLLAR_ROW = re.compile(_GLUED_DOLLAR_SUBSTITUTION_CANDIDATE_RE)
_CANDIDATES = 30
_REJECTED_CANDIDATES = "$(a) " * _CANDIDATES
_CPU_SECONDS_PER_JUDGED_CANDIDATE = 0.05


@pytest.fixture(autouse=True)
async def _reset_suspatterns_singleton() -> AsyncGenerator[None, None]:
    original_instance = SusPatternsManager._instance
    original_config = SusPatternsManager._config

    SusPatternsManager._instance = None
    SusPatternsManager._config = None

    yield

    SusPatternsManager._instance = original_instance
    SusPatternsManager._config = original_config


async def test_a_budget_spent_inside_one_rows_candidates_ends_the_whole_pass() -> None:
    cpu_clock = [0.0]
    start = time.monotonic()
    wall = iter(start + tick * 0.01 for tick in range(1_000_000))
    manager = SusPatternsManager()
    manager.configure(SecurityConfig(enable_redis=False))
    judged = {"count": 0}
    real_build = regex_module._build_regex_threat

    def counting_build(*args: Any, **kwargs: Any) -> Any:
        judged["count"] += 1
        cpu_clock[0] += _CPU_SECONDS_PER_JUDGED_CANDIDATE
        return real_build(*args, **kwargs)

    with (
        patch.object(detection_scan, "_thread_cpu_seconds", lambda: cpu_clock[0]),
        patch.object(
            regex_module, "time", SimpleNamespace(monotonic=lambda: next(wall))
        ),
        _scan_value_budget(512, max_scan_seconds=0.12),
        patch.object(regex_module, "_build_regex_threat", counting_build),
    ):
        threats, matched, timeouts = await manager._check_regex_patterns(
            _REJECTED_CANDIDATES, "127.0.0.1", None, "request_body"
        )

    assert 0 < judged["count"] < _CANDIDATES
    assert "scan_time_budget_exhausted" in timeouts
    assert "scan_time_budget_exhausted" in matched
    assert any(threat["type"] == "pattern_timeout" for threat in threats)
