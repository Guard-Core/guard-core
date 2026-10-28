import re
import time
from collections.abc import AsyncGenerator, Iterator
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

import pytest

from guard_core._utils import detection_scan
from guard_core._utils._scan_outcomes import ScanBudgetSpent
from guard_core._utils.detection_scan import _scan_value_budget
from guard_core.handlers import _suspatterns_regex as regex_module
from guard_core.handlers._suspatterns_shell_sources import (
    _GLUED_DOLLAR_SUBSTITUTION_CANDIDATE_RE,
)
from guard_core.handlers.suspatterns_handler import (
    SusPatternsManager,
    sus_patterns_handler,
)
from guard_core.models import SecurityConfig

_DOLLAR_ROW = re.compile(_GLUED_DOLLAR_SUBSTITUTION_CANDIDATE_RE)
_CANDIDATES = 30
_REJECTED_CANDIDATES = "$(a) " * _CANDIDATES


@pytest.fixture(autouse=True)
async def _reset_suspatterns_singleton() -> AsyncGenerator[None, None]:
    original_instance = SusPatternsManager._instance
    original_config = SusPatternsManager._config

    SusPatternsManager._instance = None
    SusPatternsManager._config = None

    yield

    SusPatternsManager._instance = original_instance
    SusPatternsManager._config = original_config


@pytest.fixture
def one_second_per_cpu_read() -> Iterator[None]:
    ticks = iter(float(tick) for tick in range(1_000_000))
    with patch.object(detection_scan, "_thread_cpu_seconds", lambda: next(ticks)):
        yield


@pytest.fixture
def slice_elapsed_every_candidate() -> Iterator[None]:
    start = time.monotonic()
    clock = iter(start + tick * 0.01 for tick in range(1_000_000))
    with patch.object(
        regex_module, "time", SimpleNamespace(monotonic=lambda: next(clock))
    ):
        yield


@pytest.mark.usefixtures("one_second_per_cpu_read", "slice_elapsed_every_candidate")
async def test_candidate_loop_ends_the_scan_once_the_budget_is_spent() -> None:
    manager = SusPatternsManager()
    manager.configure(SecurityConfig(enable_redis=False))
    judged = {"count": 0}
    real_build = regex_module._build_regex_threat

    def counting_build(*args: Any, **kwargs: Any) -> Any:
        judged["count"] += 1
        return real_build(*args, **kwargs)

    with (
        _scan_value_budget(512, max_scan_seconds=0.1),
        patch.object(regex_module, "_build_regex_threat", counting_build),
        pytest.raises(ScanBudgetSpent),
    ):
        mark = detection_scan._open_cpu_pass()
        try:
            await manager._check_regex_pattern(
                _DOLLAR_ROW, _REJECTED_CANDIDATES, "127.0.0.1", 0.0, "cmd_injection"
            )
        finally:
            detection_scan._close_cpu_pass(mark)

    assert judged["count"] < _CANDIDATES


@pytest.mark.usefixtures("one_second_per_cpu_read", "slice_elapsed_every_candidate")
async def test_pattern_loop_reports_a_spent_candidate_loop_as_incomplete() -> None:
    manager = SusPatternsManager()
    manager.configure(SecurityConfig(enable_redis=False))
    judged = {"count": 0}
    real_build = regex_module._build_regex_threat

    def counting_build(*args: Any, **kwargs: Any) -> Any:
        judged["count"] += 1
        return real_build(*args, **kwargs)

    with (
        _scan_value_budget(512, max_scan_seconds=0.1),
        patch.object(regex_module, "_build_regex_threat", counting_build),
    ):
        result = await manager.detect(_REJECTED_CANDIDATES, "127.0.0.1", "request_body")

    assert "scan_time_budget_exhausted" in result["timeouts"]
    assert result["is_threat"] is True
    assert judged["count"] < _CANDIDATES


async def test_fallback_check_ends_in_the_budget_outcome() -> None:
    async def spent(*args: Any, **kwargs: Any) -> tuple[None, bool]:
        raise ScanBudgetSpent

    with patch.object(sus_patterns_handler, "_check_regex_pattern", spent):
        detected, trigger = await detection_scan._fallback_pattern_check(
            "hello", "127.0.0.1", "query_param:q"
        )

    assert detected is True
    assert trigger == "Scan time budget exhausted (fallback)"
