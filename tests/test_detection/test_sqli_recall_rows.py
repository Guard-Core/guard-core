import pytest

from guard_core.handlers._suspatterns_pattern_table import _PATTERN_DEFINITIONS
from guard_core.handlers.suspatterns_handler import (
    _BUILTIN_PATTERN_COMPILE_FLAGS,
    sus_patterns_handler,
)
from guard_core.models import SecurityConfig
from guard_core.utils import detect_penetration_attempt
from tests.conftest import MockGuardRequest

ATTACKS = [
    "1and sleep(5)",
    "1AND SLEEP(5)--",
    "1 and sleep(5)",
    "pg_sleep(5)--",
    "' or pg_sleep(5)--",
    "'||pg_sleep(5)--",
    "pg_SLEEP(5)#",
    "1) or pg_sleep(5)--",
    "or sleep(0.5)",
    "' UNION SELECT",
    "' UNION ALL SELECT",
    "\\x27UNION SELECT",
    "') UNION SELECT--",
    "1 UNION SELECT",
    '" UNION SELECT',
]
BENIGN = [
    "benchmark results for sleep(5) function docs",
    "the band sleep(5) tour",
    "use sleep(5) to wait",
    "chapter 1 union select committee",
    "how to union select two tables",
    "union select",
]


@pytest.fixture(autouse=True)
def _force_enhanced_detection_singleton() -> None:
    sus_patterns_handler.configure(SecurityConfig())


async def _flagged(value: str) -> bool:
    request = MockGuardRequest(path="/search", query_params={"q": value})
    return (await detect_penetration_attempt(request, SecurityConfig())).is_threat


@pytest.mark.parametrize("value", ATTACKS)
async def test_sleep_and_union_forms_v440_flags_are_flagged_again(value: str) -> None:
    assert await _flagged(value) is True


@pytest.mark.parametrize("value", BENIGN)
async def test_sleep_and_union_prose_stays_clean(value: str) -> None:
    assert await _flagged(value) is False


@pytest.mark.redos_timing
def test_the_restored_rows_pass_the_redos_validator() -> None:
    from guard_core.detection_engine.compiler import PatternCompiler

    compiler = PatternCompiler()
    rows = [
        pattern
        for pattern, _context, category in _PATTERN_DEFINITIONS
        if category == "sqli" and ("SLEEP" in pattern or "UNION" in pattern)
    ]
    assert len(rows) >= 3
    assert all(
        compiler.validate_pattern_safety(row, flags=_BUILTIN_PATTERN_COMPILE_FLAGS)[0]
        for row in rows
    )
