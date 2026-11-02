import re
from collections.abc import Generator
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.sync.handlers import _suspatterns_regex as regex_module
from guard_core.sync.handlers import _suspatterns_shell_sources as shell_sources
from guard_core.sync.handlers import _suspatterns_shell_validators as validators
from guard_core.sync.handlers._suspatterns_shell_sources import (
    _GLOB_WILDCARD_ATOM_RE,
    _GLUED_DOLLAR_SUBSTITUTION_CANDIDATE_RE,
    _glob_wildcard_scan_matches,
)
from guard_core.sync.handlers.suspatterns_handler import SusPatternsManager

_DOLLAR_ROW = re.compile(_GLUED_DOLLAR_SUBSTITUTION_CANDIDATE_RE)
_GLOB_ROW = re.compile(_GLOB_WILDCARD_ATOM_RE)
_UNITS = 1000


@pytest.fixture(autouse=True)
def _reset_suspatterns_singleton() -> Generator[None, None]:
    original_instance = SusPatternsManager._instance
    original_config = SusPatternsManager._config

    SusPatternsManager._instance = None
    SusPatternsManager._config = None

    yield

    SusPatternsManager._instance = original_instance
    SusPatternsManager._config = original_config


class _ExaminedCounter:
    def __init__(self, regex: re.Pattern[str]) -> None:
        self._regex = regex
        self.examined = 0

    def search(self, string: str, pos: int = 0, endpos: int | None = None) -> Any:
        stop = len(string) if endpos is None else min(endpos, len(string))
        found = self._regex.search(string, pos, stop)
        self.examined += (stop if found is None else found.end()) - max(pos, 0)
        return found

    def match(self, string: str, pos: int = 0, endpos: int | None = None) -> Any:
        stop = len(string) if endpos is None else min(endpos, len(string))
        found = self._regex.match(string, pos, stop)
        self.examined += 1 if found is None else found.end() - pos
        return found


def _examined_by_dollar_validator(units: int) -> int:
    table = shell_sources._PATTERNS
    prefix = _ExaminedCounter(table["_STRONG_SQL_KEYWORD_GLUED_WINDOW_PREFIX_RE"])
    suffix = _ExaminedCounter(table["_STRONG_SQL_KEYWORD_GLUED_WINDOW_SUFFIX_RE"])
    delimiter = _ExaminedCounter(table["_BACKTICK_WINDOW_DELIMITER_RE"])
    counters = {
        "_STRONG_SQL_KEYWORD_GLUED_WINDOW_PREFIX_RE": prefix,
        "_STRONG_SQL_KEYWORD_GLUED_WINDOW_SUFFIX_RE": suffix,
        "_BACKTICK_WINDOW_DELIMITER_RE": delimiter,
    }
    with patch.dict(table, counters):
        for match in _DOLLAR_ROW.finditer("$(a) " * units):
            validators._dollar_substitution_pair_is_injection(match, "unknown")
    return prefix.examined + suffix.examined + delimiter.examined


def _examined_by_glob_validator(units: int) -> int:
    name = "_GLOB_WILDCARD_COMMAND_BOUNDARY_PREFIX_RE"
    boundary = _ExaminedCounter(validators._PATTERNS[name])
    with patch.dict(validators._PATTERNS, {name: boundary}):
        for match in _glob_wildcard_scan_matches("<?php " * units, _GLOB_ROW):
            validators._glob_wildcard_token_is_dangerous_command(match, "unknown")
    return boundary.examined


def test_dollar_substitution_validator_examines_a_bounded_window_per_match() -> None:
    one = _examined_by_dollar_validator(_UNITS)
    two = _examined_by_dollar_validator(2 * _UNITS)

    assert one > 0
    assert two <= 2.5 * one


def test_glob_wildcard_validator_examines_a_bounded_window_per_match() -> None:
    one = _examined_by_glob_validator(_UNITS)
    two = _examined_by_glob_validator(2 * _UNITS)

    assert two <= 2.5 * one


def test_strong_sql_keyword_before_a_match_ignores_a_keyword_across_a_line_break() -> (
    None
):
    content = "order\nby$(a)"
    start = content.index("$(")

    assert not validators._strong_sql_keyword_glued_to_pair(
        content, start, len(content)
    )
    spaced = "x order \t by$(a)"
    assert validators._strong_sql_keyword_glued_to_pair(
        spaced, spaced.index("$("), len(spaced)
    )


@pytest.mark.parametrize(
    ("content", "expected"),
    [
        ("select$(a)", True),
        ("xselect$(a)", False),
        ("GROUP   BY$(a)", True),
        ("GROUP`  BY$(a)", False),
        ("$(a)from", True),
        ("$(a)ORDER\nBY", False),
        ("$(a)ORDER  BY", True),
    ],
)
def test_strong_sql_keyword_beside_a_match_keeps_its_verdict(
    content: str, expected: bool
) -> None:
    match = _DOLLAR_ROW.search(content)
    assert match is not None

    assert (
        validators._strong_sql_keyword_glued_to_pair(
            content, match.start(), match.end()
        )
        is expected
    )


@pytest.mark.parametrize(
    ("content", "context", "expected"),
    [
        ("; ls*", "unknown", True),
        ("x ls*", "unknown", False),
        ("ls*", "request_body", True),
        ("  \t ls*", "request_body", True),
        ("ls*", "unknown", False),
        ("a && c?t ", "unknown", True),
        ("$(  c?t ", "unknown", True),
        ("a || c?t ", "unknown", True),
        ("&c?t ", "unknown", False),
    ],
)
def test_glob_wildcard_validator_keeps_its_verdict(
    content: str, context: str, expected: bool
) -> None:
    matches = _glob_wildcard_scan_matches(content, _GLOB_ROW)
    assert matches

    assert (
        validators._glob_wildcard_token_is_dangerous_command(matches[-1], context)
        is expected
    )


def test_candidate_loop_charges_the_budget_and_yields_between_candidates() -> None:
    manager = SusPatternsManager()
    manager.configure(SyncSecurityConfig(enable_redis=False))
    clock = iter(x * 0.01 for x in range(1_000_000))
    yields = {"count": 0}
    charges = {"count": 0}
    real_yield = regex_module._yield_to_event_loop
    real_charge = regex_module._charge_inline_cpu

    def counting_yield() -> None:
        yields["count"] += 1
        real_yield()

    def counting_charge() -> None:
        charges["count"] += 1
        real_charge()

    fake_time = SimpleNamespace(monotonic=lambda: next(clock))
    with (
        patch.object(regex_module, "time", fake_time),
        patch.object(regex_module, "_yield_to_event_loop", counting_yield),
        patch.object(regex_module, "_charge_inline_cpu", counting_charge),
    ):
        threat, timed_out = manager._check_regex_pattern(
            _DOLLAR_ROW, "$(a) " * 30, "127.0.0.1", 0.0, "cmd_injection"
        )

    assert threat is None
    assert timed_out is False
    assert yields["count"] >= 25
    assert charges["count"] >= 25
