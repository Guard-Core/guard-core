import re
from collections.abc import Iterator

import pytest

from guard_core.models import SecurityConfig
from guard_core.sync.handlers.suspatterns_handler import SusPatternsManager

_FCK_PATH = "/" + "fckeditor/editor/filemanager/" * 250


@pytest.fixture
def fresh_manager() -> Iterator[SusPatternsManager]:
    previous_instance, previous_config = (
        SusPatternsManager._instance,
        SusPatternsManager._config,
    )
    SusPatternsManager._instance = None
    SusPatternsManager._config = None
    try:
        yield SusPatternsManager(SecurityConfig())
    finally:
        SusPatternsManager._instance = previous_instance
        SusPatternsManager._config = previous_config


def test_new_manager_compiles_no_builtin_row(
    fresh_manager: SusPatternsManager,
) -> None:
    assert fresh_manager._compiled_rows is None
    assert fresh_manager._compiled_builtin_rows == {}


def test_first_detect_compiles_only_the_rows_it_searches(
    fresh_manager: SusPatternsManager,
) -> None:
    fresh_manager.detect(
        content=_FCK_PATH, ip_address="198.51.100.4", context="url_path"
    )

    assert fresh_manager._compiled_rows is None
    assert (
        0
        < len(fresh_manager._compiled_builtin_rows)
        < len(SusPatternsManager._pattern_definitions)
    )


def test_reading_compiled_patterns_gives_every_row_in_definition_order(
    fresh_manager: SusPatternsManager,
) -> None:
    fresh_manager.detect(
        content=_FCK_PATH, ip_address="198.51.100.4", context="url_path"
    )
    searched_row = next(iter(fresh_manager._compiled_builtin_rows.values()))

    rows = fresh_manager.compiled_patterns

    assert [(row[0].pattern, row[1], row[2]) for row in rows] == [
        (re.compile(source, re.IGNORECASE).pattern, contexts, category)
        for source, contexts, category in SusPatternsManager._pattern_definitions
    ]
    assert searched_row in rows
    assert fresh_manager.compiled_patterns is rows


def test_detect_verdict_is_the_same_before_and_after_the_rows_are_read(
    fresh_manager: SusPatternsManager,
) -> None:
    lazy = fresh_manager.detect(
        content=_FCK_PATH, ip_address="198.51.100.4", context="url_path"
    )
    assert fresh_manager.compiled_patterns
    eager = fresh_manager.detect(
        content=_FCK_PATH, ip_address="198.51.100.4", context="url_path"
    )

    assert lazy["is_threat"] == eager["is_threat"]
    assert [t["pattern"] for t in lazy["threats"]] == [
        t["pattern"] for t in eager["threats"]
    ]


def test_assigned_rows_replace_the_lazy_rows(
    fresh_manager: SusPatternsManager,
) -> None:
    assigned: list[tuple[re.Pattern, frozenset[str], str]] = []

    fresh_manager.compiled_patterns = assigned

    assert fresh_manager.compiled_patterns is assigned


def test_custom_row_is_searched_beside_uncompiled_builtin_rows(
    fresh_manager: SusPatternsManager,
) -> None:
    assert SusPatternsManager.add_pattern(r"zzcustomtoken\d+", custom=True)

    result = fresh_manager.detect(
        content="/zzcustomtoken123", ip_address="198.51.100.4", context="url_path"
    )

    assert result["is_threat"] is True
    assert fresh_manager._compiled_rows is None
