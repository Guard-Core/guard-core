import re
from collections.abc import Iterator

import pytest

from guard_core.handlers._suspatterns_inline_matches import _INLINE_FINDERS
from guard_core.handlers._suspatterns_lazy_rows import COMPILED_BUILTIN_PATTERNS
from guard_core.handlers.suspatterns_handler import SusPatternsManager
from guard_core.models import SecurityConfig

_FCK_PATH = "/" + "fckeditor/editor/filemanager/" * 250


@pytest.fixture
def fresh_manager() -> Iterator[SusPatternsManager]:
    previous_instance, previous_config = (
        SusPatternsManager._instance,
        SusPatternsManager._config,
    )
    SusPatternsManager._instance = None
    SusPatternsManager._config = None
    previous_rows, previous_finders = (
        dict(COMPILED_BUILTIN_PATTERNS),
        dict(_INLINE_FINDERS),
    )
    COMPILED_BUILTIN_PATTERNS.clear()
    try:
        yield SusPatternsManager(SecurityConfig())
    finally:
        SusPatternsManager._instance = previous_instance
        SusPatternsManager._config = previous_config
        COMPILED_BUILTIN_PATTERNS.clear()
        COMPILED_BUILTIN_PATTERNS.update(previous_rows)
        _INLINE_FINDERS.clear()
        _INLINE_FINDERS.update(previous_finders)


def test_new_manager_compiles_no_builtin_row(
    fresh_manager: SusPatternsManager,
) -> None:
    assert "compiled_patterns" not in vars(fresh_manager)
    assert not COMPILED_BUILTIN_PATTERNS


@pytest.mark.asyncio
async def test_first_detect_compiles_only_the_rows_it_searches(
    fresh_manager: SusPatternsManager,
) -> None:
    await fresh_manager.detect(
        content=_FCK_PATH, ip_address="198.51.100.4", context="url_path"
    )

    assert "compiled_patterns" not in vars(fresh_manager)
    assert (
        0
        < len(COMPILED_BUILTIN_PATTERNS)
        < len(SusPatternsManager._pattern_definitions)
    )


@pytest.mark.asyncio
async def test_reading_compiled_patterns_gives_every_row_in_definition_order(
    fresh_manager: SusPatternsManager,
) -> None:
    await fresh_manager.detect(
        content=_FCK_PATH, ip_address="198.51.100.4", context="url_path"
    )
    searched_pattern = next(iter(COMPILED_BUILTIN_PATTERNS.values()))

    rows = fresh_manager.compiled_patterns

    assert [(row[0].pattern, row[1], row[2]) for row in rows] == [
        (re.compile(source, re.IGNORECASE).pattern, contexts, category)
        for source, contexts, category in SusPatternsManager._pattern_definitions
    ]
    assert any(row[0] is searched_pattern for row in rows)
    assert fresh_manager.compiled_patterns is rows


@pytest.mark.asyncio
async def test_detect_verdict_is_the_same_before_and_after_the_rows_are_read(
    fresh_manager: SusPatternsManager,
) -> None:
    lazy = await fresh_manager.detect(
        content=_FCK_PATH, ip_address="198.51.100.4", context="url_path"
    )
    assert fresh_manager.compiled_patterns
    eager = await fresh_manager.detect(
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


@pytest.mark.asyncio
async def test_custom_row_is_searched_beside_uncompiled_builtin_rows(
    fresh_manager: SusPatternsManager,
) -> None:
    assert await SusPatternsManager.add_pattern(r"zzcustomtoken\d+", custom=True)

    result = await fresh_manager.detect(
        content="/zzcustomtoken123", ip_address="198.51.100.4", context="url_path"
    )

    assert result["is_threat"] is True
    assert "compiled_patterns" not in vars(fresh_manager)
