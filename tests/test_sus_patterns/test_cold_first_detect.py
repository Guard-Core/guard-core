import os
import re
import subprocess
import sys
import time
from pathlib import Path

import pytest

import guard_core
from guard_core.handlers import _suspatterns_linear_path
from guard_core.handlers._suspatterns_inline_matches import (
    _BUILTIN_ROW_FLAGS,
    linear_row_finds_nothing,
)
from guard_core.handlers._suspatterns_lazy_rows import (
    COMPILED_BUILTIN_PATTERNS,
    _SourceRow,
)
from guard_core.handlers._suspatterns_linear_mandatory_table import (
    BUILTIN_MANDATORY_CHARACTERS,
)
from guard_core.handlers._suspatterns_linear_path import _LinearPathRow, _row_for
from guard_core.handlers._suspatterns_linear_path_source import (
    mandatory_characters,
    mandatory_key,
    row_pieces,
)
from guard_core.handlers._suspatterns_literals import parse_required_literals
from guard_core.handlers._suspatterns_pattern_table import _PATTERN_DEFINITIONS
from guard_core.handlers.suspatterns_handler import SusPatternsManager

REPO_ROOT = Path(guard_core.__file__).resolve().parent.parent
_TEXTS = [
    "",
    "Quarterly report for the finance team: revenue grew while churn fell.",
    "/",
    "/wp-config.php",
    "a/b/.env",
    "x/.git/HEAD",
    "/uploads/x/shell.php?q=1",
    "wp-content/uploads/",
    "a/b/c99.php",
    "docker-compose.yml",
    "report.map",
    "a/b/x.php::$DATA",
]


def _linear_row_sources() -> list[str]:
    return [
        source
        for source, _contexts, _category in _PATTERN_DEFINITIONS
        if _row_for(source, _BUILTIN_ROW_FLAGS) is not None
    ]


def _the_rows_tail_piece(source: str) -> str:
    row = _row_for(source, _BUILTIN_ROW_FLAGS)
    assert row is not None
    return row._raw_pieces[-1]


def _the_first_giant_source() -> str:
    return max(_linear_row_sources(), key=len)


def test_a_config_without_redis_has_no_connection_key_and_imports_no_redis() -> None:
    code = (
        "import sys\n"
        "from guard_core._utils.app_managers import _connection_key_of\n"
        "from guard_core.models import SecurityConfig\n"
        "print(_connection_key_of(SecurityConfig()), 'redis' in sys.modules)\n"
    )
    env = dict(os.environ)
    env["PYTHONPATH"] = f"{REPO_ROOT}{os.pathsep}{env.get('PYTHONPATH', '')}"

    result = subprocess.run(
        [sys.executable, "-W", "ignore", "-c", code],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
        check=True,
    )

    assert result.stdout.strip() == "None False"


def test_a_linear_row_compiles_nothing_until_a_text_needs_it() -> None:
    source = _the_first_giant_source()
    split = row_pieces(source)
    assert split is not None

    row = _LinearPathRow(_BUILTIN_ROW_FLAGS, *split, source)

    assert not {"_guards", "_tests", "_mandatory"} & vars(row).keys()
    assert not list(row.find("Quarterly report"))
    assert {"_guards", "_tests", "_mandatory"} <= vars(row).keys()


def test_every_linear_row_is_compiled_with_the_flags_the_rows_are_keyed_by() -> None:
    for source in _linear_row_sources():
        assert re.compile(source, re.IGNORECASE).flags == _BUILTIN_ROW_FLAGS


def test_a_linear_row_with_no_match_is_known_without_compiling_its_regex() -> None:
    for source in _linear_row_sources():
        for text in _TEXTS:
            expected = re.compile(source, re.IGNORECASE).search(text) is None
            assert linear_row_finds_nothing(source, text) is expected, (source, text)


def test_a_source_that_is_not_a_linear_row_is_never_reported_empty() -> None:
    assert not linear_row_finds_nothing(r"\d+\.php", "x")
    assert not linear_row_finds_nothing("not a builtin row", "x")


@pytest.mark.asyncio
async def test_scanning_a_clean_value_leaves_a_linear_row_uncompiled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = _the_first_giant_source()
    monkeypatch.delitem(COMPILED_BUILTIN_PATTERNS, source, raising=False)

    threat, timed_out = await SusPatternsManager()._check_regex_pattern(
        _SourceRow(source),
        "Quarterly report",
        "203.0.113.9",
        time.monotonic(),
        "sensitive_file",
    )

    assert (threat, timed_out) == (None, False)
    assert source not in COMPILED_BUILTIN_PATTERNS


@pytest.mark.asyncio
async def test_scanning_a_matching_value_compiles_the_row_and_flags_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = _the_first_giant_source()
    monkeypatch.delitem(COMPILED_BUILTIN_PATTERNS, source, raising=False)

    threat, _timed_out = await SusPatternsManager()._check_regex_pattern(
        _SourceRow(source),
        "/uploads/0byt3m1n1.php",
        "203.0.113.9",
        time.monotonic(),
        "recon",
    )

    assert threat is not None
    assert source in COMPILED_BUILTIN_PATTERNS


def test_the_mandatory_table_is_the_parse_of_every_builtin_linear_row() -> None:
    expected = {}
    for source in _linear_row_sources():
        piece = _the_rows_tail_piece(source)
        expected[mandatory_key(piece, _BUILTIN_ROW_FLAGS)] = tuple(
            tuple(sorted(group))
            for group in mandatory_characters(piece, _BUILTIN_ROW_FLAGS)
        )

    assert BUILTIN_MANDATORY_CHARACTERS == expected


def test_a_builtin_linear_row_needs_no_parse_for_its_mandatory_characters(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        _suspatterns_linear_path,
        "mandatory_characters",
        lambda *_args: pytest.fail("parsed a builtin row"),
    )
    for source in _linear_row_sources():
        split = row_pieces(source)
        assert split is not None
        row = _LinearPathRow(_BUILTIN_ROW_FLAGS, *split, source)
        assert row._mandatory == tuple(
            map(
                frozenset,
                BUILTIN_MANDATORY_CHARACTERS[
                    mandatory_key(row._raw_pieces[-1], _BUILTIN_ROW_FLAGS)
                ],
            )
        )


def test_a_custom_linear_row_parses_its_mandatory_characters() -> None:
    source = r"\A[/\\]?(?:[\w.\-~%]+[/\\])*(?:foo|bar)\.php\Z"
    split = row_pieces(source)
    assert split is not None

    row = _LinearPathRow(_BUILTIN_ROW_FLAGS, *split, source)

    assert row._mandatory == mandatory_characters(row._raw_pieces[-1], row._flags)
    assert row._mandatory
    assert not list(row.find("a/b/baz.txt"))
    assert list(row.find("a/b/foo.php"))


def test_a_two_character_run_with_punctuation_is_a_required_literal() -> None:
    assert parse_required_literals(r"\$\{[^}]+\}") == ("${",)
    assert parse_required_literals(r"(?i)O:\d+:") == ("o:",)
    assert parse_required_literals(r"ab\d+cd") == ()
