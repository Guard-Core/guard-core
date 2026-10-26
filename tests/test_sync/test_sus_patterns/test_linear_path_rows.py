import json
import random
import re
import time
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest

from guard_core.sync.handlers._suspatterns_lazy_rows import COMPILED_BUILTIN_PATTERNS
from guard_core.sync.handlers._suspatterns_linear_path import linear_path_finder
from guard_core.sync.handlers._suspatterns_literals import (
    required_literals,
    rows_with_required_literal,
)
from guard_core.sync.handlers._suspatterns_regex import _LITERAL_EXCLUDED_SOURCES
from guard_core.sync.handlers.suspatterns_handler import SusPatternsManager

_FIXTURE_CASES = Path(__file__).parents[2] / "specs" / "fixtures" / "cases"
_RANDOM_STRINGS_PER_ROW = 2000
_VOCABULARY = [
    "a",
    "%",
    "..",
    ".",
    "-",
    "~",
    "x.php",
    "config.yml",
    ".env",
    ".git",
    "wp-content",
    "uploads",
    "files",
    "tmp",
    "?q=1",
    "?",
    " ",
    "\n",
    "\x00",
    ";",
    "::$DATA",
    "é",
    "_",
    "0",
    "x.map",
    "cgi-bin",
    "phpinfo.php",
    "docker-compose.yml",
]
_SUFFIXES = [
    ".php",
    ".php/x",
    ".php?a=1",
    ".json",
    ".asp",
    ".yml",
    ".py",
    ".map",
    ".bak",
    "~",
    "/uploads/x.php",
    ".git/HEAD",
    ".env",
]
_SEEDS = [
    "/files/x/shell.php",
    "/uploads/a/shell.php?q",
    "/tmp/y/z/cmd.php",
    "/media/shell.php",
    "/upload/x/cmd.php",
    "/images/q/uploads/files/cmd.php",
    "x/etc/passwd;",
    "etc/passwd",
    "a\netc/passwd ",
    "xx/var/log/foo&",
    "/proc/self/environ",
    "C:\\boot.ini\x00",
    "/system/a/b?q",
    "/version/x//y ",
    "/system",
    "scan x/etc/shadow ",
    "q=1&f=../../etc/passwd\n",
    "a/b/phpunit/src/Util/PHP/eval-stdin.php",
    "phpunit/x/y/src/Util/PHP/eval-stdin.php?q=1 ",
    "wp-content/uploads/",
    "a/wp-content/uploads/b/c/d.php",
    "/x/wp-content/uploads//",
    "wp-content/uploads/uploads/wp-content/uploads/x.php",
    "a/.openclaw",
    "a/.openclaw/b?x",
    "a/.git/refs",
    "x/.git/HEAD/",
    "a/b.c~",
    "a/b/c.d~?q ",
    "a/b/x.asp;",
    "a/b.bak",
    "/a/b/secrets.json",
    "a/b/credentials.yaml/",
    "x/y/moroccan_spamers.php",
    "a/b/0byt3m1n1.php",
    "/uploads/a/b/log.php",
    "/files/x/1.php",
    "a/b/c99.php",
    "a/.git;x/y",
    "/.git;ab?c",
    "local_settings.py;a;b/c",
    ".htaccess;;?;x",
    "a/b/wp-content;x?y",
    "a/b/wp-login.php;jsessionid=1",
    "a/b/x.php.",
    "a/b/x.php::$DATA",
    "a/b/x.php%00.jpg",
    "/a/b/x.map",
    "\\a\\b\\x.php",
    "a//b/x.php",
    "/",
    "",
]


def _eligible_rows() -> list[re.Pattern]:
    rows = []
    for source, _contexts, _category in SusPatternsManager()._pattern_definitions:
        compiled = COMPILED_BUILTIN_PATTERNS[source]
        if linear_path_finder(compiled) is not None and compiled not in rows:
            rows.append(compiled)
    return rows


def _fixture_strings() -> list[str]:
    found: set[str] = set()

    def walk(node: object) -> None:
        if isinstance(node, str):
            found.add(node)
        elif isinstance(node, dict):
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)

    for case_file in sorted(_FIXTURE_CASES.glob("*.json")):
        walk(json.loads(case_file.read_text()))
    return sorted(value for value in found if len(value) < 4000)


def _row_strings(source: str, generator: random.Random) -> list[str]:
    runs = re.findall(
        r"[A-Za-z0-9_.\-/ ]{4,}",
        source.replace("\\.", ".").replace("[/\\\\]", "/"),
    )
    vocabulary = _VOCABULARY + re.findall(r"[A-Za-z0-9_.\-]{2,}", source)[:40] + runs
    strings = list(_SEEDS)
    for _ in range(_RANDOM_STRINGS_PER_ROW):
        parts = []
        for _part in range(generator.randint(1, 9)):
            token = generator.choice(vocabulary)
            if generator.random() < 0.5:
                token += generator.choice(_SUFFIXES)
            parts.append(token)
            parts.append(generator.choice(["/", "/", "\\", "//", "", " ", "\n", ";"]))
        value = generator.choice(["", "/", "\\"]) + "".join(parts)
        for _mutation in range(generator.randint(0, 2)):
            if value:
                at = generator.randrange(len(value))
                value = (
                    value[:at]
                    + generator.choice(_VOCABULARY + ["/", "\\"])
                    + value[at + generator.randint(0, 1) :]
                )
        strings.append(value)
    return strings


def _signature(match: re.Match) -> tuple:
    return (
        match.span(),
        tuple(match.span(index) for index in range(1, (match.re.groups or 0) + 1)),
        match.string,
        tuple(sorted(match.re.groupindex)),
        match.group(),
    )


_ROWS = _eligible_rows()
_CORPUS = _fixture_strings()


def test_the_path_family_is_converted() -> None:
    assert len(_ROWS) >= 50


@pytest.mark.parametrize("row", _ROWS, ids=[row.pattern[:50] for row in _ROWS])
def test_linear_finder_yields_the_regex_matches(row: re.Pattern) -> None:
    finder = linear_path_finder(row)
    assert finder is not None
    generator = random.Random(20261026)
    both_match = 0
    for value in [*_row_strings(row.pattern, generator), *_CORPUS]:
        expected = [_signature(match) for match in row.finditer(value)]
        assert [_signature(match) for match in finder(value)] == expected, value
        both_match += bool(expected)
    assert both_match >= 1


@pytest.mark.parametrize("row", _ROWS, ids=[row.pattern[:50] for row in _ROWS])
def test_converted_rows_keep_their_required_literal_gate(row: re.Pattern) -> None:
    assert row.pattern not in _LITERAL_EXCLUDED_SOURCES
    kept = rows_with_required_literal(
        [(row, frozenset(), "x")], "zzz", _LITERAL_EXCLUDED_SOURCES
    )
    assert bool(list(kept)) == (not required_literals(row.pattern))


def _finder_cpu_seconds(
    finder: Callable[[str], Iterator[re.Match]], value: str
) -> float:
    best = float("inf")
    for _ in range(3):
        started = time.process_time()
        list(finder(value))
        best = min(best, time.process_time() - started)
    return best


@pytest.mark.parametrize(
    ("unit", "tail"),
    [
        ("%/", ""),
        ("a/", ""),
        ("/-/", ""),
        ("x.php/", "\x01"),
        ("wp-content/uploads/x.php/", "\x01"),
        (".git/", "\x01"),
    ],
)
def test_the_linear_finder_scales_linearly_with_the_value(unit: str, tail: str) -> None:
    small = (unit * 40000)[: 65536 - len(tail)] + tail
    large = (unit * 140000)[: 262144 - len(tail)] + tail
    for row in _ROWS:
        finder = linear_path_finder(row)
        assert finder is not None
        small_cpu = _finder_cpu_seconds(finder, small)
        large_cpu = _finder_cpu_seconds(finder, large)
        assert large_cpu <= max(0.1, 9 * small_cpu), (row.pattern[:50], unit)
