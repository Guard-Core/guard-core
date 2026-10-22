import re
import time

import pytest

from guard_core.handlers._suspatterns_shell_sources import _GLOB_WILDCARD_ATOM_RE
from guard_core.handlers._suspatterns_sources import (
    _RECON_EXTENSION_PATH_RE,
    _SENSITIVE_SOURCE_EXTENSION_PATH_RE,
    path_only_extension_tail_is_valid,
)
from guard_core.handlers.suspatterns_handler import _BUILTIN_PATTERN_COMPILE_FLAGS

_ADMINER_SEGMENT = "adminer.php/"
_CKFINDER_SEGMENT = "ckfinder/core/connector/php/connector.php/"


def _repeated(segment: str, tail: str) -> str:
    return "/" + segment * (58_000 // len(segment)) + tail


@pytest.mark.parametrize("tail", ["", " x", "@", "?q x", "?a=b c"])
@pytest.mark.parametrize(
    ("pattern", "segment"),
    [
        (_SENSITIVE_SOURCE_EXTENSION_PATH_RE, _ADMINER_SEGMENT),
        (_SENSITIVE_SOURCE_EXTENSION_PATH_RE, "admin/"),
        (_RECON_EXTENSION_PATH_RE, "x.aspx/"),
        (_GLOB_WILDCARD_ATOM_RE, _ADMINER_SEGMENT),
        (_GLOB_WILDCARD_ATOM_RE, _CKFINDER_SEGMENT),
    ],
    ids=[
        "sensitive-adminer",
        "sensitive-plain",
        "recon",
        "glob-adminer",
        "glob-ckfinder",
    ],
)
def test_a_row_scans_a_repeated_segment_input_in_linear_time(
    pattern: str, segment: str, tail: str
) -> None:
    row = re.compile(pattern, _BUILTIN_PATTERN_COMPILE_FLAGS)
    path = _repeated(segment, tail)
    started = time.process_time()
    match = row.search(path)
    if pattern != _GLOB_WILDCARD_ATOM_RE and match is not None:
        path_only_extension_tail_is_valid(match)
    elapsed = time.process_time() - started
    # linear cost: under 6 ms on an Apple silicon Mac, CPython 3.10; quadratic: 1 s+
    assert elapsed < 0.05


@pytest.mark.parametrize(
    ("path", "matches"),
    [
        ("/adminer.php", True),
        ("/adminer.php/x/y?q=1 ", True),
        ("/a/b/adminer.php;x=1/c", True),
        ("/a.php/b.php;x=1/c", True),
        ("/a.php%00b.php=x/y", True),
        ("/a.php.php", True),
        ("/a.php.jpg", True),
        ("/a.php::$DATA", True),
        ("/adminer.php?q x", False),
        ("/adminer.php@", False),
        ("/adminer.phpx", False),
        ("/a.php=x/y", False),
        ("//a.php", False),
        ("/a//b.php", False),
        ("/a.php/b x", False),
        ("/q?a.php", False),
    ],
)
def test_the_extension_row_keeps_its_verdict(path: str, matches: bool) -> None:
    row = re.compile(
        _SENSITIVE_SOURCE_EXTENSION_PATH_RE, _BUILTIN_PATTERN_COMPILE_FLAGS
    )
    match = row.search(path)
    assert (match is not None and path_only_extension_tail_is_valid(match)) is matches


@pytest.mark.parametrize(
    ("text", "spans"),
    [
        ("cat /etc/pass?d", [(4, 15)]),
        ("a b", []),
        ("x*y z?", [(0, 3), (4, 6)]),
        ("é*", [(1, 2)]),
    ],
)
def test_the_glob_row_still_matches_each_wildcard_run_from_its_start(
    text: str, spans: list[tuple[int, int]]
) -> None:
    row = re.compile(_GLOB_WILDCARD_ATOM_RE, _BUILTIN_PATTERN_COMPILE_FLAGS)
    assert [match.span() for match in row.finditer(text)] == spans
