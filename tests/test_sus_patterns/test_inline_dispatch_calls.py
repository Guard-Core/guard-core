import re
import sys
import time
from collections.abc import Callable

import pytest

from guard_core.handlers._suspatterns_inline_matches import _INLINE_FINDERS
from guard_core.handlers._suspatterns_lazy_rows import COMPILED_BUILTIN_PATTERNS
from guard_core.handlers.suspatterns_handler import SusPatternsManager

_ELIGIBLE_PREFIX = r"\A[/\\]?(?:[\w.\-~%]+[/\\])*wp-content[/\\]uploads[/\\]?"
_BENIGN = "hello world"


def _builtin_row(predicate: Callable[[str], bool]) -> re.Pattern:
    for source, _contexts, _category in SusPatternsManager()._pattern_definitions:
        if predicate(source):
            return COMPILED_BUILTIN_PATTERNS[source]
    raise AssertionError("no builtin row matches")


async def _python_calls_into(row: re.Pattern, content: str) -> int:
    calls = 0

    def profile(frame: object, event: str, _arg: object) -> None:
        nonlocal calls
        code = getattr(frame, "f_code", None)
        if (
            event == "call"
            and code is not None
            and code.co_name == "__call__"
            and code.co_filename.endswith("_suspatterns_inline_matches.py")
        ):
            calls += 1

    manager = SusPatternsManager()
    sys.setprofile(profile)
    try:
        await manager._check_regex_pattern(
            row, content, "203.0.113.9", time.monotonic(), "recon"
        )
    finally:
        sys.setprofile(None)
    return calls


@pytest.mark.asyncio
async def test_a_row_without_an_inline_finder_never_enters_the_inline_helper() -> None:
    row = _builtin_row(lambda source: _INLINE_FINDERS[source] is None)
    assert await _python_calls_into(row, _BENIGN) == 0


@pytest.mark.asyncio
async def test_a_row_with_an_inline_finder_enters_the_inline_helper_once() -> None:
    row = _builtin_row(lambda source: source.startswith(_ELIGIBLE_PREFIX))
    assert _INLINE_FINDERS[row.pattern] is not None
    assert await _python_calls_into(row, "/wp-content/uploads/x.php") == 1


def test_a_custom_pattern_with_a_builtin_text_does_not_take_the_builtin_finder() -> (
    None
):
    builtin = _builtin_row(lambda source: source.startswith(_ELIGIBLE_PREFIX))
    custom = re.compile(builtin.pattern)
    assert custom is not builtin
    inline = _INLINE_FINDERS[builtin.pattern]
    assert inline is not None
    assert inline.flags == builtin.flags
    assert inline("/wp-content/uploads/x", custom) is None
