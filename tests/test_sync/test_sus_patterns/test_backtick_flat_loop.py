import random
import re
import time
import tracemalloc

import pytest

from guard_core.sync.handlers._suspatterns_linear_path_source import flattened
from guard_core.sync.handlers._suspatterns_path_code_execution import (
    _BACKTICK_WHOLE_VALUE_COMPILED_RE,
    _GLUED_BACKTICK_CANDIDATE_COMPILED_RE,
)
from guard_core.sync.handlers._suspatterns_pattern_table import BACKTICK_WHOLE_VALUE_RE
from guard_core.sync.handlers._suspatterns_shell_sources import (
    _GLUED_BACKTICK_CANDIDATE_RE,
)
from guard_core.sync.handlers.suspatterns_handler import SusPatternsManager

_TOKENS = [
    "`",
    "`",
    "\\",
    "\\`",
    "\\\n",
    "\n",
    " ",
    ";",
    "&",
    "|",
    "$(",
    "${",
    "ls",
    "a",
    ".",
    "/",
    "~",
    "\t",
]
_SOURCES = [BACKTICK_WHOLE_VALUE_RE, _GLUED_BACKTICK_CANDIDATE_RE]
_MEMORY_SLACK_BYTES = 5 * 1024 * 1024
_SIZE = 262144


def _structured_text(rng: random.Random) -> str:
    pairs = []
    for _ in range(rng.randint(1, 4)):
        body = "".join(rng.choice(_TOKENS) for _ in range(rng.randint(0, 6)))
        pairs.append("`" + rng.choice(["ls", "a", "$(", "\n", " x", "."]) + body + "`")
    glue = rng.choice(["", " ", ";", "&", " ; ", "|", "\n"])
    return (
        rng.choice(["", " ", ";"]) + glue.join(pairs) + rng.choice(["", " ", ";", "x"])
    )


def _signature(match: re.Match) -> tuple:
    return (match.span(), match.regs, match.string, match.group())


def _all_matches(compiled: re.Pattern, text: str) -> list[tuple]:
    return [_signature(match) for match in compiled.finditer(text)]


@pytest.mark.parametrize("source", _SOURCES)
def test_the_flat_backtick_loop_yields_the_same_matches_as_the_row_text(
    source: str,
) -> None:
    flat_source = flattened(source)
    assert flat_source != source
    original = re.compile(source, re.IGNORECASE)
    flat = re.compile(flat_source, re.IGNORECASE)
    rng = random.Random(1391)
    hits = 0
    for _ in range(40000):
        text = (
            _structured_text(rng)
            if rng.random() < 0.6
            else "".join(rng.choice(_TOKENS) for _ in range(rng.randint(0, 24)))
        )
        expected = _all_matches(original, text)
        assert _all_matches(flat, text) == expected
        hits += bool(expected)
    assert hits > 1500


def test_the_compiled_helpers_use_the_flat_loop_with_the_same_flags() -> None:
    assert _BACKTICK_WHOLE_VALUE_COMPILED_RE.pattern == flattened(
        BACKTICK_WHOLE_VALUE_RE
    )
    assert _GLUED_BACKTICK_CANDIDATE_COMPILED_RE.pattern == flattened(
        _GLUED_BACKTICK_CANDIDATE_RE
    )
    assert (
        _BACKTICK_WHOLE_VALUE_COMPILED_RE.flags
        == re.compile(BACKTICK_WHOLE_VALUE_RE).flags
    )


@pytest.mark.parametrize("unit", ["`.`&", "`a`;", "`.\\`.`|", "`x`&`y`;"])
@pytest.mark.parametrize("source", [_GLUED_BACKTICK_CANDIDATE_RE])
def test_a_256_kb_backtick_body_costs_a_backtick_row_at_most_5_mb(
    source: str, unit: str
) -> None:
    from guard_core.sync.handlers._suspatterns_lazy_rows import (
        COMPILED_BUILTIN_PATTERNS,
    )

    manager = SusPatternsManager()
    content = (unit * (_SIZE // len(unit) + 1))[:_SIZE]
    tracemalloc.start()
    try:
        manager._check_regex_pattern(
            COMPILED_BUILTIN_PATTERNS[source],
            content,
            "203.0.113.9",
            time.monotonic(),
            "cmd_injection",
        )
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    assert peak <= _MEMORY_SLACK_BYTES
