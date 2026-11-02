import json
import random
import re
import sys
import time
from collections.abc import Callable

import pytest

from guard_core.sync.detection_engine.compiler import PatternCompiler
from guard_core.sync.handlers import _suspatterns_matchers as matchers
from guard_core.sync.handlers._suspatterns_sources import _SSTI_HASH_BRACE_SHAPE_RE
from guard_core.sync.handlers._suspatterns_state import _LEGACY_DETECTION_STATE
from guard_core.sync.handlers.suspatterns_handler import SusPatternsManager
from tests.probe_child import run_probe_child

_Scanner = Callable[[str, re.Pattern], list[re.Match]]
_CASES = [
    (
        "hash_brace",
        _SSTI_HASH_BRACE_SHAPE_RE,
        matchers._template_hash_brace_scan_matches,
        "#{",
        "}",
        "7*7",
    ),
    (
        "curly_keyword",
        matchers._TEMPLATE_CURLY_KEYWORD_RE,
        matchers._template_curly_keyword_scan_matches,
        "{{",
        "}}",
        " xsystem ",
    ),
    (
        "percent_keyword",
        matchers._TEMPLATE_PERCENT_KEYWORD_RE,
        matchers._template_percent_keyword_scan_matches,
        "{%",
        "%}",
        " xsystem ",
    ),
    (
        "dollar_brace",
        matchers._TEMPLATE_DOLLAR_BRACE_CALL_RE,
        matchers._template_dollar_brace_scan_matches,
        "${",
        "}",
        "7*7",
    ),
    (
        "curly_call",
        matchers._TEMPLATE_CURLY_CALL_RE,
        matchers._template_curly_call_scan_matches,
        "{{",
        "}}",
        "7*7",
    ),
    (
        "asp_keyword",
        matchers._TEMPLATE_ASP_KEYWORD_RE,
        matchers._template_asp_keyword_scan_matches,
        "<%",
        "%>",
        "7*7",
    ),
]
_PARAMETERS = ("label", "source", "scanner", "opening", "closing", "attack")
_TOKENS = [
    "#{",
    "{{",
    "}}",
    "${",
    "}",
    "{%",
    "%}",
    "<%",
    "%>",
    "system",
    "include",
    "ſystem",
    "ıo.",
    "exec",
    "eval",
    "popen",
    "File.",
    "Dir.",
    "@java.lang@",
    "@...@",
    "1",
    "11",
    "2024-01-01",
    "1111-11-1111-11-11",
    "7*7",
    "foo()",
    "x",
    " ",
    "\n",
    "\t",
    "\u2003",
    "'",
    '"',
    "(",
    ")",
    "@",
    "+",
    "-",
    "*",
    "/",
    "%",
    "{",
    "=",
    "#",
    "١",
]


def test_asp_overlapping_opener_does_not_repeat_an_accepted_frame() -> None:
    text = "<%exec<%>foo%><%eval%>"
    compiled = re.compile(matchers._TEMPLATE_ASP_KEYWORD_RE, re.I)
    expected = [m.span() for m in compiled.finditer(text)]
    actual = [
        m.span() for m in matchers._template_asp_keyword_scan_matches(text, compiled)
    ]
    assert actual == expected


@pytest.mark.parametrize(_PARAMETERS, _CASES, ids=[row[0] for row in _CASES])
@pytest.mark.parametrize("flags", [0, re.I, re.I | re.ASCII])
def test_template_scanner_preserves_raw_spans_and_groups(
    label: str,
    source: str,
    scanner: _Scanner,
    opening: str,
    closing: str,
    attack: str,
    flags: int,
) -> None:
    compiled = re.compile(source, flags)
    rng = random.Random(9301)
    hits = 0
    for trial in range(3000):
        text = "".join(rng.choices(_TOKENS, k=rng.randrange(1, 35)))
        if trial % 3 == 0:
            text = opening + attack + closing + text
        raw = [(m.span(), m.group(), m.groups()) for m in compiled.finditer(text)]
        actual = [(m.span(), m.group(), m.groups()) for m in scanner(text, compiled)]
        assert actual == raw, (label, flags, text, raw, actual)
        hits += bool(raw)
    assert hits >= 1000


@pytest.mark.parametrize(_PARAMETERS, _CASES, ids=[row[0] for row in _CASES])
@pytest.mark.parametrize("fill", [" ", "1", "@.", "\u2003"])
def test_template_scanner_preserves_uncapped_padding(
    label: str,
    source: str,
    scanner: _Scanner,
    opening: str,
    closing: str,
    attack: str,
    fill: str,
) -> None:
    compiled = re.compile(source, re.I)
    payload = opening + fill * 16384 + attack + closing
    text = "prefix " + payload + " gap " + payload
    actual = scanner(text, compiled)
    expected = [(7, 7 + len(payload)), (12 + len(payload), len(text))]
    assert [m.span() for m in actual] == expected, label
    assert [m.group() for m in actual] == [payload, payload], label


@pytest.mark.parametrize(
    ("source", "scanner", "text", "expected"),
    [
        (
            matchers._TEMPLATE_PERCENT_KEYWORD_RE,
            matchers._template_percent_keyword_scan_matches,
            "{% harmless {%} xsystem%}",
            [(12, 25)],
        ),
        (
            matchers._TEMPLATE_ASP_KEYWORD_RE,
            matchers._template_asp_keyword_scan_matches,
            "<% harmless <%> 7*7%>",
            [(12, 21)],
        ),
        (
            matchers._TEMPLATE_CURLY_CALL_RE,
            matchers._template_curly_call_scan_matches,
            "{{2024-01-01 {{7*7}}",
            [(13, 20)],
        ),
        (
            matchers._TEMPLATE_CURLY_CALL_RE,
            matchers._template_curly_call_scan_matches,
            "{{1111-11-1111-11-11 7*7}}",
            [],
        ),
        (
            matchers._TEMPLATE_CURLY_KEYWORD_RE,
            matchers._template_curly_keyword_scan_matches,
            "{{system}} {{ system}}",
            [(11, 22)],
        ),
    ],
)
def test_template_scanner_handles_delimiter_overlap_and_date_exclusions(
    source: str, scanner: _Scanner, text: str, expected: list[tuple[int, int]]
) -> None:
    compiled = re.compile(source, re.I)
    assert [m.span() for m in compiled.finditer(text)] == expected
    assert [m.span() for m in scanner(text, compiled)] == expected


@pytest.mark.parametrize(_PARAMETERS, _CASES, ids=[row[0] for row in _CASES])
@pytest.mark.parametrize("enhanced", [False, True], ids=["legacy", "enhanced"])
def test_template_registry_precedes_regex_fallback_without_a_scan_cap(
    label: str,
    source: str,
    scanner: _Scanner,
    opening: str,
    closing: str,
    attack: str,
    enhanced: bool,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    del label, scanner
    manager = SusPatternsManager()
    compiler = PatternCompiler() if enhanced else None
    state = _LEGACY_DETECTION_STATE._replace(compiler=compiler)

    def unexpected_legacy_fallback(
        *_args: object, **_kwargs: object
    ) -> tuple[dict | None, bool]:
        raise AssertionError("template patterns must not use raw regex fallback")

    def unexpected_enhanced_fallback(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("template patterns must not use compiler fallback")

    if compiler is None:
        monkeypatch.setattr(
            SusPatternsManager,
            "_check_regex_pattern_with_retry",
            unexpected_legacy_fallback,
        )
    else:
        monkeypatch.setattr(
            compiler, "create_async_safe_finditer_matcher", unexpected_enhanced_fallback
        )

    payload = opening + " " * 16384 + attack + closing
    content = "prefix " + payload
    pattern = re.compile(source, re.I)
    threat, timed_out = manager._check_regex_pattern(
        pattern,
        content,
        "203.0.113.9",
        time.monotonic(),
        "template",
        state=state,
    )

    assert timed_out is False
    assert threat is not None
    assert threat["category"] == "template"
    assert threat["match"] == payload
    assert threat["position"] == len("prefix ")


@pytest.mark.redos_timing
@pytest.mark.parametrize("label", [row[0] for row in _CASES])
def test_template_closed_and_open_frames_have_bounded_cpu_growth(label: str) -> None:
    module = __name__.rsplit(".", 1)[0] + "._template_matcher_security_probe"
    result = run_probe_child([sys.executable, "-m", module, label], 45)
    assert result.returncode == 0, (result.stdout, result.stderr)
    timings: dict[str, list[float]] = json.loads(result.stdout)
    assert set(timings) == {
        "closed_whitespace",
        "closed_digits",
        "closed_words",
        "closed_at_dots",
        "closed_quotes_digits",
        "earlier_attack_digit_suffix",
        "repeated_prefix_closed",
        "repeated_prefix_open",
    }
    for shape, times in timings.items():
        assert len(times) == 4
        assert 0 < times[-1] < 0.1, (label, shape, times)
        consecutive = 0
        for earlier, later in zip(times, times[1:], strict=False):
            consecutive = consecutive + 1 if later > 3.5 * max(earlier, 0.001) else 0
            assert consecutive < 2, (label, shape, times)
