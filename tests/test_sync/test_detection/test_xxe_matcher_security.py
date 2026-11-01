import itertools
import json
import random
import re
import subprocess
import sys

import pytest

from guard_core.sync.handlers._suspatterns_scan_windows import (
    _SCAN_WINDOW_PATTERNS,
    _iter_scan_window_matches,
)
from guard_core.sync.handlers._suspatterns_xml_xxe import (
    _XML_XXE_PUBLIC_EXTERNAL_DTD_COMPILED_RE,
    _xml_xxe_public_external_dtd_finditer,
)


@pytest.mark.parametrize(
    "source",
    [
        r"<!(?:ENTITY|DOCTYPE)[^>]+SYSTEM[^>]+>",
        r"<!DOCTYPE[^>\[]*\[[\s\S]*?<!ENTITY",
    ],
)
def test_xml_structural_finders_preserve_raw_spans(source: str) -> None:
    rng = random.Random(9305)
    compiled = re.compile(source, re.IGNORECASE)
    tokens = [
        "<!DOCTYPE",
        "<!ENTITY",
        "SYSTEM",
        "system",
        "[",
        "]",
        ">",
        "x",
        " ",
        "\n",
    ]
    for _ in range(6000):
        text = "".join(rng.choices(tokens, k=rng.randrange(1, 40)))
        expected = [m.span() for m in compiled.finditer(text)]
        actual = [
            m.span()
            for m in _iter_scan_window_matches(
                text, compiled, _SCAN_WINDOW_PATTERNS[source]
            )
        ]
        assert actual == expected, (text, actual, expected)


@pytest.mark.parametrize("gap", [" ", "\t", "\n", "x", "  "])
def test_xxe_preserves_minimum_public_gap(gap: str) -> None:
    text = f'<!DOCTYPE x PUBLIC{gap}"http://evil/x">'
    compiled = _XML_XXE_PUBLIC_EXTERNAL_DTD_COMPILED_RE
    assert compiled.search(text) is not None
    assert [
        m.group() for m in _xml_xxe_public_external_dtd_finditer(text, compiled)
    ] == [text]


def test_xxe_scanner_matches_original_language() -> None:
    rng = random.Random(9302)
    compiled = _XML_XXE_PUBLIC_EXTERNAL_DTD_COMPILED_RE
    tokens = [
        "<!DOCTYPE",
        "PUBLIC",
        "public",
        "http://",
        "https://",
        "w3.org/",
        "www.w3.org/",
        "evil/",
        "x",
        '"',
        "'",
        "<",
        ">",
        "[",
        "]",
        " ",
        "\n",
    ]
    cases = [
        f"<!DOCTYPE{left}PUBLIC{gap}{quote}http://{body}{quote}{tail}>"
        for left, gap, quote, body, tail in itertools.product(
            ["", " ", "x PUBLIC "],
            ["", " ", ' "id" '],
            ['"', "'"],
            ["", "evil/x", "w3.org/x", "<x", "[x", '">x', "PUBLIC x"],
            ["", " ", "[", "PUBLIC"],
        )
    ]
    cases.extend(
        "".join(rng.choices(tokens, k=rng.randrange(2, 40))) for _ in range(3000)
    )
    for text in cases:
        matches = list(_xml_xxe_public_external_dtd_finditer(text, compiled))
        expected = list(compiled.finditer(text))
        assert [(m.span(), m.group()) for m in matches] == [
            (m.span(), m.group()) for m in expected
        ], repr(text)


def test_xxe_reports_the_earliest_viable_doctype() -> None:
    text = '<!DOCTYPE a <!DOCTYPE b PUBLIC "http://evil/x">'
    compiled = _XML_XXE_PUBLIC_EXTERNAL_DTD_COMPILED_RE
    matches = list(_xml_xxe_public_external_dtd_finditer(text, compiled))
    assert [(m.span(), m.group()) for m in matches] == [((0, len(text)), text)]


@pytest.mark.redos_timing
def test_xxe_closed_url_keyword_flood_is_bounded() -> None:
    module = __name__.rsplit(".", 1)[0] + "._xxe_matcher_security_probe"
    completed = subprocess.run(
        [sys.executable, "-m", module],
        capture_output=True,
        text=True,
        timeout=30,
        check=True,
    )
    timings = json.loads(completed.stdout)
    for shape, samples in timings.items():
        assert max(samples) < 0.1, (shape, samples)
        assert samples[-1] < max(0.01, samples[-2] * 3), (shape, samples)
