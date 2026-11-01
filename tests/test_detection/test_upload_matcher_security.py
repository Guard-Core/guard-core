import itertools
import json
import math
import random
import re
import statistics
import subprocess
import sys

import pytest

from guard_core.handlers import _suspatterns_matchers as matchers

_SOURCES = [
    matchers._FILE_UPLOAD_DANGEROUS_EXTENSION_RE,
    matchers._FILE_UPLOAD_DOUBLE_EXTENSION_RE,
    matchers._FILE_UPLOAD_TRUNCATION_RE,
    matchers._FILE_UPLOAD_DECODED_TRUNCATION_RE,
]
_UPLOAD_SIZES = [16384, 32768, 65536, 131072]
_UPLOAD_SHAPES = {
    f"{index}:{label}"
    for index in range(4)
    for label in ("single_quoted_fields", "extension_decoys", "newline_prefix")
}


def _upload_timing_violations(rounds: list[list[float]]) -> list[str]:
    if len(rounds) != 5:
        return [f"expected 5 rounds, got {len(rounds)}: {rounds!r}"]
    if any(
        len(round_samples) != len(_UPLOAD_SIZES)
        or not all(
            isinstance(value, (int, float)) and math.isfinite(value) and value >= 0
            for value in round_samples
        )
        for round_samples in rounds
    ):
        return [f"malformed timing rounds: {rounds!r}"]
    per_size_medians = [
        statistics.median(
            rounds[round_index][size_index] for round_index in range(len(rounds))
        )
        for size_index in range(len(rounds[0]))
    ]
    violations = [
        f"absolute budget exceeded: {per_size_medians}"
        if max(per_size_medians) >= 0.05
        else ""
    ]
    per_size_minima = [
        min(round_samples[size_index] for round_samples in rounds)
        for size_index in range(len(rounds[0]))
    ]
    growth_ratio = per_size_minima[-1] / max(0.01, per_size_minima[-2] * 3)
    if growth_ratio >= 1.0:
        violations.append(f"growth budget exceeded: {growth_ratio}")
    return [violation for violation in violations if violation]


def test_upload_scanner_rejects_an_unrecognized_pattern() -> None:
    assert (
        matchers._file_upload_scan_matches('filename="x.php"', re.compile(r"filename"))
        == []
    )


@pytest.mark.redos_timing
def test_upload_repeated_fields_and_extensions_remain_bounded() -> None:
    module = __name__.rsplit(".", 1)[0] + "._upload_matcher_security_probe"
    result = subprocess.run(
        [sys.executable, "-m", module],
        capture_output=True,
        text=True,
        timeout=30,
        check=True,
    )
    measured = json.loads(result.stdout)
    assert set(measured) == _UPLOAD_SHAPES, measured
    for shape, rounds in measured.items():
        assert not _upload_timing_violations(rounds), (shape, rounds)


def test_upload_timing_assessment_uses_fixed_sample_lower_bound() -> None:
    correlated = [
        [scale * value for value in (0.004, 0.008, 0.016, 0.032)]
        for scale in (1.0, 2.0, 0.5, 1.5, 0.75)
    ]
    assert _upload_timing_violations(correlated) == []

    noisy_observations = [
        [0.0015, 0.003, 0.006, 0.019],
        [0.0015, 0.003, 0.006, 0.012],
        [0.00275, 0.0055, 0.011, 0.022],
        [0.00275, 0.0055, 0.011, 0.022],
        [0.0015, 0.003, 0.006, 0.012],
    ]
    assert _upload_timing_violations(noisy_observations) == []
    assert statistics.median(row[-1] for row in noisy_observations) >= max(
        0.01, statistics.median(row[-2] for row in noisy_observations) * 3
    )

    fourfold_growth = [[0.002, 0.004, 0.008, 0.032]] * 5
    assert any(
        "growth" in violation
        for violation in _upload_timing_violations(fourfold_growth)
    )

    inflated_penultimate = [
        [0.002, 0.004, 0.08, 0.032],
        [0.002, 0.004, 0.008, 0.032],
        [0.002, 0.004, 0.08, 0.032],
        [0.002, 0.004, 0.08, 0.032],
        [0.002, 0.004, 0.08, 0.032],
    ]
    assert any(
        "growth" in violation
        for violation in _upload_timing_violations(inflated_penultimate)
    )


@pytest.mark.parametrize(
    ("rounds", "violation"),
    (
        ([[0.001, 0.002, 0.008, 0.024]] * 5, "growth"),
        ([[0.001, 0.002, 0.003, 0.01]] * 5, "growth"),
        ([[0.01, 0.02, 0.03, 0.05]] * 5, "absolute"),
        (
            [[0.01, 0.02, 0.03, final] for final in (0.06, 0.06, 0.001, 0.06, 0.06)],
            "absolute",
        ),
    ),
)
def test_upload_timing_assessment_rejects_exact_budget_boundaries(
    rounds: list[list[float]], violation: str
) -> None:
    assert any(violation in message for message in _upload_timing_violations(rounds))


@pytest.mark.parametrize(
    "rounds",
    (
        [],
        [[0.001, 0.002, 0.003]] * 5,
        [[0.001, 0.002, 0.003, float("nan")]] * 5,
        [[0.001, 0.002, 0.003, -0.001]] * 5,
    ),
)
def test_upload_timing_assessment_rejects_malformed_rounds(
    rounds: list[list[float]],
) -> None:
    assert _upload_timing_violations(rounds)


@pytest.mark.parametrize("source", _SOURCES)
def test_upload_structural_scanner_preserves_raw_language(source: str) -> None:
    compiled = re.compile(source, re.IGNORECASE)
    bodies = [
        "x.com",
        "x.php",
        "x.php.jpg",
        "x.phar.jpg",
        "x.PHP00.jpg",
        "x.php.",
        "x.php%00.jpg",
        r"x.php\u0000.jpg",
        r"x.php\U0000.jpg",
        r"x.php\x00.jpg",
        r"x.php\X00.jpg",
        "x.php\x00.jpg",
        "x.php;.jpg",
        "x.txt",
        "x.php txt.jpg",
        "x.php\ntxt.jpg",
        "x.phpſ.jpg",
    ]
    cases = [
        f"{prefix}filename{gap}={gap}{quote}{body}{closing}"
        for prefix, gap, quote, body, closing in itertools.product(
            ["", " ", "\n", "x\n ", "x ", "; "],
            ["", " ", "\t", "\u2003"],
            ['"', "'"],
            bodies,
            ['"', "'"],
        )
    ]
    rng = random.Random(9304)
    tokens = ["filename", '"', "'", ".php", ".com", ".jpg", "=", ";", "\n", " ", "%00"]
    cases.extend("".join(rng.choices(tokens, k=25)) for _ in range(1500))
    for text in cases:
        expected = [(m.span(), m.group()) for m in compiled.finditer(text)]
        actual = [
            (m.span(), m.group())
            for m in matchers._file_upload_scan_matches(text, compiled)
        ]
        assert actual == expected, (text, actual, expected)
