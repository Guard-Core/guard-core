import random
import re
import tracemalloc
from urllib.parse import parse_qsl, quote_from_bytes

import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.sync._utils import form_pairs
from guard_core.sync._utils.form_pairs import iter_form_pairs
from guard_core.sync.detection_engine import preprocessor
from guard_core.sync.detection_engine.binary_prefix import (
    _BINARY_ARTIFACT_RE,
    _BINARY_DENSITY_LIMIT,
    _BINARY_DENSITY_RADIUS,
    build_binary_prefix,
    match_is_binary_dense,
)
from guard_core.sync.detection_engine.preprocessor import collapse_whitespace_runs
from guard_core.sync.utils import detect_penetration_attempt
from tests.test_sus_patterns.test_detection_benchmark import (
    BENIGN_CORPUS,
    MALICIOUS_CORPUS,
)
from tests.test_sync.conftest import SyncMockGuardRequest

_GENERATED_CASES = 20000
_ONE_MIB = 1048576
_BODY_MEMORY_FACTOR = 8
_WORDS = (
    b"quarterly onboarding metrics for the regional sales team include revenue "
    b"churn retention pipeline coverage forecast accuracy and headcount plans "
)
_WINDOWS = [1, 2, 3, 7, 13]


def _reference_binary_prefix(content: str) -> list[int]:
    # The per-character list exactly as in e79132b6 (landing-6d), kept only here.
    prefix = [0] * (len(content) + 1)
    count = 0
    filled = 0
    for match in _BINARY_ARTIFACT_RE.finditer(content):
        count += 1
        boundary = match.end()
        prefix[filled + 1 : boundary] = [count - 1] * (boundary - filled - 1)
        prefix[boundary] = count
        filled = boundary
    prefix[filled:] = [count] * (len(content) + 1 - filled)
    return prefix


def _reference_match_is_binary_dense(
    binary_prefix: list[int] | None, match: re.Match[str]
) -> bool:
    if binary_prefix is None:
        return False
    high = min(match.end() + _BINARY_DENSITY_RADIUS, len(binary_prefix) - 1)
    low = max(match.start() - _BINARY_DENSITY_RADIUS, 0)
    return binary_prefix[high] - binary_prefix[low] >= _BINARY_DENSITY_LIMIT


def _corpus_payloads() -> list[str]:
    payloads = [case.payload for case in MALICIOUS_CORPUS]
    payloads += [case.payload for case in BENIGN_CORPUS]
    return payloads + [
        quote_from_bytes(p.encode("utf-8", "surrogateescape")) for p in payloads
    ]


def _generated(alphabet: str, lengths: list[int], seed: int) -> list[str]:
    rng = random.Random(seed)
    return [
        "".join(rng.choice(alphabet) for _ in range(rng.choice(lengths)))
        for _ in range(_GENERATED_CASES)
    ]


_BINARY_ALPHABET = "abc ' --\x00\x01\x80\xa0ƀ�\udc80\x7f\n é"
_WHITESPACE_ALPHABET = "ab \t\r\n\x0b\x0c\x1c\x1f\x85\xa0  ​　"
_FORM_ALPHABET = "ab%+&=89AFc0 \x80é\udc80%C3%A9%80%E2%82%AC%41"

_BINARY_INPUTS = _corpus_payloads() + _generated(
    _BINARY_ALPHABET, [0, 1, 5, 60, 200, 400], 20261025
)
_WHITESPACE_INPUTS = _corpus_payloads() + _generated(
    _WHITESPACE_ALPHABET, [0, 1, 5, 60, 200], 20261026
)
_FORM_INPUTS = _corpus_payloads() + _generated(
    _FORM_ALPHABET, [0, 1, 6, 60, 200], 20261027
)


def test_binary_prefix_counts_equal_the_e79132b6_list_at_every_index() -> None:
    probe = re.compile(r"[a-c']|\S+")
    for content in _BINARY_INPUTS:
        reference = _reference_binary_prefix(content)
        compact = build_binary_prefix(content)
        assert compact.length == len(reference) - 1
        assert [compact.count_before(i) for i in range(len(reference))] == reference
        for match in probe.finditer(content):
            assert match_is_binary_dense(compact, match) == (
                _reference_match_is_binary_dense(reference, match)
            ), repr(content)


def test_binary_prefix_generated_inputs_include_dense_and_clean_neighborhoods() -> None:
    probe = re.compile(r"'")
    verdicts = {
        match_is_binary_dense(build_binary_prefix(content), match)
        for content in _BINARY_INPUTS
        for match in probe.finditer(content)
    }
    assert verdicts == {True, False}
    first = re.match("a", "a")
    assert first is not None
    assert match_is_binary_dense(None, first) is False


@pytest.mark.parametrize("window", [*_WINDOWS, None])
def test_collapse_whitespace_runs_equals_re_sub_at_any_window(
    window: int | None, monkeypatch: pytest.MonkeyPatch
) -> None:
    if window is not None:
        monkeypatch.setattr(preprocessor, "_COLLAPSE_WINDOW", window)
    for content in _WHITESPACE_INPUTS:
        assert collapse_whitespace_runs(content) == re.sub(r"\s+", " ", content), repr(
            content
        )


@pytest.mark.parametrize("window", [*_WINDOWS, None])
def test_iter_form_pairs_equals_parse_qsl_at_any_window(
    window: int | None, monkeypatch: pytest.MonkeyPatch
) -> None:
    if window is not None:
        monkeypatch.setattr(form_pairs, "PERCENT_DECODE_WINDOW", window)
    for content in _FORM_INPUTS:
        assert list(iter_form_pairs(content)) == parse_qsl(
            content, keep_blank_values=True, errors="surrogateescape"
        ), repr(content)


def test_inputs_longer_than_the_windows_keep_the_stdlib_and_re_output() -> None:
    rng = random.Random(7)
    pieces = [
        "ab",
        "%41",
        "%C3",
        "%A9",
        "%E2%82%AC",
        "+",
        "&",
        "=",
        "  ",
        "\n",
        "%",
        "é",
    ]
    for _ in range(6):
        content = "".join(rng.choice(pieces) for _ in range(40000))
        assert list(iter_form_pairs(content)) == parse_qsl(
            content, keep_blank_values=True, errors="surrogateescape"
        )
        assert collapse_whitespace_runs(content) == re.sub(r"\s+", " ", content)
        reference = _reference_binary_prefix(content)
        compact = build_binary_prefix(content)
        assert [compact.count_before(i) for i in range(0, len(reference), 97)] == (
            reference[::97]
        )


def _one_mib_request(shape: str) -> SyncMockGuardRequest:
    if shape == "flat":
        body = (_WORDS * (_ONE_MIB // len(_WORDS) + 1))[:_ONE_MIB]
        content_type = "text/plain"
    else:
        raw = (_WORDS * (_ONE_MIB // (3 * len(_WORDS)) + 1))[: _ONE_MIB // 3]
        encoded = ("note=" + quote_from_bytes(raw, safe="")).encode()
        body = encoded[:_ONE_MIB].ljust(_ONE_MIB, b"a")
        content_type = "application/x-www-form-urlencoded"
    return SyncMockGuardRequest(
        method="POST",
        path="/x",
        headers={"content-type": content_type, "content-length": str(len(body))},
        body_content=body,
    )


@pytest.mark.parametrize("shape", ["flat", "escaped"])
def test_one_mib_detection_call_peak_stays_a_small_multiple_of_the_body(
    shape: str,
) -> None:
    config = SyncSecurityConfig(
        enable_redis=False,
        rate_limit=1000,
        detection_max_body_inspect_bytes=_ONE_MIB * 2,
    )
    detect_penetration_attempt(_one_mib_request("flat"), config)
    request = _one_mib_request(shape)
    tracemalloc.start()
    try:
        result = detect_penetration_attempt(request, config)
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    assert not result.is_threat
    assert peak <= _BODY_MEMORY_FACTOR * _ONE_MIB
