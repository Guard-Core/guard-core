import random
from collections.abc import Iterator
from typing import Any
from unittest.mock import patch

import pytest

from guard_core.sync._utils import detection_scan
from guard_core.sync._utils.detection_scan import _scan_value_budget
from guard_core.sync.detection_engine import truncation
from guard_core.sync.detection_engine.base64_view import (
    build_short_base64_additive_view,
    build_short_base64_additive_view_yielding,
)
from guard_core.sync.detection_engine.preprocessor import ContentPreprocessor
from guard_core.sync.detection_engine.truncation import (
    _collect_regions,
    _collect_regions_yielding,
    reusing_attack_regions,
    truncate_safely,
    truncate_safely_yielding,
)

_ATTACKS = ("onclick=", "<script", "UNION SELECT", "../", "eval(", "${jndi")
_FILLER = "quarterly metrics for the regional team include revenue and churn "


def _text(seed: int, parts: int) -> str:
    rng = random.Random(seed)
    pieces: list[str] = []
    for _ in range(parts):
        pieces.append(_FILLER * rng.randint(1, 40))
        if rng.random() < 0.3:
            pieces.append(rng.choice(_ATTACKS))
    return "".join(pieces)


@pytest.fixture
def small_windows() -> Iterator[None]:
    with patch.object(truncation, "EXTRACTION_WINDOW_CHARS", 61):
        yield


@pytest.fixture
def every_slice_yields() -> Iterator[list[int]]:
    yields: list[int] = []

    def counting_yield() -> None:
        yields.append(1)

    with (
        patch.object(truncation, "EXTRACTION_WINDOW_CHARS", 4096),
        patch.object(truncation, "_EVENT_LOOP_SLICE_SECONDS", -1.0),
        patch.object(truncation, "_yield_to_event_loop", counting_yield),
    ):
        yield yields


@pytest.mark.usefixtures("small_windows")
@pytest.mark.parametrize("seed", range(8))
def test_yielding_collection_finds_the_same_regions_as_the_plain_one(
    seed: int,
) -> None:
    preprocessor = ContentPreprocessor(max_content_length=10_000)
    content = _text(seed, 12)

    plain = _collect_regions(preprocessor, content, 100)
    yielding = _collect_regions_yielding(preprocessor, content, 100)

    assert yielding == plain
    assert plain[0]


@pytest.mark.usefixtures("small_windows")
@pytest.mark.parametrize("seed", range(8))
def test_yielding_truncation_returns_the_plain_truncation(
    seed: int,
) -> None:
    preprocessor = ContentPreprocessor(
        max_content_length=10_000, max_full_scan_bytes=2048
    )
    content = _text(seed, 40)
    assert len(content) > 2048

    assert truncate_safely_yielding(preprocessor, content) == truncate_safely(
        preprocessor, content
    )


def test_yielding_truncation_defers_short_or_unpreserved_content() -> None:
    short = ContentPreprocessor(max_full_scan_bytes=2048)
    assert truncate_safely_yielding(short, "x" * 100) == "x" * 100
    unpreserved = ContentPreprocessor(
        max_full_scan_bytes=2048, preserve_attack_patterns=False
    )
    long_text = "y" * 5000
    assert truncate_safely_yielding(unpreserved, long_text) == long_text[:2048]


@pytest.mark.usefixtures("small_windows")
def test_yielding_truncation_reuses_and_fills_the_request_memo() -> None:
    preprocessor = ContentPreprocessor(
        max_content_length=10_000, max_full_scan_bytes=2048
    )
    content = _text(3, 40)

    with reusing_attack_regions():
        first = truncate_safely_yielding(preprocessor, content)
        with patch.object(
            truncation, "_collect_regions_yielding", side_effect=AssertionError
        ):
            second = truncate_safely_yielding(preprocessor, content)

    assert first == second == truncate_safely(preprocessor, content)


def test_extraction_yields_between_indicator_windows_in_a_request(
    every_slice_yields: list[int],
) -> None:
    preprocessor = ContentPreprocessor(max_content_length=10_000)
    content = _FILLER * 400

    with _scan_value_budget(512, max_scan_seconds=100.0):
        _collect_regions_yielding(preprocessor, content, 100)

    assert len(every_slice_yields) >= len(preprocessor.compiled_indicators)


def test_extraction_does_not_yield_outside_a_request(
    every_slice_yields: list[int],
) -> None:
    preprocessor = ContentPreprocessor(max_content_length=10_000)

    _collect_regions_yielding(preprocessor, _FILLER * 400, 100)

    assert every_slice_yields == []


def test_preprocess_yields_between_its_steps_on_a_large_clean_value(
    every_slice_yields: list[int],
) -> None:
    preprocessor = ContentPreprocessor()

    with _scan_value_budget(512, max_scan_seconds=100.0):
        preprocessor.preprocess_with_decoded(_FILLER * 20_000)

    assert len(every_slice_yields) >= 12


def test_yielding_collection_stops_when_the_scan_budget_is_spent() -> None:
    preprocessor = ContentPreprocessor(max_content_length=10_000)

    with _scan_value_budget(512, max_scan_seconds=1.0):
        detection_scan._record_scan_time(2.0)
        regions, complete = _collect_regions_yielding(preprocessor, _text(1, 10), 100)

    assert regions == []
    assert complete is False


def test_yielding_collection_charges_its_cpu_to_the_budget() -> None:
    preprocessor = ContentPreprocessor(max_content_length=10_000)
    ticks = iter(float(n) for n in range(10_000))

    with (
        patch.object(truncation, "_thread_cpu_seconds", lambda: next(ticks)),
        _scan_value_budget(512, max_scan_seconds=1000.0),
    ):
        before = detection_scan._scan_time_remaining()
        _collect_regions_yielding(preprocessor, "quiet text " * 20, 100)
        after = detection_scan._scan_time_remaining()

    assert before is not None
    assert after is not None
    assert after < before


@pytest.mark.usefixtures("small_windows")
def test_yielding_collection_stops_at_the_region_limit() -> None:
    preprocessor = ContentPreprocessor(max_content_length=300)
    content = "onclick=1 " * 400

    plain = _collect_regions(preprocessor, content, 3)
    yielding = _collect_regions_yielding(preprocessor, content, 3)

    assert yielding == plain
    assert len(plain[0]) == 3


@pytest.mark.parametrize(
    "content",
    [
        "",
        "dGVzdCBwYXlsb2FkIGZvciB0aGUgdmlldw== " * 40,
        "QUFBQUFBQUFBQUFB zzzzzzzzzzzz dGVzdCBwYXlsb2Fk",
    ],
)
def test_short_base64_view_yielding_matches_the_plain_view(
    content: str,
) -> None:
    preprocessor = ContentPreprocessor(max_full_scan_bytes=2048)

    assert build_short_base64_additive_view_yielding(
        preprocessor, content
    ) == build_short_base64_additive_view(preprocessor, content)


def test_public_yielding_wrappers_match_their_plain_twins() -> None:
    preprocessor = ContentPreprocessor(max_full_scan_bytes=2048)
    value = _text(5, 40)
    decoded: Any = value

    assert preprocessor.preprocess_signal_preserving_yielding(
        value
    ) == preprocessor.preprocess_signal_preserving(value)
    assert preprocessor.preprocess_signal_preserving_yielding("") == ""
    assert preprocessor.preprocess_short_base64_additive_view_yielding(
        value
    ) == preprocessor.preprocess_short_base64_additive_view(value)
    assert preprocessor.preprocess_comment_dropped_view_yielding(
        decoded + "/* c */ -- x", "other"
    ) == preprocessor.preprocess_comment_dropped_view(decoded + "/* c */ -- x", "other")
    assert preprocessor.preprocess_comment_dropped_view_yielding(
        "no comment markers here", "other"
    ) == preprocessor.preprocess_comment_dropped_view(
        "no comment markers here", "other"
    )


def test_short_base64_view_yielding_decodes_and_stops_at_the_cap(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import base64

    from guard_core.sync.detection_engine import base64_view

    preprocessor = ContentPreprocessor()
    dollar = base64.b64encode(b"${7*7}").decode()
    hashed = base64.b64encode(b"#{7*7}").decode()
    content = f"a={dollar}&b={hashed}"
    assert (
        build_short_base64_additive_view_yielding(preprocessor, content)
        == "${7*7}\n#{7*7}"
    )

    monkeypatch.setattr(base64_view, "MAX_SHORT_BASE64_CANDIDATES", 1)

    assert build_short_base64_additive_view_yielding(preprocessor, content) == "${7*7}"
