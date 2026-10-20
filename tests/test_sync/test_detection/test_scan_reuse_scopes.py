import concurrent.futures
import re
from typing import Any, cast

import pytest

from guard_core.sync.detection_engine.preprocessor import ContentPreprocessor
from guard_core.sync.detection_engine.truncation import reusing_attack_regions
from guard_core.sync.handlers._suspatterns_literals import (
    required_literals,
    reusing_literal_presence,
    rows_with_required_literal,
)

BIG = ("lorem ipsum <script>alert(1)</script> dolor sit amet " * 6000)[:262500]


class _CountingIndicator:
    pattern = "x"
    flags = 0

    def __init__(self) -> None:
        self.calls = 0

    def finditer(self, text: str):
        self.calls += 1
        return re.finditer("x", text)


def _preprocessor_with_counter() -> tuple[ContentPreprocessor, _CountingIndicator]:
    preprocessor = ContentPreprocessor()
    counter = _CountingIndicator()
    cast(Any, preprocessor).compiled_indicators = [counter]
    return preprocessor, counter


def test_attack_regions_of_one_content_are_computed_once_inside_the_scope() -> None:
    preprocessor, counter = _preprocessor_with_counter()
    with reusing_attack_regions():
        first = preprocessor.extract_attack_regions("axb" * 10)
        second = preprocessor.extract_attack_regions("axb" * 10)
    assert first == second != []
    assert counter.calls == 1


def test_attack_regions_are_computed_every_time_outside_the_scope() -> None:
    preprocessor, counter = _preprocessor_with_counter()
    preprocessor.extract_attack_regions("axb" * 10)
    preprocessor.extract_attack_regions("axb" * 10)
    assert counter.calls == 2


def test_the_scope_ends_with_the_with_block() -> None:
    preprocessor, counter = _preprocessor_with_counter()
    with reusing_attack_regions():
        preprocessor.extract_attack_regions("axb")
    preprocessor.extract_attack_regions("axb")
    assert counter.calls == 2


def test_a_caller_changing_the_returned_regions_does_not_change_the_memo() -> None:
    preprocessor, _counter = _preprocessor_with_counter()
    with reusing_attack_regions():
        first = preprocessor.extract_attack_regions("axb")
        first.clear()
        assert preprocessor.extract_attack_regions("axb") != []


def test_a_content_without_indicators_is_reused_as_empty() -> None:
    preprocessor, counter = _preprocessor_with_counter()
    with reusing_attack_regions():
        assert preprocessor.extract_attack_regions("abc") == []
        assert preprocessor.extract_attack_regions("abc") == []
    assert counter.calls == 1


def test_different_contents_get_their_own_regions() -> None:
    preprocessor, counter = _preprocessor_with_counter()
    with reusing_attack_regions():
        one = preprocessor.extract_attack_regions("axb")
        other = preprocessor.extract_attack_regions("ccccxcccc")
    assert one != other
    assert counter.calls == 2


def test_an_indicator_that_timed_out_is_never_memoized(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _TimingOut:
        def __init__(self, max_workers: int) -> None:
            pass

        def __enter__(self) -> "_TimingOut":
            return self

        def __exit__(self, *exc: object) -> None:
            return None

        def submit(self, fn, *args):
            return self

        def result(self, timeout: float):
            raise concurrent.futures.TimeoutError

    preprocessor, _counter = _preprocessor_with_counter()
    monkeypatch.setattr(concurrent.futures, "ThreadPoolExecutor", _TimingOut)
    with reusing_attack_regions():
        assert preprocessor.extract_attack_regions("axb") == []
        monkeypatch.undo()
        assert preprocessor.extract_attack_regions("axb") != []


def test_truncating_a_big_content_gives_the_same_text_with_and_without_the_scope() -> (
    None
):
    preprocessor = ContentPreprocessor()
    plain = preprocessor.truncate_safely(BIG)
    with reusing_attack_regions():
        first = preprocessor.truncate_safely(BIG)
        second = preprocessor.truncate_safely(BIG)
    assert plain == first == second
    assert len(plain) < len(BIG)


def _rows(*sources: str) -> list[tuple[re.Pattern, frozenset[str], str]]:
    return [
        (re.compile(source, re.IGNORECASE), frozenset(), "sqli") for source in sources
    ]


ROWS = _rows(r"UNION\s+SELECT", r"<script", r"\bdrop\s+table", r"\d+")
LARGE_WITH_SCRIPT = ("lorem ipsum dolor sit amet " * 400) + " <script> "
LARGE_PLAIN = "lorem ipsum dolor sit amet " * 400


def _kept(rows: list, folded: str) -> list[str]:
    return [
        row[0].pattern for row in rows_with_required_literal(rows, folded, frozenset())
    ]


@pytest.mark.parametrize(
    "folded", [LARGE_WITH_SCRIPT, LARGE_PLAIN, "union select", "x"]
)
def test_the_kept_rows_equal_the_plain_substring_test(folded: str) -> None:
    expected = [
        row[0].pattern
        for row in ROWS
        if not required_literals(row[0].pattern)
        or any(literal in folded for literal in required_literals(row[0].pattern))
    ]
    assert _kept(ROWS, folded) == expected
    with reusing_literal_presence():
        assert _kept(ROWS, folded) == expected
        assert _kept(ROWS, folded) == expected


def test_a_large_content_with_a_missing_character_keeps_no_row_for_it() -> None:
    assert "<script" in _kept(ROWS, LARGE_WITH_SCRIPT)
    assert "<script" not in _kept(ROWS, LARGE_PLAIN)


def test_the_presence_of_one_content_is_shared_by_the_row_lists_inside_the_scope() -> (
    None
):
    from guard_core.sync.handlers import _suspatterns_literals

    equal_copy = LARGE_WITH_SCRIPT[:-1] + LARGE_WITH_SCRIPT[-1]
    assert equal_copy is not LARGE_WITH_SCRIPT
    with reusing_literal_presence():
        _kept(ROWS[:2], LARGE_WITH_SCRIPT)
        assert _kept(ROWS[2:], equal_copy) == _kept(ROWS[2:], LARGE_WITH_SCRIPT)
        memo = _suspatterns_literals._presence_memo.get()
        assert memo is not None
        assert len(memo) == 1


def test_the_presence_is_forgotten_when_the_scope_ends() -> None:
    with reusing_literal_presence():
        _kept(ROWS, LARGE_WITH_SCRIPT)
    from guard_core.sync.handlers import _suspatterns_literals

    assert _suspatterns_literals._presence_memo.get() is None


class _SearchCountingText(str):
    searched: list[str]

    def __new__(cls, value: str) -> "_SearchCountingText":
        instance = super().__new__(cls, value)
        instance.searched = []
        return instance

    def __contains__(self, item: object) -> bool:
        self.searched.append(str(item))
        return super().__contains__(item)


def test_a_literal_with_a_character_the_content_lacks_is_not_searched() -> None:
    content = _SearchCountingText(LARGE_PLAIN)
    assert "<script" not in _kept(ROWS, content)
    assert "<script" not in content.searched
    assert "select" not in content.searched


def test_a_literal_whose_characters_are_all_there_is_searched() -> None:
    content = _SearchCountingText("lorem union select " * 400)
    assert "select" in {
        literal for row in ROWS for literal in required_literals(row[0].pattern)
    }
    assert "<script" not in _kept(ROWS, content)
    assert "select" in content.searched


def test_a_small_content_is_searched_for_every_literal() -> None:
    content = _SearchCountingText("small <script> text")
    assert "<script" in _kept(ROWS, content)
    assert "<script" in content.searched
