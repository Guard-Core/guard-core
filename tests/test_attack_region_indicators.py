import random
import re
import time
from typing import Any

import pytest

from guard_core.detection_engine.on_handler_indicator import OnHandlerIndicator
from guard_core.detection_engine.preprocessor import ContentPreprocessor

_REFERENCE = re.compile(r"on\w+=", re.IGNORECASE)
_FINDER = OnHandlerIndicator()


def _spans(finder_result: Any) -> list[tuple[int, int]]:
    return [(m.start(), m.end()) for m in finder_result]


def _assert_same_matches(text: str) -> int:
    expected = _spans(_REFERENCE.finditer(text))
    assert _spans(_FINDER.finditer(text)) == expected, repr(text)
    return len(expected)


_HAND_CASES = [
    "",
    "on=",
    "on==",
    "onx=",
    "ONx=",
    "oNcLiCk=1",
    "onon=",
    "ononon=",
    "onon",
    "xon",
    "xon=",
    "xonx=",
    "x on=y",
    "onclick=a onload=b",
    "a=onclick=b",
    "<img src=x onerror=alert(1)>",
    "oné=",
    "onй=",
    "ОНй=",
    "on9=",
    "on_=",
    "on_on=",
    "xxon",
    "xxonx",
    "xxonx=",
    "ünon=",
    "ünönx=",
    "o n=",
    "on-x=",
    "on x=",
    "foo.onclick=1;bar.onfocus=2",
    "onononononononononononon",
    "onononononononononononon=",
    "Kon=",
    "ǅon=",
    "on²=",
    "on٠=",
]


def test_finder_matches_the_regex_on_hand_picked_inputs() -> None:
    assert sum(_assert_same_matches(case) for case in _HAND_CASES) > 15


def test_finder_matches_the_regex_on_fuzz() -> None:
    rng = random.Random(37)
    alphabet = ["o", "n", "on", "ON", "x", "_", "9", "=", "=", " ", "é", "й", "Ж", "\n"]
    matches = 0
    for _ in range(20000):
        text = "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 24)))
        matches += _assert_same_matches(text)
    assert matches > 1000


def test_finder_matches_the_regex_for_every_single_character_neighbour() -> None:
    for code in range(0x2500):
        char = chr(code)
        _assert_same_matches(f"on{char}=")
        _assert_same_matches(f"{char}on=")
        _assert_same_matches(f"o{char}n=x")


def test_finder_has_the_indicator_surface_the_engine_reads() -> None:
    assert _FINDER.pattern == _REFERENCE.pattern
    assert _FINDER.flags == _REFERENCE.flags
    assert _FINDER.search("zz onclick=1") is not None
    assert _FINDER.search("zz on=1") is None


def test_the_indicator_list_keeps_25_entries_and_the_list_type() -> None:
    preprocessor = ContentPreprocessor()
    assert isinstance(preprocessor.compiled_indicators, list)
    assert len(preprocessor.compiled_indicators) == 25
    assert len(preprocessor.attack_indicators) == 25
    assert isinstance(preprocessor.compiled_indicators[2], OnHandlerIndicator)


def _cpu_seconds(work: Any) -> float:
    start = time.thread_time()
    work()
    return time.thread_time() - start


@pytest.mark.parametrize("size", [16384, 65536, 262144])
def test_onon_stays_linear(size: int) -> None:
    text = "on" * (size // 2)
    assert _cpu_seconds(lambda: list(_FINDER.finditer(text))) < 0.5
