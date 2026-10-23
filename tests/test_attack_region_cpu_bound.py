import re
import threading
import time
from collections.abc import Iterator
from typing import Any, cast

import pytest

from guard_core._utils.detection_scan import _scan_value_budget
from guard_core.detection_engine.preprocessor import ContentPreprocessor


class _Burner:
    pattern = "burn"
    flags = 0

    def __init__(self, seconds: float) -> None:
        self.seconds = seconds
        self.calls = 0

    def finditer(self, text: str) -> Iterator[re.Match[str]]:
        self.calls += 1
        end = time.thread_time() + self.seconds
        while time.thread_time() < end:
            pass
        return re.finditer("x", text)


def _with_indicators(*indicators: Any) -> ContentPreprocessor:
    preprocessor = ContentPreprocessor()
    cast(Any, preprocessor).compiled_indicators = list(indicators)
    return preprocessor


def test_the_budget_stops_the_indicators_after_the_one_that_spent_it() -> None:
    slow, after = _Burner(0.06), _Burner(0.0)
    preprocessor = _with_indicators(slow, after)
    started = time.monotonic()
    with _scan_value_budget(10, max_scan_seconds=0.03):
        regions = preprocessor.extract_attack_regions("axb")
    assert (slow.calls, after.calls) == (1, 0)
    assert regions != []
    assert time.monotonic() - started < 0.03 + 0.06 + 0.5


def test_a_budget_of_zero_skips_every_indicator_and_the_scan_continues() -> None:
    first, second = _Burner(0.0), _Burner(0.0)
    preprocessor = _with_indicators(first, second)
    with _scan_value_budget(10, max_scan_seconds=0.0):
        assert preprocessor.extract_attack_regions("axb") == []
    assert (first.calls, second.calls) == (0, 0)
    assert preprocessor.truncate_safely("a" * 300000) == (
        preprocessor._cap_with_tail("a" * 300000)
    )


def test_regions_found_before_the_budget_ran_out_are_kept() -> None:
    found, slow, after = _Burner(0.0), _Burner(0.06), _Burner(0.0)
    preprocessor = _with_indicators(found, slow, after)
    with _scan_value_budget(10, max_scan_seconds=0.03):
        assert preprocessor.extract_attack_regions("axb") != []
    assert (found.calls, slow.calls, after.calls) == (1, 1, 0)


def test_without_a_scan_budget_every_indicator_runs() -> None:
    first, second = _Burner(0.0), _Burner(0.0)
    _with_indicators(first, second).extract_attack_regions("axb")
    assert (first.calls, second.calls) == (1, 1)


def test_extract_attack_regions_starts_no_thread(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    starts: list[str] = []
    original = threading.Thread.start

    def counting_start(self: threading.Thread) -> None:
        starts.append(self.name)
        original(self)

    monkeypatch.setattr(threading.Thread, "start", counting_start)
    preprocessor = ContentPreprocessor()
    for _ in range(3):
        preprocessor.extract_attack_regions("<script>x</script> onclick=1 " * 50)
    assert starts == []
