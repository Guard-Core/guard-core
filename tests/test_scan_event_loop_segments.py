import time

from guard_core._utils.detection_scan import _scan_value_budget
from guard_core.detection_engine.preprocessor import ContentPreprocessor

_WORDS = "quarterly onboarding metrics for the regional sales team include revenue "


async def test_preprocessing_a_4_mb_clean_value_never_blocks_the_loop_for_100_ms() -> (
    None
):
    text = (_WORDS * (4_000_000 // len(_WORDS) + 1))[:4_000_000]
    coroutine = ContentPreprocessor().preprocess_with_decoded(text)
    longest = 0.0

    with _scan_value_budget(512, max_scan_seconds=1000.0):
        while True:
            started = time.thread_time()
            try:
                coroutine.send(None)
            except StopIteration:
                longest = max(longest, time.thread_time() - started)
                break
            longest = max(longest, time.thread_time() - started)

    assert longest < 0.1
