import random
import time

import pytest

from guard_core.detection_engine.printable_count import printable_count


def test_the_count_equals_the_per_character_count_on_random_text() -> None:
    rng = random.Random(327)
    for _ in range(3000):
        text = "".join(
            chr(rng.choice([rng.randint(0, 0x7F), rng.randint(0, 0x400)]))
            for _ in range(rng.randint(0, 40))
        )
        assert printable_count(text) == sum(map(str.isprintable, text)), repr(text)


@pytest.mark.parametrize("text", ["", "plain text", "\x00" * 1000, "a\nb\tc\x7f"])
def test_the_count_of_ascii_edge_cases(text: str) -> None:
    assert printable_count(text) == sum(map(str.isprintable, text))


def test_an_ascii_block_is_counted_far_faster_than_per_character() -> None:
    text = "\x00" * 300_000
    started = time.process_time()
    for _ in range(5):
        fast = printable_count(text)
    fast_seconds = time.process_time() - started
    started = time.process_time()
    for _ in range(5):
        slow = sum(map(str.isprintable, text))
    slow_seconds = time.process_time() - started

    assert fast == slow == 0
    assert fast_seconds * 10 < slow_seconds
