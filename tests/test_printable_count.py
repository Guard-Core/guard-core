import base64
import gzip
import json
import random
import time

import pytest

from guard_core.detection_engine.printable_count import printable_count
from guard_core.models import SecurityConfig
from guard_core.utils import detect_penetration_attempt
from tests.conftest import MockGuardRequest


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


class _BoundedReaderRequest(MockGuardRequest):
    async def read_body_prefix(self, max_bytes: int) -> bytes:
        return self._body[:max_bytes]


async def test_many_base64_gzip_bombs_in_one_json_body_stay_cheap() -> None:
    bomb = base64.b64encode(gzip.compress(b"\0" * 300_000, 9)).decode()
    body = json.dumps({f"k{index}": bomb for index in range(500)}).encode()
    request = _BoundedReaderRequest(
        method="POST",
        body_content=body,
        headers={
            "content-type": "application/json",
            "content-length": str(len(body)),
        },
    )

    config = SecurityConfig(enable_redis=False)
    await detect_penetration_attempt(MockGuardRequest(path="/warm"), config)
    started = time.process_time()
    await detect_penetration_attempt(request, config)

    assert time.process_time() - started < 3.0
