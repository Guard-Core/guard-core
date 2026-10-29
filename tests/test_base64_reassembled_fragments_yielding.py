import base64
from collections.abc import Iterator
from unittest.mock import patch

import pytest

from guard_core.detection_engine import base64_decode, truncation

_ATTACK = b"' UNION SELECT password FROM users--"
_LONG_RUN = base64.b64encode(bytes(range(128, 176))).decode()


@pytest.fixture
def small_windows() -> Iterator[None]:
    with (
        patch.object(truncation, "EXTRACTION_WINDOW_CHARS", 64),
        patch.object(base64_decode, "FRAGMENT_SCAN_WINDOW", 48),
    ):
        yield


def _token_hiding_the_attack_in_sub_floor_runs() -> str:
    encoded = base64.b64encode(_ATTACK).decode()
    chunks = [encoded[i : i + 8] for i in range(0, len(encoded), 8)]
    return " ".join([_LONG_RUN, *chunks])


@pytest.mark.usefixtures("small_windows")
async def test_a_long_token_of_short_runs_is_decoded_beside_its_long_run() -> None:
    token = _token_hiding_the_attack_in_sub_floor_runs()

    decoded = await base64_decode.decode_base64_candidates_yielding(token)

    assert decoded == f"{token} {_ATTACK.decode()}"
    assert decoded == base64_decode.decode_base64_candidates(token)
