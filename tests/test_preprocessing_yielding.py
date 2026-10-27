import base64
import gzip
import random
import re
from collections.abc import Iterator
from unittest.mock import patch

import pytest

from guard_core.detection_engine import (
    base64_decode,
    encoding_decoders,
    preprocessor,
    truncation,
    whitespace_collapse,
)
from guard_core.detection_engine.preprocessor import (
    ContentPreprocessor,
    collapse_whitespace_runs,
)

_WORDS = "quarterly onboarding metrics for the regional sales team include revenue "
_ATTACK = b"' UNION SELECT password FROM users--"


@pytest.fixture
def small_windows() -> Iterator[None]:
    with (
        patch.object(truncation, "EXTRACTION_WINDOW_CHARS", 64),
        patch.object(preprocessor, "_COLLAPSE_WINDOW", 7),
        patch.object(encoding_decoders, "PERCENT_RUN_WINDOW_CHARS", 5),
        patch.object(base64_decode, "FRAGMENT_SCAN_WINDOW", 48),
    ):
        yield


def _random_binary(rng: random.Random, size: int) -> bytes:
    return bytes(rng.getrandbits(8) for _ in range(size))


@pytest.mark.parametrize("seed", range(10))
async def test_yielding_whitespace_collapse_matches_the_plain_collapse(
    seed: int, small_windows: None
) -> None:
    rng = random.Random(seed)
    text = "".join(
        rng.choice(["a", "bc", " ", "  ", "\t", "\n\r", " ", "x" * 9])
        for _ in range(400)
    )

    assert await whitespace_collapse.collapse_yielding(
        text, preprocessor._COLLAPSE_WINDOW
    ) == collapse_whitespace_runs(text)
    assert collapse_whitespace_runs(text) == re.sub(r"\s+", " ", text)


@pytest.mark.parametrize("seed", range(10))
async def test_yielding_overlong_percent_decode_matches_the_plain_decode(
    seed: int, small_windows: None
) -> None:
    rng = random.Random(seed)
    text = "".join(
        rng.choice(["%C0%AF", "%c0%ae", "%E0%80%AF", "%41", "abc", "%", "%4", "f", " "])
        for _ in range(300)
    )
    content_preprocessor = ContentPreprocessor()

    assert await encoding_decoders.decode_overlong_utf8_percent_runs_yielding(
        text
    ) == content_preprocessor._decode_overlong_utf8_percent_runs(text)


def test_percent_free_text_is_returned_as_is_by_the_overlong_decode() -> None:
    text = _WORDS * 50

    assert encoding_decoders.decode_overlong_utf8_percent_runs(text) is text


def _base64_token_cases(rng: random.Random) -> list[str]:
    printable_head = base64.b64encode(_ATTACK * 40).decode()
    binary_tail = base64.b64encode(_random_binary(rng, 900)).decode()
    gzipped = base64.b64encode(gzip.compress(_ATTACK * 5, mtime=0)).decode()
    return [
        printable_head + binary_tail,
        binary_tail + printable_head,
        gzipped + " " + _WORDS * 6,
        base64.b64encode(_ATTACK * 30).decode().replace("+", "-").replace("/", "_"),
        " ".join(rng.choice(_WORDS.split()) for _ in range(120)),
        _WORDS.replace(" ", "") * 4,
        printable_head + "=" * 2 + "-" * 5 + binary_tail,
    ]


@pytest.mark.parametrize("seed", range(6))
@pytest.mark.parametrize("gunzip_attempts", [0, 8])
async def test_yielding_base64_decode_matches_the_plain_decode(
    seed: int, gunzip_attempts: int, small_windows: None
) -> None:
    for content in _base64_token_cases(random.Random(seed)):
        plain_attempts = [gunzip_attempts]
        yielding_attempts = [gunzip_attempts]

        plain = base64_decode.decode_base64_candidates(content, plain_attempts)
        yielding = await base64_decode.decode_base64_candidates_yielding(
            content, yielding_attempts
        )

        assert yielding == plain
        assert yielding_attempts == plain_attempts


async def test_yielding_base64_decode_defaults_its_gunzip_budget() -> None:
    content = base64.b64encode(gzip.compress(_ATTACK * 5, mtime=0)).decode()

    assert await base64_decode.decode_base64_candidates_yielding(
        content
    ) == base64_decode.decode_base64_candidates(content)


async def test_yielding_base64_decode_matches_on_a_space_free_4_mb_body() -> None:
    rng = random.Random(3)
    body = base64.b64encode(_random_binary(rng, 3_000_000)).decode()
    content_preprocessor = ContentPreprocessor()

    assert await base64_decode.decode_base64_candidates_yielding(
        body, [8]
    ) == content_preprocessor._decode_base64_candidates(body, [8])


async def test_preprocessor_base64_yielding_keeps_small_content_on_the_plain_path() -> (
    None
):
    content_preprocessor = ContentPreprocessor()
    content = base64.b64encode(_ATTACK).decode()

    assert await base64_decode.decode_base64_candidates_yielding(
        content
    ) == content_preprocessor._decode_base64_candidates(content)
