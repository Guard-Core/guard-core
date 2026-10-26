import random
import tracemalloc
import urllib.parse

import pytest

from guard_core.sync.detection_engine.encoding_decoders import percent_decode

_ALPHABET = [
    "%",
    "%",
    "%",
    "4",
    "1",
    "a",
    "F",
    "g",
    "c",
    "3",
    "8",
    "0",
    "/",
    "e",
    "é",
    "€",
    " ",
    "+",
    "\x00",
    "\ud800",
]
_ESCAPES = [f"%{value:02x}" for value in range(256)]
_ESCAPES += [escape.upper() for escape in _ESCAPES]
_ERRORS = ["ignore", "replace", "surrogateescape"]
_MEMORY_SLACK_BYTES = 5 * 1024 * 1024
_SIZE = 262144


def _same(text: str, errors: str) -> None:
    assert percent_decode(text, errors) == urllib.parse.unquote(text, errors=errors)


@pytest.mark.parametrize("errors", _ERRORS)
def test_every_escape_alone_and_in_pairs_decodes_like_the_standard_library(
    errors: str,
) -> None:
    for escape in _ESCAPES:
        _same(escape, errors)
        _same("a" + escape + "b", errors)
    rng = random.Random(139)
    for _ in range(4000):
        _same("".join(rng.choice(_ESCAPES) for _ in range(rng.randint(1, 4))), errors)


@pytest.mark.parametrize("errors", _ERRORS)
def test_invalid_mixed_case_and_multibyte_shapes_decode_like_the_standard_library(
    errors: str,
) -> None:
    for text in [
        "",
        "%",
        "%%",
        "%4",
        "%g1",
        "%1g",
        "%%41",
        "%41%",
        "100%",
        "%aF%Af%AF%af",
        "%e2%82%ac",
        "%E2%82",
        "%e2a%82%ac",
        "%c0%af%c0%ae",
        "%f0%9f%98%80",
        "%f0%9f%98",
        "é%41€%e2%82%acé",
        "%C3é%A9",
        "%ed%a0%80",
        "\ud800%41",
        "a+b%2Bc%20d",
    ]:
        _same(text, errors)


def test_random_strings_decode_like_the_standard_library() -> None:
    rng = random.Random(1390)
    hits = 0
    for _ in range(30000):
        text = "".join(rng.choice(_ALPHABET) for _ in range(rng.randint(0, 40)))
        errors = rng.choice(_ERRORS)
        _same(text, errors)
        hits += percent_decode(text, errors) != text
    assert hits > 3000


def test_strict_errors_raise_where_the_standard_library_raises() -> None:
    for text in ["%ff", "%e2%82", "a%c0%afb"]:
        with pytest.raises(UnicodeDecodeError):
            urllib.parse.unquote(text, errors="strict")
        with pytest.raises(UnicodeDecodeError):
            percent_decode(text, "strict")


def test_a_run_longer_than_one_join_block_keeps_its_order() -> None:
    text = "".join(f"%{value % 128:02x}x" for value in range(20000))
    _same(text, "ignore")


@pytest.mark.parametrize("unit", ["%/", "%41", "%00", "%4", "%e2%82%ac", "a%2f"])
def test_a_256_kb_value_costs_the_decoder_at_most_5_mb(unit: str) -> None:
    content = (unit * (_SIZE // len(unit) + 1))[:_SIZE]
    tracemalloc.start()
    try:
        percent_decode(content, "ignore")
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    assert peak <= _MEMORY_SLACK_BYTES
