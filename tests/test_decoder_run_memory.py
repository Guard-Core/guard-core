import random
import re
import tracemalloc
from collections.abc import Callable

import pytest

from guard_core.detection_engine import encoding_decoders as decoders

_ONE_MIB = 1048576
_PEAK_BUDGET_BYTES = 6 * 1024 * 1024

_OLD_HEX_TEXT_RUN_RE = re.compile(
    r"(?<![0-9A-Za-z])((?:[0-9a-fA-F]{2}){6,})(?![0-9A-Za-z])"
)
_OLD_PERCENT_BYTE_RUN_RE = re.compile(r"(?:%[0-9a-fA-F]{2})+")


def _peak_bytes(call: Callable[[], object]) -> int:
    tracemalloc.start()
    try:
        tracemalloc.reset_peak()
        call()
        return tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()


def _reference_hex_text_runs(content: str) -> str:
    def _replace(match: re.Match[str]) -> str:
        raw = bytes.fromhex(match.group(1))
        return (
            match.group(0)
            if raw.translate(None, decoders._PRINTABLE_ASCII_BYTES)
            else raw.decode("ascii")
        )

    return _OLD_HEX_TEXT_RUN_RE.sub(_replace, content)


def _reference_overlong_percent_runs(content: str) -> str:
    def _replace(match: re.Match[str]) -> str:
        run = match.group()
        raw = bytes(int(run[i + 1 : i + 3], 16) for i in range(0, len(run), 3))
        try:
            raw.decode("utf-8")
        except UnicodeDecodeError:
            return decoders.lenient_overlong_utf8_decode(raw)
        return run

    return _OLD_PERCENT_BYTE_RUN_RE.sub(_replace, content)


@pytest.mark.parametrize(
    "content",
    [
        " " + "a" * (_ONE_MIB - 2) + " ",
        " " + "a" * (_ONE_MIB - 3) + " ",
        " " + "4142" * (_ONE_MIB // 4 - 1) + " ",
        "+" + "A" * (_ONE_MIB - 3) + "-",
    ],
    ids=["even-a-run", "odd-a-run", "printable-pairs", "base64-run"],
)
def test_a_megabyte_hex_run_decodes_within_a_few_megabytes(content: str) -> None:
    assert (
        _peak_bytes(lambda: decoders.decode_octal_hex_text_and_utf7(content))
        < _PEAK_BUDGET_BYTES
    )


@pytest.mark.parametrize("unit", ["%41", "%C3%A9", "%C0%AF"])
def test_a_megabyte_percent_run_decodes_within_a_few_megabytes(unit: str) -> None:
    content = unit * (_ONE_MIB // len(unit))
    assert (
        _peak_bytes(lambda: decoders.decode_overlong_utf8_percent_runs(content))
        < _PEAK_BUDGET_BYTES
    )


def test_hex_text_runs_decode_the_same_text_as_the_pair_repeat_pattern() -> None:
    rng = random.Random(353)
    alphabet = "0123456789abcdefABCDEF 4142gG-/=+"
    for _ in range(4000):
        content = "".join(rng.choice(alphabet) for _ in range(rng.randrange(0, 40)))
        assert decoders.decode_hex_text_runs(content) == _reference_hex_text_runs(
            content
        )
    for length in range(10, 30):
        for tail in ("", "g", " ", "z9"):
            content = " " + "41" * (length // 2) + "4" * (length % 2) + tail
            assert decoders.decode_hex_text_runs(content) == _reference_hex_text_runs(
                content
            )


def test_percent_runs_decode_the_same_text_as_the_unbounded_run_pattern() -> None:
    rng = random.Random(354)
    tokens = ["%41", "%C0%AF", "%C3%A9", "%E0%80%AF", "%f0%80%80%af", "%zz", "x", "%4"]
    chunk = decoders.PERCENT_RUN_CHUNK_TOKENS
    for _ in range(3000):
        content = "".join(rng.choice(tokens) for _ in range(rng.randrange(0, 12)))
        assert decoders.decode_overlong_utf8_percent_runs(
            content
        ) == _reference_overlong_percent_runs(content)
    for straddle in ("%C3%A9", "%C0%AF", "%E2%82%AC", "%E0%80%AF"):
        for offset in range(0, 4):
            content = "x%41" * 2 + "%41" * (chunk - 1 - offset) + straddle + "%41" * 3
            assert decoders.decode_overlong_utf8_percent_runs(
                content
            ) == _reference_overlong_percent_runs(content)
    long_run = "%41" * (3 * chunk + 5) + "%C0%AF" + "%41" * (chunk + 1)
    assert decoders.decode_overlong_utf8_percent_runs(
        long_run
    ) == _reference_overlong_percent_runs(long_run)
