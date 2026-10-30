import random
import re
import time

from guard_core.detection_engine.encoding_decoders import decode_utf7_shifted_runs

_REFERENCE_RE = re.compile(r"\+[A-Za-z0-9+/]{3,}-")
_ALPHABET = "+-/aAZ09 &"


def _reference_decode(content: str) -> str:
    if "+" not in content:
        return content

    def _replace(match: re.Match[str]) -> str:
        try:
            decoded = match.group(0).encode("ascii").decode("utf-7")
        except UnicodeDecodeError:
            return match.group(0)
        return decoded if decoded and decoded.isprintable() else match.group(0)

    return _REFERENCE_RE.sub(_replace, content)


def _cpu_seconds_of(content: str) -> float:
    started = time.process_time()
    decode_utf7_shifted_runs(content)
    return time.process_time() - started


def test_a_long_run_of_plus_signs_costs_linear_time() -> None:
    assert _cpu_seconds_of("+" * 160_000) < 0.5


def test_a_long_run_of_plus_and_letter_pairs_costs_linear_time() -> None:
    assert _cpu_seconds_of("+a" * 80_000) < 0.5


def test_a_long_run_of_plus_signs_closed_by_a_minus_costs_linear_time() -> None:
    assert _cpu_seconds_of("+" * 160_000 + "-") < 0.5


def test_the_decoder_gives_the_reference_output_on_random_strings() -> None:
    rng = random.Random(320)
    for _ in range(20_000):
        length = rng.randint(0, 24)
        content = "".join(rng.choice(_ALPHABET) for _ in range(length))
        assert decode_utf7_shifted_runs(content) == _reference_decode(content), content


def test_the_decoder_decodes_the_known_cases() -> None:
    assert decode_utf7_shifted_runs("a+ADw-script+AD4-b") == "a<script>b"
    assert decode_utf7_shifted_runs("+ADw") == "+ADw"
    assert decode_utf7_shifted_runs("no shift") == "no shift"
    assert decode_utf7_shifted_runs("++ADw-") == _reference_decode("++ADw-")
