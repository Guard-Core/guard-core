import base64
import binascii
import random
import re
import tracemalloc
from urllib.parse import quote_from_bytes

import pytest

from guard_core.detection_engine import base64_alphabet, base64_decode
from guard_core.detection_engine.base64_decode import decode_base64_candidates
from tests.test_preprocessor_base64_corpus import BASE64_CORRUPTION_CORPUS
from tests.test_sus_patterns.test_detection_benchmark import (
    BENIGN_CORPUS,
    MALICIOUS_CORPUS,
)

# Reference: the decoder exactly as in 7bee8f73 (landing-6c), kept only here.
MIN_RUN_LENGTH = 12
DATA_ALPHABET = "A-Za-z0-9+/_\\-"
_RUN_UNIT = rf"[{DATA_ALPHABET}][{re.escape(base64_alphabet.SEPARATOR_CHARS)}]*"
BASE64_RE = re.compile(
    rf"(?<![{DATA_ALPHABET}])(?:"
    rf"(?:{_RUN_UNIT}){{{MIN_RUN_LENGTH},}}={{0,2}}"
    rf"|(?:{_RUN_UNIT}){{{MIN_RUN_LENGTH - 1},}}="
    rf"|(?:{_RUN_UNIT}){{{MIN_RUN_LENGTH - 2},}}=="
    rf")(?![{DATA_ALPHABET}=])"
)
RUN_RE = re.compile(
    rf"(?<![{DATA_ALPHABET}])[{DATA_ALPHABET}]{{{MIN_RUN_LENGTH},}}"
    rf"={{0,2}}(?![{DATA_ALPHABET}=])"
)
SUB_FLOOR_RUN_RE = re.compile(
    rf"(?<![{DATA_ALPHABET}])"
    rf"[{DATA_ALPHABET}]{{1,{MIN_RUN_LENGTH - 1}}}"
    rf"(?![{DATA_ALPHABET}])"
)
WHITESPACE_RE = re.compile(rf"[{re.escape(base64_alphabet.SEPARATOR_CHARS)}]+")
HEX_LITERAL_RE = re.compile(r"0[xX][0-9a-fA-F]+")

GZIP_MAGIC = b"\x1f\x8b"
MAX_GUNZIP_OUTPUT_BYTES = 8192
MAX_GUNZIP_ATTEMPTS_PER_PASS = 8

PRINTABLE_RATIO_THRESHOLD = 0.5
FALLBACK_PRINTABLE_RATIO_THRESHOLD = 0.95
MAX_REPLACEMENT_CHAR_RATIO = 0.2


def is_hex_literal(token: str) -> bool:
    return bool(HEX_LITERAL_RE.fullmatch(token))


def printable_ratio(text: str) -> float:
    if not text:
        return 0.0
    printable_count = (
        len(text) if text.isprintable() else sum(map(str.isprintable, text))
    )
    return printable_count / len(text)


def replacement_char_ratio(text: str) -> float:
    if not text:
        return 0.0
    return text.count("�") / len(text)


def bounded_gunzip(
    raw: bytes, max_output_bytes: int = MAX_GUNZIP_OUTPUT_BYTES
) -> bytes | None:
    if raw[:2] != GZIP_MAGIC:
        return None
    import zlib

    try:
        decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
        return decompressor.decompress(raw, max_output_bytes)
    except (zlib.error, OSError):
        return None


def _reference_decode_base64_candidates(
    content: str,
    gunzip_attempts_left: list[int] | None = None,
    max_gunzip_output_bytes: int = MAX_GUNZIP_OUTPUT_BYTES,
) -> str:
    if gunzip_attempts_left is None:
        gunzip_attempts_left = [MAX_GUNZIP_ATTEMPTS_PER_PASS]

    def _decode_cleaned(cleaned: str, min_printable_ratio: float) -> str | None:
        padding = (4 - len(cleaned) % 4) % 4
        padded = cleaned + "=" * padding
        try:
            raw = base64.b64decode(padded, validate=True)
        except (ValueError, binascii.Error):
            return None
        if raw[:2] == GZIP_MAGIC and gunzip_attempts_left[0] > 0:
            gunzip_attempts_left[0] -= 1
            gunzipped = bounded_gunzip(raw, max_gunzip_output_bytes)
            if gunzipped is not None:
                raw = gunzipped
        try:
            decoded = raw.decode("utf-8")
        except UnicodeDecodeError:
            decoded = raw.decode("utf-8", errors="replace")
            if replacement_char_ratio(decoded) > MAX_REPLACEMENT_CHAR_RATIO:
                return None
        if printable_ratio(decoded) >= min_printable_ratio:
            return decoded
        return None

    def _decode_token(token: str, min_printable_ratio: float) -> str | None:
        if is_hex_literal(token):
            return None
        cleaned = WHITESPACE_RE.sub("", token)
        urlsafe_decoded = _decode_cleaned(
            cleaned.translate(base64_alphabet.URLSAFE_TRANSLATION),
            min_printable_ratio,
        )
        if urlsafe_decoded is not None:
            return urlsafe_decoded
        if "-" in cleaned or "_" in cleaned:
            return _decode_cleaned(
                cleaned.replace("-", "").replace("_", ""), min_printable_ratio
            )
        return None

    def _decode_runs(token: str) -> str:
        def _replace_run(match: re.Match[str]) -> str:
            segment = match.group(0)
            decoded = _decode_token(segment, FALLBACK_PRINTABLE_RATIO_THRESHOLD)
            return decoded if decoded is not None else segment

        return RUN_RE.sub(_replace_run, token)

    def _replace(match: re.Match[str]) -> str:
        token = match.group(0)
        primary_threshold = (
            FALLBACK_PRINTABLE_RATIO_THRESHOLD
            if base64_alphabet.WIDENED_CANDIDATE_MARKER_RE.search(token)
            else PRINTABLE_RATIO_THRESHOLD
        )
        decoded = _decode_token(token, primary_threshold)
        base = decoded if decoded is not None else _decode_runs(token)
        fragments = "".join(SUB_FLOOR_RUN_RE.findall(token))
        reassembled = (
            _decode_token(fragments, FALLBACK_PRINTABLE_RATIO_THRESHOLD)
            if len(fragments) >= MIN_RUN_LENGTH
            else None
        )
        if reassembled is None or reassembled in base:
            return base
        return f"{base} {reassembled}"

    return BASE64_RE.sub(_replace, content)


_GENERATED_CASES = 20000
_BODY_MEMORY_FACTOR = 8
_ONE_MIB = 1048576
_WORDS = (
    b"quarterly onboarding metrics for the regional sales team include revenue "
    b"churn retention pipeline coverage forecast accuracy and headcount plans "
)


def _corpus_payloads() -> list[str]:
    payloads = [case.payload for case in MALICIOUS_CORPUS]
    payloads += [case.payload for case in BENIGN_CORPUS]
    payloads += BASE64_CORRUPTION_CORPUS
    wrapped = []
    for payload in payloads:
        encoded = base64.b64encode(payload.encode("utf-8", "surrogateescape")).decode()
        wrapped.append(encoded)
        wrapped.append(encoded.replace("+", "-").replace("/", "_").rstrip("="))
        wrapped.append(
            "\r\n".join(encoded[i : i + 76] for i in range(0, len(encoded), 76))
        )
        wrapped.append(f"a={encoded}&b={payload}")
    return payloads + wrapped


def _generated_inputs() -> list[str]:
    rng = random.Random(20261025)
    alphabet = "abcXYZ0189+/_-=  \t\r\n.,;é\udc80"
    pieces = ["=", "==", "===", "-", "_", " ", "\r\n", "ab", "Zm9v", "aGVsbG8gd29ybGQ="]
    cases = []
    for _ in range(_GENERATED_CASES):
        if rng.random() < 0.5:
            length = rng.choice([3, 11, 12, 13, 24, 60, 200])
            cases.append("".join(rng.choice(alphabet) for _ in range(length)))
            continue
        raw = bytes(rng.randrange(256) for _ in range(rng.randrange(1, 40)))
        encoded = base64.b64encode(raw).decode()
        if rng.random() < 0.5:
            encoded = encoded.replace("+", "-").replace("/", "_")
        parts = [rng.choice(pieces) for _ in range(rng.randrange(0, 4))]
        parts.insert(rng.randrange(len(parts) + 1), encoded)
        cases.append("".join(parts))
    return cases


_CORPUS_INPUTS = _corpus_payloads()
_ALL_INPUTS = _CORPUS_INPUTS + _generated_inputs()


def test_decoder_output_equals_the_7bee8f73_reference_on_every_input() -> None:
    assert len(_ALL_INPUTS) >= _GENERATED_CASES + len(_CORPUS_INPUTS)
    for content in _ALL_INPUTS:
        assert decode_base64_candidates(content) == _reference_decode_base64_candidates(
            content
        ), repr(content)


@pytest.mark.parametrize("window", [1, 2, 3, 7, 13])
def test_fragment_windows_cut_at_any_size_keep_the_reference_output(
    window: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(base64_decode, "FRAGMENT_SCAN_WINDOW", window)
    for content in _ALL_INPUTS[:4000] + _ALL_INPUTS[-4000:]:
        assert decode_base64_candidates(content) == _reference_decode_base64_candidates(
            content
        ), repr(content)


def test_inputs_longer_than_the_scan_window_keep_the_reference_output() -> None:
    rng = random.Random(7)
    pieces = ["ab", "Zm9v", "x", "  ", "=", "-", "aGVsbG8gd29ybGQ=", "\n", "qrstuvw"]
    for _ in range(6):
        content = "".join(rng.choice(pieces) for _ in range(40000))
        assert decode_base64_candidates(content) == _reference_decode_base64_candidates(
            content
        )


def test_decoder_actually_decodes_in_part_of_the_inputs() -> None:
    changed = sum(decode_base64_candidates(c) != c for c in _ALL_INPUTS)
    assert changed > _GENERATED_CASES // 10


def _one_mib_body(shape: str) -> str:
    if shape == "flat":
        return (_WORDS * (_ONE_MIB // len(_WORDS) + 1))[:_ONE_MIB].decode()
    raw = (_WORDS * (_ONE_MIB // (3 * len(_WORDS)) + 1))[: _ONE_MIB // 3]
    encoded = ("note=" + quote_from_bytes(raw, safe="")).encode()
    return encoded[:_ONE_MIB].ljust(_ONE_MIB, b"a").decode()


@pytest.mark.parametrize("shape", ["flat", "escaped"])
def test_one_mib_body_decode_peak_stays_a_small_multiple_of_the_body(
    shape: str,
) -> None:
    body = _one_mib_body(shape)
    tracemalloc.start()
    try:
        decode_base64_candidates(body)
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    assert peak <= _BODY_MEMORY_FACTOR * len(body)
