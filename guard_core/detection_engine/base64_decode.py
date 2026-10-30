import base64
import binascii
import re
from collections.abc import Iterator
from contextvars import ContextVar
from functools import partial

from guard_core.detection_engine import (
    base64_alphabet,
    compressed_payloads,
    truncation,
)
from guard_core.detection_engine.printable_count import printable_count

MIN_RUN_LENGTH = 12
DATA_ALPHABET = "A-Za-z0-9+/_\\-"
_RUN_UNIT = rf"[{DATA_ALPHABET}][{re.escape(base64_alphabet.SEPARATOR_CHARS)}]*"
_SEPARATORS = re.escape(base64_alphabet.SEPARATOR_CHARS)


def _at_least_units(min_units: int) -> str:
    return (
        rf"(?:{_RUN_UNIT}){{{min_units - 1}}}"
        rf"[{DATA_ALPHABET}][{DATA_ALPHABET}{_SEPARATORS}]*"
    )


BASE64_RE = re.compile(
    rf"(?<![{DATA_ALPHABET}])(?:"
    rf"{_at_least_units(MIN_RUN_LENGTH)}={{0,2}}"
    rf"|{_at_least_units(MIN_RUN_LENGTH - 1)}="
    rf"|{_at_least_units(MIN_RUN_LENGTH - 2)}=="
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
SEPARATOR_DELETION = dict.fromkeys(map(ord, base64_alphabet.SEPARATOR_CHARS))
NON_DATA_RE = re.compile(rf"[^{DATA_ALPHABET}]")
NON_RUN_CHAR_RE = re.compile(rf"[^{DATA_ALPHABET}=]")
FRAGMENT_SCAN_WINDOW = 32768
HEX_LITERAL_RE = re.compile(r"0[xX][0-9a-fA-F]+")

GZIP_MAGIC = b"\x1f\x8b"
MAX_GUNZIP_OUTPUT_BYTES = 8192
MAX_GUNZIP_ATTEMPTS_PER_PASS = 8

PRINTABLE_RATIO_THRESHOLD = 0.5
FALLBACK_PRINTABLE_RATIO_THRESHOLD = 0.95
MAX_REPLACEMENT_CHAR_RATIO = 0.2


decompression_cut: ContextVar[bool] = ContextVar(
    "guard_core_decompression_cut", default=False
)


scan_saw_decompression_cut: ContextVar[bool] = ContextVar(
    "guard_core_scan_saw_decompression_cut", default=False
)


def flag_decompression_cut(decode_budget_exhausted: list[bool] | None) -> None:
    """A value whose unpacked content the cap cut is no pattern threat (the
    ``decode_budget_exhausted`` list is left alone); the scan reports it with the
    outcome a plain body past the cap takes."""
    if decode_budget_exhausted is not None and decompression_cut.get():
        scan_saw_decompression_cut.set(True)


def is_hex_literal(token: str) -> bool:
    return bool(HEX_LITERAL_RE.fullmatch(token))


def printable_ratio(text: str) -> float:
    if not text:
        return 0.0
    printable = len(text) if text.isprintable() else printable_count(text)
    return printable / len(text)


def replacement_char_ratio(text: str) -> float:
    if not text:
        return 0.0
    return text.count("�") / len(text)


def _windows_cut_at(
    token: str, cut_char_re: re.Pattern[str]
) -> Iterator[tuple[int, int]]:
    start = 0
    while start < len(token):
        cut = cut_char_re.search(token, start + FRAGMENT_SCAN_WINDOW)
        end = cut.start() if cut else len(token)
        yield start, end
        start = end


def join_sub_floor_runs(token: str) -> str:
    return "".join(
        "".join(SUB_FLOOR_RUN_RE.findall(token, start, end))
        for start, end in _windows_cut_at(token, NON_DATA_RE)
    )


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


def _decode_cleaned(
    cleaned: str,
    min_printable_ratio: float,
    gunzip_attempts_left: list[int],
    max_gunzip_output_bytes: int,
) -> str | None:
    padding = (4 - len(cleaned) % 4) % 4
    try:
        raw = base64.b64decode(cleaned + "=" * padding, validate=True)
    except (ValueError, binascii.Error):
        return None
    if (
        compressed_payloads.looks_like_gzip(raw)
        or compressed_payloads.looks_like_zlib(raw)
    ) and gunzip_attempts_left[0] > 0:
        gunzip_attempts_left[0] -= 1
        inflated = compressed_payloads.bounded_inflate(raw, max_gunzip_output_bytes)
        if inflated is not None:
            raw = inflated[0]
            if inflated[1]:
                decompression_cut.set(True)
    try:
        decoded = raw.decode("utf-8")
    except UnicodeDecodeError:
        decoded = raw.decode("utf-8", errors="replace")
        if replacement_char_ratio(decoded) > MAX_REPLACEMENT_CHAR_RATIO:
            return None
    if printable_ratio(decoded) >= min_printable_ratio:
        return decoded
    return None


def _decode_token(
    token: str,
    min_printable_ratio: float,
    gunzip_attempts_left: list[int],
    max_gunzip_output_bytes: int,
) -> str | None:
    if is_hex_literal(token):
        return None
    cleaned = token.translate(SEPARATOR_DELETION)
    urlsafe = cleaned.translate(base64_alphabet.URLSAFE_TRANSLATION)
    has_urlsafe_chars = "-" in cleaned or "_" in cleaned
    if has_urlsafe_chars:
        urlsafe_decoded = _decode_cleaned(
            urlsafe, min_printable_ratio, gunzip_attempts_left, max_gunzip_output_bytes
        )
        if urlsafe_decoded is not None:
            return urlsafe_decoded
        return _decode_cleaned(
            cleaned.replace("-", "").replace("_", ""),
            min_printable_ratio,
            gunzip_attempts_left,
            max_gunzip_output_bytes,
        )
    del cleaned
    return _decode_cleaned(
        urlsafe, min_printable_ratio, gunzip_attempts_left, max_gunzip_output_bytes
    )


def _replace_run(
    gunzip_attempts_left: list[int], max_gunzip_output_bytes: int, match: re.Match[str]
) -> str:
    segment = match.group(0)
    decoded = _decode_token(
        segment,
        FALLBACK_PRINTABLE_RATIO_THRESHOLD,
        gunzip_attempts_left,
        max_gunzip_output_bytes,
    )
    return decoded if decoded is not None else segment


def _decode_runs(
    token: str, gunzip_attempts_left: list[int], max_gunzip_output_bytes: int
) -> str:
    return RUN_RE.sub(
        partial(_replace_run, gunzip_attempts_left, max_gunzip_output_bytes), token
    )


def _replace(
    gunzip_attempts_left: list[int], max_gunzip_output_bytes: int, match: re.Match[str]
) -> str:
    token = match.group(0)
    primary_threshold = (
        FALLBACK_PRINTABLE_RATIO_THRESHOLD
        if base64_alphabet.WIDENED_CANDIDATE_MARKER_RE.search(token)
        else PRINTABLE_RATIO_THRESHOLD
    )
    decoded = _decode_token(
        token, primary_threshold, gunzip_attempts_left, max_gunzip_output_bytes
    )
    base = (
        decoded
        if decoded is not None
        else _decode_runs(token, gunzip_attempts_left, max_gunzip_output_bytes)
    )
    fragments = (
        "".join(SUB_FLOOR_RUN_RE.findall(token))
        if len(token) <= FRAGMENT_SCAN_WINDOW
        else join_sub_floor_runs(token)
    )
    reassembled = (
        _decode_token(
            fragments,
            FALLBACK_PRINTABLE_RATIO_THRESHOLD,
            gunzip_attempts_left,
            max_gunzip_output_bytes,
        )
        if len(fragments) >= MIN_RUN_LENGTH
        else None
    )
    if reassembled is None or reassembled in base:
        return base
    return f"{base} {reassembled}"


def decode_base64_candidates(
    content: str,
    gunzip_attempts_left: list[int] | None = None,
    max_gunzip_output_bytes: int = MAX_GUNZIP_OUTPUT_BYTES,
) -> str:
    if gunzip_attempts_left is None:
        gunzip_attempts_left = [MAX_GUNZIP_ATTEMPTS_PER_PASS]
    return BASE64_RE.sub(
        partial(_replace, gunzip_attempts_left, max_gunzip_output_bytes), content
    )


async def _decode_runs_yielding(
    token: str, gunzip_attempts_left: list[int], max_gunzip_output_bytes: int
) -> str:
    replace_run = partial(_replace_run, gunzip_attempts_left, max_gunzip_output_bytes)
    parts: list[str | tuple[int, int]] = []
    changed = False
    for start, end in _windows_cut_at(token, NON_RUN_CHAR_RE):
        window = token[start:end]
        decoded = RUN_RE.sub(replace_run, window)
        changed = changed or decoded != window
        parts.append(decoded if decoded != window else (start, end))
        await truncation.yield_once_slice_elapsed()
    if not changed:
        return token
    return "".join(
        token[part[0] : part[1]] if isinstance(part, tuple) else part for part in parts
    )


async def _join_sub_floor_runs_yielding(token: str) -> str:
    joined: list[str] = []
    for start, end in _windows_cut_at(token, NON_DATA_RE):
        joined.append("".join(SUB_FLOOR_RUN_RE.findall(token, start, end)))
        await truncation.yield_once_slice_elapsed()
    return "".join(joined)


async def _replace_token_yielding(
    token: str, gunzip_attempts_left: list[int], max_gunzip_output_bytes: int
) -> str:
    primary_threshold = (
        FALLBACK_PRINTABLE_RATIO_THRESHOLD
        if base64_alphabet.WIDENED_CANDIDATE_MARKER_RE.search(token)
        else PRINTABLE_RATIO_THRESHOLD
    )
    decoded = _decode_token(
        token, primary_threshold, gunzip_attempts_left, max_gunzip_output_bytes
    )
    await truncation.yield_once_slice_elapsed()
    base = (
        decoded
        if decoded is not None
        else await _decode_runs_yielding(
            token, gunzip_attempts_left, max_gunzip_output_bytes
        )
    )
    fragments = await _join_sub_floor_runs_yielding(token)
    reassembled = (
        _decode_token(
            fragments,
            FALLBACK_PRINTABLE_RATIO_THRESHOLD,
            gunzip_attempts_left,
            max_gunzip_output_bytes,
        )
        if len(fragments) >= MIN_RUN_LENGTH
        else None
    )
    await truncation.yield_once_slice_elapsed()
    if reassembled is None or reassembled in base:
        return base
    return f"{base} {reassembled}"


async def decode_base64_candidates_yielding(
    content: str,
    gunzip_attempts_left: list[int] | None = None,
    max_gunzip_output_bytes: int = MAX_GUNZIP_OUTPUT_BYTES,
) -> str:
    if len(content) <= truncation.EXTRACTION_WINDOW_CHARS:
        return decode_base64_candidates(
            content, gunzip_attempts_left, max_gunzip_output_bytes
        )
    if gunzip_attempts_left is None:
        gunzip_attempts_left = [MAX_GUNZIP_ATTEMPTS_PER_PASS]
    pieces: list[str] = []
    last = 0
    for match in BASE64_RE.finditer(content):
        if match.start() > last:
            pieces.append(content[last : match.start()])
        pieces.append(
            _replace(gunzip_attempts_left, max_gunzip_output_bytes, match)
            if match.end() - match.start() <= FRAGMENT_SCAN_WINDOW
            else await _replace_token_yielding(
                match.group(0), gunzip_attempts_left, max_gunzip_output_bytes
            )
        )
        last = match.end()
    if last < len(content):
        pieces.append(content[last:])
    return "".join(pieces)
