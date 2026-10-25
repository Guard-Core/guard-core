import base64
import binascii
import re

from guard_core.sync.detection_engine import base64_alphabet

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
FRAGMENT_SCAN_WINDOW = 32768
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


def join_sub_floor_runs(token: str) -> str:
    joined: list[str] = []
    start = 0
    while start < len(token):
        cut = NON_DATA_RE.search(token, start + FRAGMENT_SCAN_WINDOW)
        end = cut.start() if cut else len(token)
        joined.append("".join(SUB_FLOOR_RUN_RE.findall(token, start, end)))
        start = end
    return "".join(joined)


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


def decode_base64_candidates(
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
        cleaned = token.translate(SEPARATOR_DELETION)
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
        fragments = (
            "".join(SUB_FLOOR_RUN_RE.findall(token))
            if len(token) <= FRAGMENT_SCAN_WINDOW
            else join_sub_floor_runs(token)
        )
        reassembled = (
            _decode_token(fragments, FALLBACK_PRINTABLE_RATIO_THRESHOLD)
            if len(fragments) >= MIN_RUN_LENGTH
            else None
        )
        if reassembled is None or reassembled in base:
            return base
        return f"{base} {reassembled}"

    return BASE64_RE.sub(_replace, content)
