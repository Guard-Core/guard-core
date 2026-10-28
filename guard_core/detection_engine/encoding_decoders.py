import re
from collections.abc import Iterator

from guard_core.detection_engine import truncation

HEX_ESCAPE_RE = re.compile(r"\\x([0-9a-fA-F]{2})")
UNICODE_ESCAPE_RE = re.compile(r"\\u([0-9a-fA-F]{4})")
PERCENT_U_ESCAPE_RE = re.compile(r"%u([0-9a-fA-F]{4})", re.IGNORECASE)
HTML_HEX_ENTITY_WITHOUT_SEMICOLON_RE = re.compile(
    r"&#[xX]([0-9a-fA-F]{2})(?![0-9a-fA-F]*;)"
)
OCTAL_ESCAPE_RE = re.compile(r"\\([0-3][0-7]{2})")
HEX_TEXT_RUN_RE = re.compile(r"(?<![0-9A-Za-z])((?:[0-9a-fA-F]{2}){6,})(?![0-9A-Za-z])")
UTF7_SHIFTED_RUN_RE = re.compile(r"\+[A-Za-z0-9+/]{3,}-")
_PRINTABLE_ASCII_BYTES = bytes([9, 10, 13, *range(0x20, 0x7F)])
PERCENT_BYTE_RUN_RE = re.compile(r"(?:%[0-9a-fA-F]{2})+")
_NON_PERCENT_RUN_CHAR_RE = re.compile(r"[^%0-9A-Fa-f]")
PERCENT_RUN_WINDOW_CHARS = 32768
_ASCII_RUN_SPLIT_RE = re.compile("([\x00-\x7f]+)")
_PERCENT_BYTE_TABLE = {
    (high + low).encode(): bytes.fromhex(high + low)
    for high in "0123456789ABCDEFabcdef"
    for low in "0123456789ABCDEFabcdef"
}
_PERCENT_PIECES_PER_JOIN = 4096

OVERLONG_LEAD_SPECS: dict[int, tuple[int, int, int, int]] = {
    0xC0: (2, 0x1F, 0x80, 0xBF),
    0xC1: (2, 0x1F, 0x80, 0xBF),
    0xE0: (3, 0x0F, 0x80, 0x9F),
    0xF0: (4, 0x07, 0x80, 0x8F),
}


def _percent_decode_ascii_run(run: str) -> bytes:
    pieces = run.encode().split(b"%")
    decoded = bytearray(pieces[0])
    table = _PERCENT_BYTE_TABLE
    for start in range(1, len(pieces), _PERCENT_PIECES_PER_JOIN):
        block = pieces[start : start + _PERCENT_PIECES_PER_JOIN]
        decoded += b"".join(
            [
                byte + piece[2:] if (byte := table.get(piece[:2])) else b"%" + piece
                for piece in block
            ]
        )
    return bytes(decoded)


def percent_decode(content: str, errors: str = "replace") -> str:
    if "%" not in content:
        return content
    bits = _ASCII_RUN_SPLIT_RE.split(content)
    decoded = [bits[0]]
    for index in range(1, len(bits), 2):
        run = bits[index]
        decoded.append(
            _percent_decode_ascii_run(run).decode("utf-8", errors)
            if "%" in run
            else run
        )
        decoded.append(bits[index + 1])
    return "".join(decoded)


def decode_hex_escapes(content: str) -> str:
    def _replace(match: re.Match[str]) -> str:
        try:
            return chr(int(match.group(1), 16))
        except ValueError:
            return match.group(0)

    return HEX_ESCAPE_RE.sub(_replace, content)


def decode_unicode_escapes(content: str) -> str:
    def _replace(match: re.Match[str]) -> str:
        try:
            return chr(int(match.group(1), 16))
        except ValueError:
            return match.group(0)

    return UNICODE_ESCAPE_RE.sub(_replace, content)


def decode_percent_u_escapes(content: str) -> str:
    def _replace(match: re.Match[str]) -> str:
        try:
            return chr(int(match.group(1), 16))
        except ValueError:
            return match.group(0)

    return PERCENT_U_ESCAPE_RE.sub(_replace, content)


def _printable_ascii_chr(code: int) -> str | None:
    char = chr(code)
    return char if char.isprintable() or char in "\t\n\r" else None


def decode_html_hex_entities_without_semicolon(content: str) -> str:
    """Read ``&#x3ealert`` as ``>alert``: html.unescape takes every following hex
    digit into the entity (``&#x3ea``), so the two-digit form is read separately.
    A run ended by ``;`` keeps its longer meaning."""
    if "&#" not in content:
        return content

    def _replace(match: re.Match[str]) -> str:
        decoded = _printable_ascii_chr(int(match.group(1), 16))
        return match.group(0) if decoded is None or ord(decoded) > 0x7F else decoded

    return HTML_HEX_ENTITY_WITHOUT_SEMICOLON_RE.sub(_replace, content)


def decode_octal_escapes(content: str) -> str:
    if "\\" not in content:
        return content

    def _replace(match: re.Match[str]) -> str:
        decoded = _printable_ascii_chr(int(match.group(1), 8))
        return match.group(0) if decoded is None or ord(decoded) > 0x7F else decoded

    return OCTAL_ESCAPE_RE.sub(_replace, content)


def decode_hex_text_runs(content: str) -> str:
    """Decode a run of hex digit pairs when, and only when, it spells printable
    ASCII text, so hashes, ids and binary-looking values are left as they are. A
    ``0x`` literal is not a run (SQL ``LOAD_FILE(0x...)`` keeps its literal)."""

    def _replace(match: re.Match[str]) -> str:
        raw = bytes.fromhex(match.group(1))
        return (
            match.group(0)
            if raw.translate(None, _PRINTABLE_ASCII_BYTES)
            else raw.decode("ascii")
        )

    return HEX_TEXT_RUN_RE.sub(_replace, content)


def decode_utf7_shifted_runs(content: str) -> str:
    """Decode each ``+<base64>-`` run of UTF-7 when it spells printable text."""
    if "+" not in content:
        return content

    def _replace(match: re.Match[str]) -> str:
        try:
            decoded = match.group(0).encode("ascii").decode("utf-7")
        except UnicodeDecodeError:
            return match.group(0)
        return decoded if decoded and decoded.isprintable() else match.group(0)

    return UTF7_SHIFTED_RUN_RE.sub(_replace, content)


def html_unescape(content: str) -> str:
    import html

    return html.unescape(decode_html_hex_entities_without_semicolon(content))


def decode_octal_hex_text_and_utf7(content: str) -> str:
    return decode_utf7_shifted_runs(decode_hex_text_runs(decode_octal_escapes(content)))


def _decode_overlong_sequence_at(raw: bytes, index: int) -> tuple[str, int] | None:
    spec = OVERLONG_LEAD_SPECS.get(raw[index])
    if spec is None or index + spec[0] > len(raw):
        return None
    sequence_length, lead_mask, first_continuation_min, first_continuation_max = spec
    continuations = raw[index + 1 : index + sequence_length]
    if not first_continuation_min <= continuations[0] <= first_continuation_max:
        return None
    if any(not 0x80 <= byte <= 0xBF for byte in continuations[1:]):
        return None
    codepoint = raw[index] & lead_mask
    for byte in continuations:
        codepoint = (codepoint << 6) | (byte & 0x3F)
    return chr(codepoint), sequence_length


def lenient_overlong_utf8_decode(raw: bytes) -> str:
    chars: list[str] = []
    index = 0
    length = len(raw)
    while index < length:
        overlong = _decode_overlong_sequence_at(raw, index)
        if overlong is not None:
            char, consumed = overlong
            chars.append(char)
            index += consumed
        elif raw[index] < 0x80:
            chars.append(chr(raw[index]))
            index += 1
        else:
            index += 1
    return "".join(chars)


def percent_run_windows(content: str) -> Iterator[tuple[int, int]]:
    start = 0
    while start < len(content):
        cut = _NON_PERCENT_RUN_CHAR_RE.search(content, start + PERCENT_RUN_WINDOW_CHARS)
        end = cut.start() if cut else len(content)
        yield start, end
        start = end


def decode_overlong_utf8_percent_runs(content: str) -> str:
    if "%" not in content:
        return content

    def _replace(match: re.Match[str]) -> str:
        run = match.group()
        raw = bytes(int(run[i + 1 : i + 3], 16) for i in range(0, len(run), 3))
        try:
            raw.decode("utf-8")
        except UnicodeDecodeError:
            return lenient_overlong_utf8_decode(raw)
        return run

    return PERCENT_BYTE_RUN_RE.sub(_replace, content)


async def decode_overlong_utf8_percent_runs_yielding(content: str) -> str:
    if "%" not in content or len(content) <= truncation.EXTRACTION_WINDOW_CHARS:
        return decode_overlong_utf8_percent_runs(content)
    decoded: list[str] = []
    for start, end in percent_run_windows(content):
        decoded.append(decode_overlong_utf8_percent_runs(content[start:end]))
        await truncation.yield_once_slice_elapsed()
    return "".join(decoded)


_LOST_BYTE = "[\ufffd\udc80-\udcff]"
_AT_SEGMENT_START = r"(?<![^/\\])"
_LOST_BYTE_RE = re.compile(_LOST_BYTE)
_LOST_BYTE_PAIR_RE = re.compile(f"{_LOST_BYTE}{{2}}")
_LOST_DOT_RUN_RE = re.compile(
    rf"{_AT_SEGMENT_START}(?:\.|{_LOST_BYTE}{{2}}){{2}}(?=[\\/])"
)
_LOST_SEPARATOR_BEFORE_SEPARATOR_RE = re.compile(
    rf"({_AT_SEGMENT_START}\.\.){_LOST_BYTE}{{1,2}}(?=[\\/])"
)
_LOST_SEPARATOR_RE = re.compile(
    rf"({_AT_SEGMENT_START}\.\.){_LOST_BYTE}{{2}}(?=[\w.-])"
)
_LOST_BYTE_REPAIR_PASSES = 4


def repair_lost_overlong_bytes(content: str) -> str:
    """Read a traversal whose overlong bytes the framework decoded to U+FFFD
    (or left as surrogate escapes) the way the percent decoder reads the same
    bytes: the two dots of a ``..`` segment may each be a lost pair, a lost byte
    after a segment's ``..`` is its separator. Only a ``..`` that opens a
    segment is repaired, so a lost byte elsewhere in a text is left alone."""
    if not _LOST_BYTE_RE.search(content):
        return content
    for _ in range(_LOST_BYTE_REPAIR_PASSES):
        repaired = _LOST_DOT_RUN_RE.sub(
            lambda match: _LOST_BYTE_PAIR_RE.sub(".", match.group()), content
        )
        repaired = _LOST_SEPARATOR_BEFORE_SEPARATOR_RE.sub(r"\1", repaired)
        repaired = _LOST_SEPARATOR_RE.sub(r"\1/", repaired)
        if repaired == content:
            break
        content = repaired
    return content
