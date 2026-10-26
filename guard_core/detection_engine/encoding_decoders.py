import re

HEX_ESCAPE_RE = re.compile(r"\\x([0-9a-fA-F]{2})")
UNICODE_ESCAPE_RE = re.compile(r"\\u([0-9a-fA-F]{4})")
PERCENT_U_ESCAPE_RE = re.compile(r"%u([0-9a-fA-F]{4})", re.IGNORECASE)
PERCENT_BYTE_RUN_RE = re.compile(r"(?:%[0-9a-fA-F]{2})+")
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


def decode_overlong_utf8_percent_runs(content: str) -> str:
    def _replace(match: re.Match[str]) -> str:
        run = match.group()
        raw = bytes(int(run[i + 1 : i + 3], 16) for i in range(0, len(run), 3))
        try:
            raw.decode("utf-8")
        except UnicodeDecodeError:
            return lenient_overlong_utf8_decode(raw)
        return run

    return PERCENT_BYTE_RUN_RE.sub(_replace, content)
