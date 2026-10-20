import binascii
import re
from typing import Any

_RUN_FLOOR = 12

SHORT_BASE64_TOKEN_RE = re.compile(r"[A-Za-z0-9+/]{4,}")
MAX_SHORT_BASE64_TOKEN_LENGTH = _RUN_FLOOR - 1
SHORT_BASE64_MARKER_CHARS = frozenset("${}#")
MAX_SHORT_BASE64_CANDIDATES = 20000
PRINTABLE_RATIO_THRESHOLD = 0.95


def _printable_ratio(text: str) -> float:
    if not text:
        return 0.0
    printable_count = (
        len(text) if text.isprintable() else sum(map(str.isprintable, text))
    )
    return printable_count / len(text)


_PADDING_BY_REMAINDER = {0: "", 2: "==", 3: "="}
_MARKER_BYTES = tuple(char.encode() for char in sorted(SHORT_BASE64_MARKER_CHARS))


def build_short_base64_additive_view(preprocessor: Any, content: str) -> str:
    if not content:
        return ""

    content = preprocessor.normalize_unicode(content)
    content = preprocessor.truncate_safely(content)

    decoded_fragments: list[str] = []
    attempts = 0
    for match in SHORT_BASE64_TOKEN_RE.finditer(content):
        if attempts >= MAX_SHORT_BASE64_CANDIDATES:
            break
        attempts += 1
        token = match.group(0)
        padding = _PADDING_BY_REMAINDER.get(len(token) % 4)
        if padding is None or len(token) > MAX_SHORT_BASE64_TOKEN_LENGTH:
            continue
        try:
            raw = binascii.a2b_base64(token + padding)
        except binascii.Error:
            continue
        if not any(marker in raw for marker in _MARKER_BYTES):
            continue
        try:
            decoded = raw.decode("utf-8")
        except UnicodeDecodeError:
            continue
        if _printable_ratio(decoded) >= PRINTABLE_RATIO_THRESHOLD:
            decoded_fragments.append(decoded)

    return "\n".join(decoded_fragments)
