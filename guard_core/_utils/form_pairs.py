import re
from collections.abc import Iterator
from urllib.parse import parse_qsl, unquote

PERCENT_DECODE_WINDOW = 32768
_HIGH_BYTE_ESCAPE_RE = re.compile(r"%[89A-Fa-f][0-9A-Fa-f]")


def _window_end(text: str, start: int) -> int:
    cut = text.find("%", start + PERCENT_DECODE_WINDOW)
    while cut != -1 and _HIGH_BYTE_ESCAPE_RE.fullmatch(text, cut - 3, cut):
        cut = text.find("%", cut + 1)
    return len(text) if cut == -1 else cut


def _decode_component(text: str) -> str:
    text = text.replace("+", " ")
    decoded: list[str] = []
    start = 0
    while start < len(text):
        end = _window_end(text, start)
        decoded.append(unquote(text[start:end], errors="surrogateescape"))
        start = end
    return "".join(decoded)


def iter_form_pairs(raw_body: str) -> Iterator[tuple[str, str]]:
    if len(raw_body) <= PERCENT_DECODE_WINDOW:
        yield from parse_qsl(raw_body, keep_blank_values=True, errors="surrogateescape")
        return
    for chunk in raw_body.split("&"):
        if chunk:
            name, _, value = chunk.partition("=")
            yield _decode_component(name), _decode_component(value)
