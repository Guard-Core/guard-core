import re
from array import array
from bisect import bisect_left

_BINARY_ARTIFACT_RE = re.compile(
    r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f"
    r"\x80-\xa2\xa4\xa6-\xa9\xab-\xaf\xb4\xb6-\xb8\xbb-\xbf"
    r"\u0180-\u024f\ufffd\udc80-\udcff]"
)
_BINARY_DENSITY_RADIUS = 64
_BINARY_DENSITY_LIMIT = 4
_TEXT_NEIGHBOURHOOD_RADIUS = 8


class BinaryPrefix:
    """Where the binary artifacts of one scanned text sit.

    Holds the text length and the sorted positions of the artifact characters
    (4 bytes each, none for a clean text), where the old per-character list
    held 8 bytes for every character of the body.
    """

    __slots__ = ("length", "_positions")

    def __init__(self, length: int, positions: "array[int]") -> None:
        self.length = length
        self._positions = positions

    def count_before(self, index: int) -> int:
        return bisect_left(self._positions, index)


def build_binary_prefix(content: str) -> BinaryPrefix:
    positions = array("I", (m.start() for m in _BINARY_ARTIFACT_RE.finditer(content)))
    return BinaryPrefix(len(content), positions)


def span_is_binary_dense(binary_prefix: BinaryPrefix, start: int, end: int) -> bool:
    high = min(end + _BINARY_DENSITY_RADIUS, binary_prefix.length)
    low = max(start - _BINARY_DENSITY_RADIUS, 0)
    return (
        binary_prefix.count_before(high) - binary_prefix.count_before(low)
        >= _BINARY_DENSITY_LIMIT
    )


def span_has_text_neighbourhood(
    binary_prefix: BinaryPrefix, start: int, end: int
) -> bool:
    high = min(end + _TEXT_NEIGHBOURHOOD_RADIUS, binary_prefix.length)
    low = max(start - _TEXT_NEIGHBOURHOOD_RADIUS, 0)
    return binary_prefix.count_before(high) == binary_prefix.count_before(low)


def match_is_binary_dense(binary_prefix: BinaryPrefix | None, match: re.Match) -> bool:
    if binary_prefix is None:
        return False
    return span_is_binary_dense(binary_prefix, match.start(), match.end())


def match_has_text_neighbourhood(
    binary_prefix: BinaryPrefix | None, match: re.Match
) -> bool:
    if binary_prefix is None:
        return False
    # measured around the match without the white space it swallowed. The scan text
    # has its white space runs collapsed, so a command padded with 8 spaces or
    # newlines sits one character from the binary; white space on both sides of it
    # is the padding, and binary noise does not delimit a literal command that way.
    text = match.group()
    leading = len(text) - len(text.lstrip())
    trailing = len(text) - len(text.rstrip())
    start, end = (
        match.start() + leading,
        max(match.start() + leading, match.end() - trailing),
    )
    string = match.string
    if start > 0 and string[start - 1].isspace() and string[end : end + 1].isspace():
        return True
    return span_has_text_neighbourhood(binary_prefix, start, end)
