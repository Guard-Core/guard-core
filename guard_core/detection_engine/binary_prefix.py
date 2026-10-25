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


def match_is_binary_dense(binary_prefix: BinaryPrefix | None, match: re.Match) -> bool:
    if binary_prefix is None:
        return False
    high = min(match.end() + _BINARY_DENSITY_RADIUS, binary_prefix.length)
    low = max(match.start() - _BINARY_DENSITY_RADIUS, 0)
    return (
        binary_prefix.count_before(high) - binary_prefix.count_before(low)
        >= _BINARY_DENSITY_LIMIT
    )
