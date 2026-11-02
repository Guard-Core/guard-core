import re
from dataclasses import dataclass

from guard_core.sync.handlers._suspatterns_literals import _FOLD

_TOKEN_RE = re.compile(r"\\.|[\[\]()|]", re.DOTALL)
_LOOKAHEAD_RE = re.compile(r"\(\?=\[[^\]\\]*\]\)")
_NON_LITERAL_START = frozenset("\\[](|)*+?{.^$")
_OPTIONAL_QUANTIFIERS = frozenset("?*{")
_EVERY_BRANCH = "*"


@dataclass(frozen=True)
class AlternationParts:
    prefix: str
    branches: tuple[str, ...]
    suffix: str


def _group_end(text: str, start: int) -> int | None:
    depth = 0
    in_class = False
    for token in _TOKEN_RE.finditer(text, start):
        char = token.group()
        if in_class:
            in_class = char != "]"
        elif char == "[":
            in_class = True
        elif char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return token.end()
    return None


def _top_level_branches(text: str) -> tuple[str, ...]:
    branches: list[str] = []
    depth = 0
    in_class = False
    start = 0
    for token in _TOKEN_RE.finditer(text):
        char = token.group()
        if in_class:
            in_class = char != "]"
        elif char == "[":
            in_class = True
        elif char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
        elif char == "|" and depth == 0:
            branches.append(text[start : token.start()])
            start = token.end()
    branches.append(text[start:])
    return tuple(branches)


def split_alternation(piece: str) -> AlternationParts | None:
    """A first-character lookahead, one alternation group and a suffix, or None."""
    lookahead = _LOOKAHEAD_RE.match(piece)
    if lookahead is None or not piece.startswith("(?:", lookahead.end()):
        return None
    group_end = _group_end(piece, lookahead.end())
    if group_end is None:
        return None
    inner = piece[lookahead.end() + 3 : group_end - 1]
    while inner.startswith("(?:") and _group_end(inner, 0) == len(inner):
        inner = inner[3:-1]
    branches = _top_level_branches(inner)
    return AlternationParts(piece[: lookahead.end()], branches, piece[group_end:])


AlternationLayout = tuple[int, int, tuple[int, ...], int]


def alternation_from_layout(source: str, layout: AlternationLayout) -> AlternationParts:
    """The parts of ``split_alternation(source)`` from where they lie in ``source``:
    the prefix length, where the branches start, each branch's length (a ``|``
    follows every branch but the last) and where the suffix starts."""
    prefix_end, branches_start, lengths, suffix_start = layout
    branches = []
    position = branches_start
    for length in lengths:
        branches.append(source[position : position + length])
        position += length + 1
    return AlternationParts(source[:prefix_end], tuple(branches), source[suffix_start:])


def alternation_layout(source: str, parts: AlternationParts) -> AlternationLayout:
    """Where the parts of ``split_alternation(source)`` lie, so that
    ``alternation_from_layout`` rebuilds them without scanning ``source``."""
    prefix_end = len(parts.prefix)
    suffix_start = len(source) - len(parts.suffix)
    lengths = tuple(map(len, parts.branches))
    for wrapping in range(len(source)):
        branches_start = prefix_end + 3 + 3 * wrapping
        layout = (prefix_end, branches_start, lengths, suffix_start)
        if alternation_from_layout(source, layout) == parts:
            return layout
    raise ValueError("the branches do not lie inside the source")


def _folded(char: str) -> str:
    return char.translate(_FOLD).lower()


def _leading_literal(branch: str) -> tuple[str, str] | None:
    if branch[:1] == "\\" and len(branch) > 1 and not branch[1].isalnum():
        return branch[1], branch[2:3]
    if branch and branch[0] not in _NON_LITERAL_START:
        return branch[0], branch[1:2]
    return None


def _branch_key(branch: str) -> str | None:
    """The folded character every match of this branch starts with, else None."""
    leading = _leading_literal(branch)
    if leading is None or leading[1] in _OPTIONAL_QUANTIFIERS:
        return None
    first = leading[0]
    if first.isascii() or first.lower() == first.upper():
        return _folded(first)
    return None


def _text_key(char: str) -> str:
    folded = _folded(char)
    if char.isascii() or char.lower() == char.upper() or ord(char) in _FOLD:
        return folded
    return _EVERY_BRANCH


class BucketedTail:
    """A long alternation matched by compiling only the branches that can start
    with the character at the match position, on first need. It answers
    ``match`` exactly as the whole pattern would."""

    def __init__(self, parts: AlternationParts, flags: int) -> None:
        self._parts = parts
        self._flags = flags
        self._keys = tuple(map(_branch_key, parts.branches))
        self._compiled: dict[str, re.Pattern[str] | None] = {}

    def _pattern_for(self, key: str) -> re.Pattern[str] | None:
        if key not in self._compiled:
            parts = self._parts
            chosen = [
                branch
                for branch, branch_key in zip(parts.branches, self._keys, strict=True)
                if key == _EVERY_BRANCH or branch_key in (None, key)
            ]
            self._compiled[key] = (
                re.compile(
                    f"{parts.prefix}(?:{'|'.join(chosen)}){parts.suffix}", self._flags
                )
                if chosen
                else None
            )
        return self._compiled[key]

    def match(self, text: str, pos: int = 0) -> re.Match[str] | None:
        key = _text_key(text[pos]) if pos < len(text) else None
        pattern = self._pattern_for(key) if key is not None else None
        return None if pattern is None else pattern.match(text, pos)
