import re
from collections.abc import Iterator

from guard_core.sync.handlers._suspatterns_literals import _PARSER

SEGMENT_RUN_RE = re.compile(r"[\w.\-~%]+")
PATH_SEPARATORS = "/\\"
FLAT_CHAIN_CLASS = r"[\w.\-~%/\\]"
SEPARATOR = r"[/\\]"
OPTIONAL_SEPARATOR = r"[/\\]?"
_PLAIN_CHAIN = r"(?:[\w.\-~%]+[/\\])*"
_GUARDED_CHAIN_OPEN = "(?:(?!"
_GUARDED_CHAIN_BODY = r"[\w.\-~%]+[/\\])*"
_LEADING_SEPARATORS = (r"\A[/\\]?", r"\A[/\\]")
_GROUP_OPENER_RE = re.compile(r"\(\?P<\w+>|\(\?:|\(")
_LITERAL_PIECE_RE = re.compile(r"(?:[A-Za-z0-9_\-|?():]|\\[./\\]|\[/\\\\\])+\Z")
_FLAT_EQUIVALENTS = (
    (r"(?:(?![/\\?])\S)*", r"[^\s/\\?]*"),
    (r"(?:(?!\n).)*", r".*"),
    (r"(?:[/\\][\w.\-~%]*)*", r"(?:[/\\][/\\\w.\-~%]*)?"),
)


def _outside_classes(source: str, start: int = 0) -> Iterator[tuple[int, str]]:
    i = start
    in_class = False
    while i < len(source):
        char = source[i]
        if char == "\\":
            i += 2
            continue
        if in_class:
            in_class = char != "]"
        elif char == "[":
            in_class = True
        else:
            yield i, char
        i += 1


def _group_end(source: str, open_at: int) -> int | None:
    depth = 0
    for i, char in _outside_classes(source, open_at):
        depth += (char == "(") - (char == ")")
        if depth == 0:
            return i + 1
    return None


def _chain_at(source: str, i: int) -> tuple[int, str | None] | None:
    if source.startswith(_PLAIN_CHAIN, i):
        return i + len(_PLAIN_CHAIN), None
    if not source.startswith(_GUARDED_CHAIN_OPEN, i):
        return None
    guard_end = _group_end(source, i + len("(?:"))
    if guard_end is None or not source.startswith(_GUARDED_CHAIN_BODY, guard_end):
        return None
    guard = source[i + len(_GUARDED_CHAIN_OPEN) : guard_end - 1]
    return guard_end + len(_GUARDED_CHAIN_BODY), guard


def flattened(piece: str) -> str:
    for group_loop, flat_class in _FLAT_EQUIVALENTS:
        piece = piece.replace(group_loop, flat_class)
    return piece


def without_unbalanced_parentheses(piece: str) -> str:
    opened: list[tuple[int, int]] = []
    drop: list[tuple[int, int]] = []
    for i, char in _outside_classes(piece):
        opener = _GROUP_OPENER_RE.match(piece, i) if char == "(" else None
        if opener is not None:
            opened.append((i, opener.end()))
        elif char == ")":
            (opened.pop() if opened else drop.append((i, i + 1)))
    for start, end in sorted(drop + opened, reverse=True):
        piece = piece[:start] + piece[end:]
    return piece


def split_on_chains(source: str) -> tuple[list[str], list[str | None]]:
    pieces: list[str] = []
    guards: list[str | None] = []
    start = 0
    for i, char in _outside_classes(source):
        chain = _chain_at(source, i) if char == "(" and i >= start else None
        if chain is not None:
            pieces.append(source[start:i])
            guards.append(chain[1])
            start = chain[0]
    pieces.append(source[start:])
    return pieces, guards


def _is_separator_terminated_literal(piece: str) -> bool:
    return (
        _LITERAL_PIECE_RE.match(piece) is not None
        and piece.endswith(SEPARATOR)
        and piece.count(SEPARATOR) == 1
    )


def row_pieces(source: str) -> tuple[list[str], list[str | None]] | None:
    pieces, guards = split_on_chains(source)
    if not guards:
        return None
    if without_unbalanced_parentheses(pieces[0]) not in _LEADING_SEPARATORS:
        return None
    for interior in pieces[1:-1]:
        if not _is_separator_terminated_literal(interior):
            return None
    return pieces, guards


def _case_variants(characters: set[str]) -> frozenset[str]:
    return frozenset(
        variant for char in characters for variant in (char, char.lower(), char.upper())
    )


def _lookahead_first_characters(argument: tuple) -> frozenset[str] | None:
    direction, items = argument
    if direction != 1 or len(items) != 1 or str(items[0][0]) != "IN":
        return None
    characters: set[str] = set()
    for operation, value in items[0][1]:
        name = str(operation)
        if name == "LITERAL":
            characters.add(chr(value))
        elif name == "RANGE":
            characters.update(map(chr, range(value[0], value[1] + 1)))
        else:
            return None
    return _case_variants(characters)


def mandatory_characters(piece: str, flags: int) -> tuple[frozenset[str], ...]:
    parsed = _PARSER.parse(without_unbalanced_parentheses(piece), flags)
    groups = [
        _case_variants({chr(argument)})
        for operation, argument in parsed
        if str(operation) == "LITERAL"
    ]
    lookahead_sets = [
        _lookahead_first_characters(argument)
        for operation, argument in parsed
        if str(operation) == "ASSERT"
    ]
    return (*groups, *(chars for chars in lookahead_sets if chars is not None))
