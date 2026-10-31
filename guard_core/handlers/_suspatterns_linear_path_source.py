import re
from collections.abc import Iterable, Iterator, Sequence

from guard_core._lazy_patterns import LazyPatterns, module_attribute_lookup
from guard_core.handlers._suspatterns_literals import _PARSER, source_digest

Span = tuple[int, int]
SEGMENT_STEP_RE = re.compile(r"[\w.\-~%]+[/\\]")
PATH_SEPARATORS = "/\\"
FLAT_CHAIN_CLASS = r"[\w.\-~%/\\]"
SEPARATOR = r"[/\\]"
OPTIONAL_SEPARATOR = r"[/\\]?"
_PLAIN_CHAIN = r"(?:[\w.\-~%]+[/\\])*"
_GUARDED_CHAIN_OPEN = "(?:(?!"
_GUARDED_CHAIN_BODY = r"[\w.\-~%]+[/\\])*"
_LEADING_SEPARATORS = (r"\A[/\\]?", r"\A[/\\]")
_STRUCTURE_RE = re.compile(r"\\.|[\[\]()|]", re.DOTALL)
_STRUCTURE_CHARACTERS = "()|"
_GROUP_OPENER_RE = re.compile(r"\(\?P<\w+>|\(\?:|\(")
_PATTERNS = LazyPatterns(
    {
        "_LITERAL_PIECE_RE": (r"(?:[A-Za-z0-9_\-|?():]|\\[./\\]|\[/\\\\\])+\Z", 0),
    }
)
__getattr__ = module_attribute_lookup(_PATTERNS)


_FLAT_EQUIVALENTS = (
    (r"(?:(?![/\\?])\S)*", r"[^\s/\\?]*"),
    (r"(?:(?!\n).)*", r".*"),
    (r"(?:[/\\][\w.\-~%]*)*", r"(?:[/\\][/\\\w.\-~%]*)?"),
    (r"(?:[^`\\\n]|\\.)*", r"[^`\\\n]*(?:\\.[^`\\\n]*)*"),
)


def _outside_classes(source: str, start: int = 0) -> Iterator[tuple[int, str]]:
    """Every ``(``, ``)`` and ``|`` that is neither escaped nor inside a class."""
    in_class = False
    for token in _STRUCTURE_RE.finditer(source, start):
        char = token.group()
        if in_class:
            in_class = char != "]"
        elif char == "[":
            in_class = True
        elif char in _STRUCTURE_CHARACTERS:
            yield token.start(), char


def _group_end(source: str, open_at: int) -> int | None:
    depth = 0
    for i, char in _outside_classes(source, open_at):
        depth += (char == "(") - (char == ")")
        if depth == 0:
            return i + 1
    return None


def _chain_at(source: str, i: int) -> tuple[int, Span | None] | None:
    if source.startswith(_PLAIN_CHAIN, i):
        return i + len(_PLAIN_CHAIN), None
    if not source.startswith(_GUARDED_CHAIN_OPEN, i):
        return None
    guard_end = _group_end(source, i + len("(?:"))
    if guard_end is None or not source.startswith(_GUARDED_CHAIN_BODY, guard_end):
        return None
    guard = (i + len(_GUARDED_CHAIN_OPEN), guard_end - 1)
    return guard_end + len(_GUARDED_CHAIN_BODY), guard


def flattened(piece: str) -> str:
    for group_loop, flat_class in _FLAT_EQUIVALENTS:
        piece = piece.replace(group_loop, flat_class)
    return piece


def unbalanced_parenthesis_spans(piece: str) -> list[Span]:
    """The spans of the closers without an opener and the openers without a closer,
    last first."""
    opened: list[Span] = []
    drop: list[Span] = []
    for i, char in _outside_classes(piece):
        opener = _GROUP_OPENER_RE.match(piece, i) if char == "(" else None
        if opener is not None:
            opened.append((i, opener.end()))
        elif char == ")":
            (opened.pop() if opened else drop.append((i, i + 1)))
    return sorted(drop + opened, reverse=True)


def without_spans(piece: str, spans: Iterable[Span]) -> str:
    """``piece`` with the given spans cut out; ``spans`` come last first."""
    for start, end in spans:
        piece = piece[:start] + piece[end:]
    return piece


def without_unbalanced_parentheses(piece: str) -> str:
    return without_spans(piece, unbalanced_parenthesis_spans(piece))


def chain_spans(source: str) -> tuple[list[Span], list[Span | None]]:
    pieces: list[Span] = []
    guards: list[Span | None] = []
    start = 0
    for i, char in _outside_classes(source):
        chain = _chain_at(source, i) if char == "(" and i >= start else None
        if chain is not None:
            pieces.append((start, i))
            guards.append(chain[1])
            start = chain[0]
    pieces.append((start, len(source)))
    return pieces, guards


def _sliced(
    source: str, pieces: Sequence[Span], guards: Sequence[Span | None]
) -> tuple[list[str], list[str | None]]:
    return (
        [source[start:end] for start, end in pieces],
        [None if guard is None else source[guard[0] : guard[1]] for guard in guards],
    )


def split_on_chains(source: str) -> tuple[list[str], list[str | None]]:
    return _sliced(source, *chain_spans(source))


def _is_separator_terminated_literal(piece: str) -> bool:
    return (
        _PATTERNS["_LITERAL_PIECE_RE"].match(piece) is not None
        and piece.endswith(SEPARATOR)
        and piece.count(SEPARATOR) == 1
    )


def _has_top_level_alternation(source: str) -> bool:
    depth = 0
    for _, char in _outside_classes(source):
        depth += (char == "(") - (char == ")")
        if char == "|" and depth == 0:
            return True
    return False


def row_spans(source: str) -> tuple[list[Span], list[Span | None]] | None:
    """Where the pieces and guards of a linear row lie in its source, or None."""
    if _PLAIN_CHAIN not in source and _GUARDED_CHAIN_OPEN not in source:
        return None
    if _has_top_level_alternation(source):
        return None
    pieces, guards = chain_spans(source)
    if not guards:
        return None
    if (
        without_unbalanced_parentheses(source[: pieces[0][1]])
        not in _LEADING_SEPARATORS
    ):
        return None
    for start, end in pieces[1:-1]:
        if not _is_separator_terminated_literal(source[start:end]):
            return None
    return pieces, guards


def row_pieces(source: str) -> tuple[list[str], list[str | None]] | None:
    """The chain pieces of a linear row, or None for any other row.

    A builtin row is looked up in the generated table of where its pieces lie (the
    split is fixed by its source), so the first scan that reaches it parses
    nothing. Any other source is split here.
    """
    from guard_core.handlers._suspatterns_linear_split_table import BUILTIN_ROW_SPANS

    digest = source_digest(source)
    spans = (
        BUILTIN_ROW_SPANS[digest] if digest in BUILTIN_ROW_SPANS else row_spans(source)
    )
    return None if spans is None else _sliced(source, *spans)


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


def mandatory_key(piece: str, flags: int) -> str:
    return source_digest(f"{flags}:{piece}")
