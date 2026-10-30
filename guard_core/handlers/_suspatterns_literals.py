import hashlib
import importlib
import re
import sys
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from contextvars import ContextVar
from typing import Protocol, runtime_checkable

from guard_core.handlers._suspatterns_lazy_rows import PatternRow
from guard_core.handlers._suspatterns_literal_table import BUILTIN_REQUIRED_LITERALS

_PARSER = importlib.import_module(
    "re._parser" if sys.version_info >= (3, 11) else "sre_parse"
)

_MIN_LITERAL_LENGTH = 3
_MIN_PUNCTUATED_LITERAL_LENGTH = 2
# A single character is a usable literal only if prose and URLs rarely carry it.
_COMMON_SINGLE_CHARACTERS = frozenset(".,:-_ /'\"?!()")
_FOLD = {0x130: "i", 0x131: "i", 0x17F: "s", 0x212A: "k"}
_required_literals: dict[str, tuple[str, ...]] = {}


def fold_for_literals(text: str) -> str:
    return text.translate(_FOLD).lower()


def _usable(run: str) -> bool:
    if not (run.isascii() and run.isprintable()):
        return False
    if len(run) >= _MIN_LITERAL_LENGTH:
        return True
    if len(run) == _MIN_PUNCTUATED_LITERAL_LENGTH:
        return not run.isalnum()
    return len(run) == 1 and run not in _COMMON_SINGLE_CHARACTERS and not run.isalnum()


@runtime_checkable
class _ParsedNodes(Protocol):
    def __getitem__(self, index: int, /) -> tuple[object, object]: ...

    def __len__(self) -> int: ...


def _nodes(value: object) -> _ParsedNodes:
    if not isinstance(value, _ParsedNodes):
        raise TypeError(value)
    return value


def _tuple_item(argument: object, index: int) -> object:
    if not isinstance(argument, tuple):
        raise TypeError(argument)
    return argument[index]


def _branch_list(value: object) -> list[object]:
    if not isinstance(value, list):
        raise TypeError(value)
    return value


def _requirements(items: _ParsedNodes) -> list[tuple[str, ...]]:
    found: list[tuple[str, ...]] = []
    current: list[int] = []

    def close_run() -> None:
        run = "".join(map(chr, current))
        current.clear()
        if _usable(run):
            found.append((run.lower(),))

    for index in range(len(items)):
        op, argument = items[index]
        name = str(op)
        if name == "LITERAL":
            if not isinstance(argument, int):
                raise TypeError(argument)
            current.append(argument)
            continue
        close_run()
        if name == "SUBPATTERN":
            found.extend(_requirements(_nodes(_tuple_item(argument, 3))))
        elif name in ("MAX_REPEAT", "MIN_REPEAT"):
            minimum = _tuple_item(argument, 0)
            if isinstance(minimum, int) and minimum >= 1:
                found.extend(_requirements(_nodes(_tuple_item(argument, 2))))
        elif name == "BRANCH":
            found.extend(_branch_requirement(_branch_list(_tuple_item(argument, 1))))
    close_run()
    return found


def _branch_requirement(branches: list[object]) -> list[tuple[str, ...]]:
    alternatives: list[str] = []
    for branch in branches:
        best = _best_requirement(_requirements(_nodes(branch)))
        if best is None:
            return []
        alternatives.extend(best)
    return [tuple(dict.fromkeys(alternatives))]


def _best_requirement(
    candidates: list[tuple[str, ...]],
) -> tuple[str, ...] | None:
    if not candidates:
        return None
    return max(candidates, key=lambda alts: (min(map(len, alts)), -len(alts)))


def source_digest(source: str) -> str:
    return hashlib.blake2b(source.encode(), digest_size=8).hexdigest()


def parse_required_literals(source: str) -> tuple[str, ...]:
    try:
        parsed = _PARSER.parse(source, re.IGNORECASE)
        return _best_requirement(_requirements(parsed)) or ()
    except Exception:
        return ()


def required_literals(source: str) -> tuple[str, ...]:
    if source not in _required_literals:
        precomputed = BUILTIN_REQUIRED_LITERALS.get(source_digest(source))
        _required_literals[source] = (
            parse_required_literals(source) if precomputed is None else precomputed
        )
    return _required_literals[source]


_LARGE_CONTENT_CHARS = 4096
_Presence = tuple[frozenset[str], dict[str, bool]]
_presence_memo: ContextVar[dict[str, _Presence] | None] = ContextVar(
    "literal_presence_memo", default=None
)


@contextmanager
def reusing_literal_presence() -> Iterator[None]:
    token = _presence_memo.set({})
    try:
        yield
    finally:
        _presence_memo.reset(token)


def _presence_of(folded_content: str) -> _Presence:
    memo = _presence_memo.get()
    entry = None if memo is None else memo.get(folded_content)
    if entry is None:
        entry = (frozenset(folded_content), {})
        if memo is not None:
            memo[folded_content] = entry
    return entry


def _rows_by_substring(
    rows: Sequence[PatternRow],
    folded_content: str,
    excluded_sources: frozenset[str],
) -> Iterator[PatternRow]:
    for row in rows:
        source = row[0].pattern
        literals = () if source in excluded_sources else required_literals(source)
        if not literals or any(map(folded_content.__contains__, literals)):
            yield row


def _rows_by_presence(
    rows: Sequence[PatternRow],
    folded_content: str,
    excluded_sources: frozenset[str],
) -> Iterator[PatternRow]:
    chars, present = _presence_of(folded_content)
    for row in rows:
        source = row[0].pattern
        literals = () if source in excluded_sources else required_literals(source)
        if not literals:
            yield row
            continue
        for literal in literals:
            found = present.get(literal)
            if found is None:
                found = present[literal] = (
                    chars.issuperset(literal) and literal in folded_content
                )
            if found:
                yield row
                break


def rows_with_required_literal(
    rows: Sequence[PatternRow],
    folded_content: str,
    excluded_sources: frozenset[str],
) -> Iterator[PatternRow]:
    if len(folded_content) < _LARGE_CONTENT_CHARS:
        return _rows_by_substring(rows, folded_content, excluded_sources)
    return _rows_by_presence(rows, folded_content, excluded_sources)
