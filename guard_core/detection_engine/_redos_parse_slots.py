from __future__ import annotations

import functools
import importlib
import re
from collections.abc import Callable
from types import ModuleType
from typing import NamedTuple, Protocol

from guard_core.detection_engine._redos_ignorecase_fold import expand_ignorecase
from guard_core.detection_engine._redos_intervals import (
    _IntervalSet,
    cached_category_intervals,
)
from guard_core.detection_engine._redos_parse_nodes import (
    _assertion_parts,
    _Body,
    _body_of,
    _branch_alternatives,
    _code_point_of,
    _group_parts,
    _Node,
    _range_bounds,
    _repeat_parts,
)


def _import_regex_parser_module() -> ModuleType:
    try:
        return importlib.import_module("re._parser")
    except ImportError:
        return importlib.import_module("sre_parse")


def _import_regex_compiler_module() -> ModuleType:
    try:
        return importlib.import_module("re._compiler")
    except ImportError:
        return importlib.import_module("sre_compile")


class _ParserState(Protocol):
    @property
    def flags(self) -> int: ...


class _SubPatternLike(Protocol):
    @property
    def data(self) -> _Body: ...

    @property
    def state(self) -> _ParserState: ...


_regex_parser: ModuleType = _import_regex_parser_module()
_regex_compiler: ModuleType = _import_regex_compiler_module()


class _PairingAtom(NamedTuple):
    intervals: _IntervalSet
    allows_zero: bool
    unbounded: bool
    predicate: Callable[[int], bool] | None = None
    max_repeat: int | None = None
    variable_bounded: bool = False

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, _PairingAtom):
            return NotImplemented
        return (self.intervals, self.allows_zero, self.unbounded) == (
            other.intervals,
            other.allows_zero,
            other.unbounded,
        )

    def __hash__(self) -> int:
        return hash((self.intervals, self.allows_zero, self.unbounded))


class _NonPairingSlot(NamedTuple):
    is_boundary: bool
    inner: list[list[_Slot]] | None
    unbounded: bool = False
    max_repeat: int | None = None
    variable_bounded: bool = False


_Slot = _PairingAtom | _NonPairingSlot

_PAIRING_OPS = frozenset(
    {
        _regex_parser.LITERAL,
        _regex_parser.NOT_LITERAL,
        _regex_parser.IN,
        _regex_parser.ANY,
        _regex_parser.CATEGORY,
    }
)
_POSSESSIVE_REPEAT = getattr(_regex_parser, "POSSESSIVE_REPEAT", None)
_ATOMIC_GROUP = getattr(_regex_parser, "ATOMIC_GROUP", None)
_REPEAT_OPS = frozenset(
    {_regex_parser.MAX_REPEAT, _regex_parser.MIN_REPEAT, _POSSESSIVE_REPEAT}
)
_ASSERT_OPS = frozenset({_regex_parser.ASSERT, _regex_parser.ASSERT_NOT})
_CATEGORY_ESCAPES: dict[object, str] = {
    _regex_parser.CATEGORY_DIGIT: r"\d",
    _regex_parser.CATEGORY_NOT_DIGIT: r"\D",
    _regex_parser.CATEGORY_SPACE: r"\s",
    _regex_parser.CATEGORY_NOT_SPACE: r"\S",
    _regex_parser.CATEGORY_WORD: r"\w",
    _regex_parser.CATEGORY_NOT_WORD: r"\W",
}


def _subpattern_body_and_flags(av: object, flags: int) -> tuple[_Body, int]:
    _group, add_flags, del_flags, body = _group_parts(av)
    return body, (flags | add_flags) & ~del_flags


def _atomic_group_body_and_flags(av: object, flags: int) -> tuple[_Body, int]:
    return _body_of(av), flags


_GROUP_LIKE_BODY_EXTRACTORS: dict[
    object, Callable[[object, int], tuple[_Body, int]]
] = {
    _regex_parser.SUBPATTERN: _subpattern_body_and_flags,
    _ATOMIC_GROUP: _atomic_group_body_and_flags,
}


def _parse_pattern(pattern: str, flags: int) -> _SubPatternLike:
    parsed: _SubPatternLike = _regex_parser.parse(pattern, flags)
    return parsed


def _compile_class_node(op: object, av: object, flags: int) -> re.Pattern[str]:
    state = _regex_parser.State()
    state.flags = flags
    subpattern = _regex_parser.SubPattern(state, [(op, av)])
    compiled: re.Pattern[str] = _regex_compiler.compile(subpattern, flags)
    return compiled


def _category_predicate(category: object, flags: int) -> Callable[[int], bool]:
    escape = _CATEGORY_ESCAPES.get(category)
    if escape is None:
        return lambda code_point: True
    compiled = re.compile(escape, flags)
    return lambda code_point: compiled.fullmatch(chr(code_point)) is not None


def _class_node_cache_key(
    op: object, av: object, flags: int
) -> tuple[object, object, int]:
    if op is _regex_parser.IN:
        return (op, tuple(_body_of(av)), flags)
    return (op, av, flags)


def _compiled_node_predicate(compiled: re.Pattern[str]) -> Callable[[int], bool]:
    def predicate(code_point: int) -> bool:
        return compiled.fullmatch(chr(code_point)) is not None

    return predicate


def _class_node_predicate(op: object, av: object, flags: int) -> Callable[[int], bool]:
    key = _class_node_cache_key(op, av, flags)
    return _cached_class_node_predicate(*key)


@functools.lru_cache(maxsize=1024)
def _cached_class_node_predicate(
    op: object, av: object, flags: int
) -> Callable[[int], bool]:
    if op is _regex_parser.CATEGORY:
        predicate = _category_predicate(av, flags)
    else:
        predicate = _compiled_node_predicate(_compile_class_node(op, av, flags))
    return predicate


def _category_intervals(category: object, flags: int) -> _IntervalSet:
    predicate = _category_predicate(category, flags)
    return cached_category_intervals((category, flags & re.ASCII), predicate)


def _apply_ignorecase(intervals: _IntervalSet, flags: int) -> _IntervalSet:
    if not flags & re.IGNORECASE:
        return intervals
    return expand_ignorecase(intervals, ascii_only=bool(flags & re.ASCII))


def _member_intervals(op: object, av: object, flags: int) -> _IntervalSet:
    if op is _regex_parser.CATEGORY:
        return _category_intervals(av, flags)
    if op is _regex_parser.RANGE:
        low, high = _range_bounds(av)
        return _apply_ignorecase(_IntervalSet.from_range(low, high), flags)
    if op is _regex_parser.LITERAL:
        return _apply_ignorecase(_IntervalSet.single(_code_point_of(av)), flags)
    return _IntervalSet.empty()


def _in_intervals(av: object, flags: int) -> _IntervalSet:
    negate = False
    member = _IntervalSet.empty()
    for item_op, item_av in _body_of(av):
        if item_op is _regex_parser.NEGATE:
            negate = True
            continue
        member = member.union(_member_intervals(item_op, item_av, flags))
    return member.complement() if negate else member


def _any_intervals(flags: int) -> _IntervalSet:
    if flags & re.DOTALL:
        return _IntervalSet.full()
    return _IntervalSet.full().difference(_IntervalSet.single(ord("\n")))


def _node_intervals(op: object, av: object, flags: int) -> _IntervalSet:
    if op is _regex_parser.NOT_LITERAL:
        return _apply_ignorecase(
            _IntervalSet.single(_code_point_of(av)), flags
        ).complement()
    if op is _regex_parser.IN:
        return _in_intervals(av, flags)
    if op is _regex_parser.ANY:
        return _any_intervals(flags)
    return _member_intervals(op, av, flags)


def _candidate_chars_for_atom_text(atom_text: str, flags: int) -> frozenset[str]:
    try:
        parsed = _regex_parser.parse(atom_text, flags)
    except re.error:
        return frozenset()
    if len(parsed.data) != 1:
        return frozenset()
    op, av = parsed.data[0]
    intervals = _node_intervals(op, av, parsed.state.flags)
    return frozenset(chr(cp) for cp in intervals.component_first_members())


def _pairing_atom(
    op: object,
    av: object,
    flags: int,
    allows_zero: bool,
    unbounded: bool,
    max_repeat: int | None = None,
    variable_bounded: bool = False,
) -> _PairingAtom:
    intervals = _node_intervals(op, av, flags)
    predicate = _class_node_predicate(op, av, flags)
    return _PairingAtom(
        intervals, allows_zero, unbounded, predicate, max_repeat, variable_bounded
    )


def _nonpairing_slot(
    op: object,
    av: object,
    flags: int,
    allows_zero: bool,
    unbounded: bool,
    max_repeat: int | None = None,
    variable_bounded: bool = False,
) -> _NonPairingSlot:
    if op is _regex_parser.BRANCH:
        branches = _branch_alternatives(av)
        inner = [_walk_sequence(alt, flags) for alt in branches]
        return _NonPairingSlot(
            not allows_zero, inner, unbounded, max_repeat, variable_bounded
        )
    extractor = _GROUP_LIKE_BODY_EXTRACTORS.get(op)
    if extractor is not None:
        body, child_flags = extractor(av, flags)
        return _NonPairingSlot(
            not allows_zero,
            _sequence_to_alternatives(body, child_flags),
            unbounded,
            max_repeat,
            variable_bounded,
        )
    if op in _ASSERT_OPS:
        _direction, body = _assertion_parts(av)
        return _NonPairingSlot(False, _sequence_to_alternatives(body, flags), False)
    if op is _regex_parser.AT:
        return _NonPairingSlot(False, None, False)
    return _NonPairingSlot(True, None, False)


def _unrepeated_slot(op: object, av: object, flags: int) -> _Slot:
    if op in _PAIRING_OPS:
        return _pairing_atom(op, av, flags, False, False)
    return _nonpairing_slot(op, av, flags, False, False)


def _repeat_slot(av: object, flags: int) -> _Slot:
    low, high, body = _repeat_parts(av)
    allows_zero = low == 0
    unbounded = high == _regex_parser.MAXREPEAT
    variable_bounded = not unbounded and low < high
    max_repeat = high if not unbounded else None
    if len(body) == 1:
        op, item_av = body[0]
        if op in _PAIRING_OPS:
            return _pairing_atom(
                op,
                item_av,
                flags,
                allows_zero,
                unbounded,
                max_repeat,
                variable_bounded,
            )
        return _nonpairing_slot(
            op,
            item_av,
            flags,
            allows_zero,
            unbounded,
            max_repeat,
            variable_bounded,
        )
    return _NonPairingSlot(
        not allows_zero,
        _sequence_to_alternatives(body, flags),
        unbounded,
        max_repeat,
        variable_bounded,
    )


def _slot_for_flat_item(item: _Node, flags: int) -> _Slot:
    op, av = item
    if op in _REPEAT_OPS:
        return _repeat_slot(av, flags)
    return _unrepeated_slot(op, av, flags)


def _walk_sequence(items: _Body, flags: int) -> list[_Slot]:
    return [_slot_for_flat_item(item, flags) for item in items]


def _sequence_to_alternatives(items: _Body, flags: int) -> list[list[_Slot]]:
    if len(items) == 1 and items[0][0] is _regex_parser.BRANCH:
        branches = _branch_alternatives(items[0][1])
        return [_walk_sequence(alt, flags) for alt in branches]
    return [_walk_sequence(items, flags)]


def _pattern_slots(pattern: str, flags: int) -> list[_Slot] | None:
    try:
        parsed = _parse_pattern(pattern, flags)
    except re.error:
        return None
    return _walk_sequence(parsed.data, parsed.state.flags)
