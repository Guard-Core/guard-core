from __future__ import annotations

from collections.abc import Sequence
from typing import TypeAlias, TypeGuard

_Node: TypeAlias = tuple[object, object]
_Body: TypeAlias = Sequence[_Node]

_REPEAT_SHAPE = "a repeat node is (low, high, body)"
_GROUP_SHAPE = "a group node is (group, add_flags, del_flags, body)"
_ASSERTION_SHAPE = "an assertion node is (direction, body)"
_BRANCH_SHAPE = "a branch node is (None, alternatives)"
_CONDITIONAL_SHAPE = "a conditional node is (group, yes_branch, no_branch)"
_BODY_SHAPE = "a group body is a sequence of (op, av) nodes"
_GROUP_NUMBER_SHAPE = "a back-reference node is a group number"
_CODE_POINT_SHAPE = "a literal node is a code point"
_RANGE_SHAPE = "a range node is (low, high)"


def _is_body(av: object) -> TypeGuard[_Body]:
    return hasattr(av, "__len__") and hasattr(av, "__getitem__")


def _body_of(av: object) -> _Body:
    if not _is_body(av):
        raise TypeError(_BODY_SHAPE)
    return av


def _group_number_of(av: object) -> int:
    if not isinstance(av, int):
        raise TypeError(_GROUP_NUMBER_SHAPE)
    return av


def _code_point_of(av: object) -> int:
    if not isinstance(av, int):
        raise TypeError(_CODE_POINT_SHAPE)
    return av


def _range_bounds(av: object) -> tuple[int, int]:
    if not (isinstance(av, tuple) and len(av) == 2):
        raise TypeError(_RANGE_SHAPE)
    return av


def _repeat_parts(av: object) -> tuple[int, int, _Body]:
    if not (isinstance(av, tuple) and len(av) == 3):
        raise TypeError(_REPEAT_SHAPE)
    return av


def _group_parts(av: object) -> tuple[int | None, int, int, _Body]:
    if not (isinstance(av, tuple) and len(av) == 4):
        raise TypeError(_GROUP_SHAPE)
    return av


def _assertion_parts(av: object) -> tuple[int, _Body]:
    if not (isinstance(av, tuple) and len(av) == 2):
        raise TypeError(_ASSERTION_SHAPE)
    return av


def _branch_alternatives(av: object) -> Sequence[_Body]:
    if not (isinstance(av, tuple) and len(av) == 2):
        raise TypeError(_BRANCH_SHAPE)
    alternatives: Sequence[_Body] = av[1]
    return alternatives


def _conditional_parts(av: object) -> tuple[int, _Body, _Body | None]:
    if not (isinstance(av, tuple) and len(av) == 3):
        raise TypeError(_CONDITIONAL_SHAPE)
    return av
