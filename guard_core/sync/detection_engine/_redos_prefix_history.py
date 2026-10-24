from typing import Any

from guard_core.sync.detection_engine._redos_parse_slots import (
    _PAIRING_OPS,
    _regex_parser,
)
from guard_core.sync.detection_engine._redos_repeat_prefix_state import (
    _RepeatPrefixState,
)


def _node_observes_history(op: Any, av: Any) -> bool:
    if op in _PAIRING_OPS:
        return False
    if op is _regex_parser.AT:
        return "BOUNDARY" in str(av)
    if op in {_regex_parser.MAX_REPEAT, _regex_parser.MIN_REPEAT}:
        return _observes_history(av[2])
    if op is _regex_parser.SUBPATTERN:
        group, add, delete, body = av
        return bool(group or add or delete) or _observes_history(body)
    if op is _regex_parser.BRANCH:
        return any(_observes_history(alt) for alt in av[1])
    return True


def _observes_history(items: list[Any]) -> bool:
    return any(_node_observes_history(op, av) for op, av in items)


def _suffix_history(items: list[Any], enclosing: bool) -> list[bool]:
    observed = enclosing
    result = []
    for op, av in reversed(items):
        result.append(observed)
        observed = observed or _node_observes_history(op, av)
    return list(reversed(result))


def _optional_states_are_equivalent(
    body: list[Any], states: list[_RepeatPrefixState], history_observable: bool
) -> bool:
    return (
        not history_observable
        and not _observes_history(body)
        and not any(
            state.pending or state.forbidden or not state.excluded.is_empty()
            for state in states
        )
    )


def _contains_repeat(items: list[Any]) -> bool:
    return any(_node_contains_repeat(op, av) for op, av in items)


def _node_contains_repeat(op: Any, av: Any) -> bool:
    if op in {
        _regex_parser.MAX_REPEAT,
        _regex_parser.MIN_REPEAT,
        getattr(_regex_parser, "POSSESSIVE_REPEAT", None),
    }:
        return av[1] > 1 or _contains_repeat(av[2])
    return any(_contains_repeat(child) for child in _nested_repeat_nodes(op, av))


def _nested_repeat_nodes(op: Any, av: Any) -> list[list[Any]]:
    if op is _regex_parser.SUBPATTERN:
        return [av[3]]
    if op is _regex_parser.BRANCH:
        return list(av[1])
    if op in {_regex_parser.ASSERT, _regex_parser.ASSERT_NOT}:
        return [av[1]]
    if op is getattr(_regex_parser, "ATOMIC_GROUP", None):
        return [av]
    return []
