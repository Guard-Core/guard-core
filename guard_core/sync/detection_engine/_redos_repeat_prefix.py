from __future__ import annotations

import re
import time
from collections.abc import Callable
from typing import Any

from guard_core.sync.detection_engine._redos_parse_slots import (
    _node_intervals,
    _regex_parser,
)
from guard_core.sync.detection_engine._redos_prefix_history import (
    _contains_repeat,
    _optional_states_are_equivalent,
    _suffix_history,
)
from guard_core.sync.detection_engine._redos_repeat_alphabet import (
    _repeat_alphabet_fills,
)
from guard_core.sync.detection_engine._redos_repeat_lookbehind import (
    _walk_negative_behind,
)
from guard_core.sync.detection_engine._redos_repeat_prefix_state import (
    _PREFIX_WALK_STATE_LIMIT,
    _PREFIX_WALK_TEXT_BUDGET,
    _REPEAT_PREFIX_STATE_LIMIT,
    _capture_state,
    _consume_atom,
    _consume_piece,
    _negative_assertion,
    _positive_assertion,
    _RepeatPrefixState,
    _state_text_size,
)

_REPEAT_PREFIX_REPEAT_OPS = frozenset(
    {
        _regex_parser.MAX_REPEAT,
        _regex_parser.MIN_REPEAT,
        getattr(_regex_parser, "POSSESSIVE_REPEAT", None),
    }
)
_REPEAT_PREFIX_ATOM_OPS = frozenset(
    {
        _regex_parser.LITERAL,
        _regex_parser.NOT_LITERAL,
        _regex_parser.IN,
        _regex_parser.ANY,
        _regex_parser.CATEGORY,
    }
)


def _check_deadline(deadline: float | None) -> None:
    if deadline is not None and time.monotonic() >= deadline:
        raise TimeoutError(
            "Pattern validation repeat-prefix construction exceeded its deadline"
        )


def _unique_states(states: list[_RepeatPrefixState]) -> list[_RepeatPrefixState]:
    unique = list(dict.fromkeys(states))
    if len(unique) > _PREFIX_WALK_STATE_LIMIT:
        raise TimeoutError("Pattern validation repeat-prefix state budget exceeded")
    if sum(map(_state_text_size, unique)) > _PREFIX_WALK_TEXT_BUDGET:
        raise TimeoutError("Pattern validation repeat-prefix text budget exceeded")
    return unique


def _assertion_witnesses(
    body: list[Any], flags: int, deadline: float | None
) -> list[_RepeatPrefixState]:
    states = _PrefixWalk(flags, [], deadline, False).walk(
        body, [_RepeatPrefixState("")]
    )
    if any(
        state.pending or state.forbidden or not state.excluded.is_empty()
        for state in states
    ):
        raise TimeoutError(
            "Pattern validation cannot resolve nested assertion constraints"
        )
    return states


class _PrefixWalk:
    def __init__(
        self,
        flags: int,
        prefixes: list[str],
        deadline: float | None,
        collect: bool,
        alphabet: list[str] | None = None,
        repeat_collector: Callable[[list[Any], int, list[_RepeatPrefixState]], None]
        | None = None,
        canonical_optionals: bool = False,
        require_reachable: bool = False,
    ) -> None:
        self.flags = flags
        self.prefixes = prefixes
        self.deadline = deadline
        self.collect = collect
        self.alphabet = alphabet or []
        self.repeat_collector = repeat_collector
        self.canonical_optionals = canonical_optionals
        self.require_reachable = require_reachable

    def walk(
        self,
        items: list[Any],
        states: list[_RepeatPrefixState],
        history_observable: bool = False,
    ) -> list[_RepeatPrefixState]:
        history = _suffix_history(items, history_observable)
        for index, (op, av) in enumerate(items):
            _check_deadline(self.deadline)
            states = _unique_states(self.node(op, av, states, history[index]))
            if not states:
                self.check_remaining_repeats(items[index + 1 :])
                break
        return states

    def check_remaining_repeats(self, items: list[Any]) -> None:
        if self.require_reachable and _contains_repeat(items):
            raise TimeoutError("Pattern validation cannot resolve repeat-site prefixes")

    def atoms(
        self, op: Any, av: Any, states: list[_RepeatPrefixState]
    ) -> list[_RepeatPrefixState]:
        intervals = _node_intervals(op, av, self.flags)
        return [
            next_state
            for state in states
            if (next_state := _consume_atom(state, intervals)) is not None
        ]

    def record_prefixes(self, high: int, states: list[_RepeatPrefixState]) -> None:
        if self.collect and high > 1:
            self.prefixes.extend(state.text + state.pending for state in states)
            if len(self.prefixes) > _REPEAT_PREFIX_STATE_LIMIT * 4:
                raise TimeoutError(
                    "Pattern validation repeat-prefix candidate budget exceeded"
                )

    def repeat(
        self,
        av: Any,
        states: list[_RepeatPrefixState],
        history_observable: bool = False,
    ) -> list[_RepeatPrefixState]:
        low, high, body = av
        self.record_prefixes(high, states)
        if high > 1 and self.repeat_collector is not None:
            self.repeat_collector(body, self.flags, states)
        if low == 0 and high > 0:
            expanded = self.walk(body, states, history_observable)
            if self.canonical_optionals and _optional_states_are_equivalent(
                body, states, history_observable
            ):
                return states
            return self.pending_repeats(
                body,
                _unique_states(states + expanded),
                expanded,
                high - 1,
                history_observable,
            )
        for _ in range(low):
            _check_deadline(self.deadline)
            previous = states
            states = self.walk(body, states, history_observable)
            if states == previous or not states:
                break
        return self.pending_repeats(
            body, states, states, high - low, history_observable
        )

    def pending_repeats(
        self,
        body: list[Any],
        result: list[_RepeatPrefixState],
        frontier: list[_RepeatPrefixState],
        remaining: int,
        history_observable: bool,
    ) -> list[_RepeatPrefixState]:
        while remaining > 0:
            pending = [state for state in frontier if state.pending]
            if not pending:
                break
            _check_deadline(self.deadline)
            frontier = self.walk(body, pending, history_observable)
            result = _unique_states(result + frontier)
            if frontier == pending:
                break
            remaining -= 1
        return result

    def branch(
        self,
        av: Any,
        states: list[_RepeatPrefixState],
        history_observable: bool = False,
    ) -> list[_RepeatPrefixState]:
        _unused, alternatives = av
        result: list[_RepeatPrefixState] = []
        for alternative in alternatives:
            result = _unique_states(
                result + self.walk(alternative, states, history_observable)
            )
        return result

    def group(
        self,
        av: Any,
        states: list[_RepeatPrefixState],
        history_observable: bool = False,
    ) -> list[_RepeatPrefixState]:
        group, add_flags, del_flags, body = av
        child = _PrefixWalk(
            (self.flags | add_flags) & ~del_flags,
            self.prefixes,
            self.deadline,
            self.collect,
            self.alphabet,
            self.repeat_collector,
            self.canonical_optionals,
            self.require_reachable,
        )
        return [
            _capture_state(next_state, group, len(state.text))
            for state in states
            for next_state in child.walk(body, [state], history_observable)
        ]

    def assertion(
        self, op: Any, av: Any, states: list[_RepeatPrefixState]
    ) -> list[_RepeatPrefixState]:
        direction, body = av
        witnesses = _assertion_witnesses(body, self.flags, self.deadline)
        if op is _regex_parser.ASSERT:
            return [
                next_state
                for state in states
                for next_state in _positive_assertion(direction, witnesses, state)
            ]
        if direction < 0:
            return _walk_negative_behind(
                body, self.flags, witnesses, states, self.alphabet
            )
        return [
            next_state
            for state in states
            for next_state in _negative_assertion(body, self.flags, witnesses, state)
        ]

    def backreference(
        self, group: int, states: list[_RepeatPrefixState]
    ) -> list[_RepeatPrefixState]:
        result = []
        for state in states:
            captured = dict(state.captures).get(group)
            if (
                captured is not None
                and (next_state := _consume_piece(state, captured)) is not None
            ):
                result.append(next_state)
        return result

    def node(
        self,
        op: Any,
        av: Any,
        states: list[_RepeatPrefixState],
        history_observable: bool = False,
    ) -> list[_RepeatPrefixState]:
        if op in _REPEAT_PREFIX_ATOM_OPS:
            return self.atoms(op, av, states)
        if op in _REPEAT_PREFIX_REPEAT_OPS:
            return self.repeat(
                av,
                states,
                history_observable
                or op is getattr(_regex_parser, "POSSESSIVE_REPEAT", None),
            )
        if op is _regex_parser.GROUPREF:
            return self.backreference(av, states)
        handlers = {
            _regex_parser.BRANCH: self.branch,
            _regex_parser.SUBPATTERN: self.group,
            _regex_parser.GROUPREF_EXISTS: self.conditional,
        }
        if op in handlers:
            return handlers[op](av, states, history_observable)
        if op in {_regex_parser.ASSERT, _regex_parser.ASSERT_NOT}:
            return self.assertion(op, av, states)
        if op is getattr(_regex_parser, "ATOMIC_GROUP", None):
            return self.walk(av, states, True)
        return states if op is _regex_parser.AT else []

    def conditional(
        self,
        av: Any,
        states: list[_RepeatPrefixState],
        history_observable: bool = False,
    ) -> list[_RepeatPrefixState]:
        group, yes_branch, no_branch = av
        return [
            next_state
            for state in states
            for next_state in self.walk(
                yes_branch if group in dict(state.captures) else (no_branch or []),
                [state],
                history_observable,
            )
        ]


def _repeat_reaching_prefixes(
    pattern: str,
    flags: int,
    deadline: float | None = None,
    *,
    require_reachable: bool = False,
) -> list[str]:
    try:
        parsed = _regex_parser.parse(pattern, flags)
    except re.error:
        return []
    prefixes: list[str] = []
    alphabet = _repeat_alphabet_fills(pattern, flags, deadline, include_prefix=True)
    _PrefixWalk(
        parsed.state.flags,
        prefixes,
        deadline,
        True,
        alphabet,
        canonical_optionals=True,
        require_reachable=require_reachable,
    ).walk(parsed.data, [_RepeatPrefixState("")])
    return list(dict.fromkeys(prefix for prefix in prefixes if prefix))
