from dataclasses import replace
from typing import Any

from guard_core.sync.detection_engine._redos_intervals import _IntervalSet
from guard_core.sync.detection_engine._redos_parse_slots import (
    _PAIRING_OPS,
    _node_intervals,
)
from guard_core.sync.detection_engine._redos_repeat_prefix_state import (
    _REPEAT_PREFIX_STATE_LIMIT,
    _RepeatPrefixState,
)


def _check_mutation_budget(state: _RepeatPrefixState, count: int = 0) -> None:
    if state.captures:
        raise TimeoutError(
            "Pattern validation cannot resolve capture-dependent lookbehind"
        )
    if count > _REPEAT_PREFIX_STATE_LIMIT:
        raise TimeoutError("Pattern validation lookbehind state budget exceeded")


def _forbidden_final_atom(body: list[Any], flags: int) -> _IntervalSet | None:
    if len(body) != 1 or body[0][0] not in _PAIRING_OPS:
        return None
    op, av = body[0]
    return _node_intervals(op, av, flags)


def _negative_lookbehind(
    forbidden: _IntervalSet, state: _RepeatPrefixState
) -> list[_RepeatPrefixState]:
    if not state.text or not forbidden.contains(ord(state.text[-1])):
        return [state]
    _check_mutation_budget(state)
    last_atom = state.last_atom or _IntervalSet.single(ord(state.text[-1]))
    available = last_atom.difference(forbidden)
    member = available.first_member()
    if member is None:
        return []
    return [replace(state, text=state.text[:-1] + chr(member), last_atom=available)]


def _matching_witness_width(text: str, witnesses: list[_RepeatPrefixState]) -> int:
    return max(
        (len(w.text) for w in witnesses if w.text and text.endswith(w.text)),
        default=0,
    )


def _changed_prefixes(
    state: _RepeatPrefixState, width: int, alphabet: list[str]
) -> list[_RepeatPrefixState]:
    return [
        replace(state, text=state.text[:i] + char + state.text[i + 1 :])
        for i in range(len(state.text) - 1, len(state.text) - width - 1, -1)
        for char in alphabet
        if char != state.text[i]
    ]


def _lookbehind_alternatives(
    state: _RepeatPrefixState,
    witnesses: list[_RepeatPrefixState],
    alphabet: list[str],
) -> list[_RepeatPrefixState]:
    width = _matching_witness_width(state.text, witnesses)
    if width == 0:
        return [state]
    _check_mutation_budget(state, width * len(alphabet))
    return _changed_prefixes(state, width, alphabet)


def _walk_negative_behind(
    body: list[Any],
    flags: int,
    witnesses: list[_RepeatPrefixState],
    states: list[_RepeatPrefixState],
    alphabet: list[str],
) -> list[_RepeatPrefixState]:
    forbidden = _forbidden_final_atom(body, flags)
    if forbidden is None:
        return [
            next_state
            for state in states
            for next_state in _lookbehind_alternatives(state, witnesses, alphabet)
        ]
    return [
        next_state
        for state in states
        for next_state in _negative_lookbehind(forbidden, state)
    ]
