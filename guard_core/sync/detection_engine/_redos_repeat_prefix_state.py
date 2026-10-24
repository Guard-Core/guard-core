from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import Any

from guard_core.sync.detection_engine._redos_intervals import _IntervalSet
from guard_core.sync.detection_engine._redos_parse_slots import (
    _PAIRING_OPS,
    _node_intervals,
)

_REPEAT_PREFIX_BUDGET = 24000
_REPEAT_PREFIX_STATE_LIMIT = 1024
_PREFIX_WALK_STATE_LIMIT = 16384
_PREFIX_WALK_TEXT_BUDGET = 2000000


@dataclass(frozen=True, slots=True)
class _RepeatPrefixState:
    text: str
    pending: str = ""
    excluded: _IntervalSet = field(default_factory=_IntervalSet.empty)
    forbidden: tuple[str, ...] = ()
    captures: tuple[tuple[int, str], ...] = ()
    last_atom: _IntervalSet | None = None


def _state_text_size(state: _RepeatPrefixState) -> int:
    return (
        len(state.text)
        + len(state.pending)
        + sum(map(len, state.forbidden))
        + sum(len(value) for _group, value in state.captures)
    )


def _merge_pending(left: str, right: str) -> str | None:
    common = min(len(left), len(right))
    if left[:common] != right[:common]:
        return None
    return left if len(left) >= len(right) else right


def _remaining_forbidden(words: tuple[str, ...], piece: str) -> tuple[str, ...] | None:
    if any(piece.startswith(word) for word in words):
        return None
    return tuple(word[len(piece) :] for word in words if word.startswith(piece))


def _consume_piece(state: _RepeatPrefixState, piece: str) -> _RepeatPrefixState | None:
    if not piece:
        return state
    if state.excluded.contains(ord(piece[0])):
        return None
    common = min(len(state.pending), len(piece))
    if state.pending[:common] != piece[:common]:
        return None
    forbidden = _remaining_forbidden(state.forbidden, piece)
    if forbidden is None:
        return None
    if len(state.text) + len(piece) > _REPEAT_PREFIX_BUDGET:
        raise TimeoutError("Pattern validation repeat-prefix length budget exceeded")
    return replace(
        state,
        text=state.text + piece,
        pending=state.pending[common:],
        excluded=_IntervalSet.empty(),
        forbidden=forbidden,
        last_atom=_IntervalSet.single(ord(piece[-1])),
    )


def _consume_atom(
    state: _RepeatPrefixState, intervals: _IntervalSet
) -> _RepeatPrefixState | None:
    available = intervals.difference(state.excluded)
    for word in state.forbidden:
        if len(word) == 1:
            available = available.difference(_IntervalSet.single(ord(word)))
    member = ord(state.pending[0]) if state.pending else available.first_member()
    if member is None or not available.contains(member):
        return None
    consumed = _consume_piece(state, chr(member))
    return replace(consumed, last_atom=available) if consumed is not None else None


def _capture_state(
    state: _RepeatPrefixState, group: int | None, start: int
) -> _RepeatPrefixState:
    if group is None:
        return state
    captures = dict(state.captures)
    captures[group] = state.text[start:]
    return replace(state, captures=tuple(sorted(captures.items())))


def _positive_assertion(
    direction: int, witnesses: list[_RepeatPrefixState], state: _RepeatPrefixState
) -> list[_RepeatPrefixState]:
    if direction < 0:
        return [
            replace(
                state,
                text=state.text[: -len(witness.text)] + witness.text
                if witness.text
                else state.text,
                captures=tuple(
                    sorted((dict(state.captures) | dict(witness.captures)).items())
                ),
            )
            for witness in witnesses
        ]
    return [
        replace(
            state,
            pending=pending,
            captures=tuple(
                sorted((dict(state.captures) | dict(witness.captures)).items())
            ),
        )
        for witness in witnesses
        if (pending := _merge_pending(state.pending, witness.text)) is not None
    ]


def _negative_assertion(
    body: list[Any],
    flags: int,
    witnesses: list[_RepeatPrefixState],
    state: _RepeatPrefixState,
) -> list[_RepeatPrefixState]:
    if not body:
        return []
    if len(body) == 1 and body[0][0] in _PAIRING_OPS:
        op, av = body[0]
        return [
            replace(
                state, excluded=state.excluded.union(_node_intervals(op, av, flags))
            )
        ]
    words = tuple(witness.text for witness in witnesses if witness.text)
    return [replace(state, forbidden=state.forbidden + words)]
