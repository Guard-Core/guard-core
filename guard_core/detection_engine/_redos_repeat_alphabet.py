from __future__ import annotations

import time

from guard_core.detection_engine._redos_intervals import _IntervalSet
from guard_core.detection_engine._redos_parse_slots import (
    _NonPairingSlot,
    _PairingAtom,
    _pattern_slots,
    _Slot,
)

_LARGE_BOUNDED_REPEAT_LIMIT = 4096


def _is_large_bounded_repeat(slot: _Slot) -> bool:
    return (
        slot.variable_bounded
        and slot.max_repeat is not None
        and slot.max_repeat >= _LARGE_BOUNDED_REPEAT_LIMIT
    )


def _collect_alphabet_atoms(
    slots: list[_Slot], repeated: bool = False
) -> list[tuple[_IntervalSet, bool]]:
    atoms: list[tuple[_IntervalSet, bool]] = []
    for slot in slots:
        is_repeated = repeated or _can_repeat(slot)
        if isinstance(slot, _PairingAtom):
            atoms.append((slot.intervals, is_repeated))
        elif slot.inner is not None:
            for alternative in slot.inner:
                atoms.extend(_collect_alphabet_atoms(alternative, is_repeated))
    return atoms


def _can_repeat(slot: _Slot) -> bool:
    return slot.unbounded or (slot.max_repeat is not None and slot.max_repeat > 1)


def _split_alphabet(
    regions: list[_IntervalSet], constraint: _IntervalSet, deadline: float | None
) -> list[_IntervalSet]:
    result: list[_IntervalSet] = []
    for region in regions:
        if deadline is not None and time.thread_time() >= deadline:
            raise TimeoutError("Pattern validation alphabet exceeded its deadline")
        for part in (region.intersection(constraint), region.difference(constraint)):
            if not part.is_empty():
                result.append(part)
    return result


def _repeated_characters(atoms: list[tuple[_IntervalSet, bool]]) -> _IntervalSet:
    repeated = _IntervalSet.empty()
    for intervals, unbounded in atoms:
        if unbounded:
            repeated = repeated.union(intervals)
    return repeated


def _repeat_alphabet_fills(
    pattern: str,
    flags: int,
    deadline: float | None = None,
    *,
    include_prefix: bool = False,
) -> list[str]:
    slots = _pattern_slots(pattern, flags)
    if slots is None:
        return []
    atoms = _collect_alphabet_atoms(slots, include_prefix)
    repeated = _repeated_characters(atoms)
    if repeated.is_empty():
        return []
    regions = [repeated]
    for constraint in dict.fromkeys(intervals for intervals, _repeat in atoms):
        regions = _split_alphabet(regions, constraint, deadline)
    return [
        chr(member)
        for region in regions
        if (member := region.first_member()) is not None
    ]


def _has_large_bounded_repeat(pattern: str, flags: int) -> bool:
    slots = _pattern_slots(pattern, flags)
    if slots is None:
        return False
    return _slots_have_large_bounded_repeat(slots)


def _slots_have_large_bounded_repeat(slots: list[_Slot]) -> bool:
    for slot in slots:
        if _is_large_bounded_repeat(slot):
            return True
        if isinstance(slot, _NonPairingSlot) and slot.inner is not None:
            if any(
                _slots_have_large_bounded_repeat(alternative)
                for alternative in slot.inner
            ):
                return True
    return False
