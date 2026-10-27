from __future__ import annotations

from guard_core.detection_engine._redos_exact_state import (
    _MAX_GROUP_CROSSING_DEPTH,
    _exact_overlap_fill_raw,
    _isolated_group_exact_state,
    _narrow_exact_state_raw,
)
from guard_core.detection_engine._redos_intervals import _IntervalSet
from guard_core.detection_engine._redos_parse_slots import (
    _NonPairingSlot,
    _PairingAtom,
    _pattern_slots,
    _Slot,
)
from guard_core.detection_engine._redos_stray_chooser import (
    _build_stray_context,
    _StrayContext,
    choose_class_intersection_stray,
)


def _crossing_slot_narrows(
    slot: _Slot, shared: _IntervalSet, depth: int
) -> _IntervalSet | None:
    if isinstance(slot, _PairingAtom):
        if slot.allows_zero:
            return shared
        overlap = shared.intersection(slot.intervals)
        return None if overlap.is_empty() else overlap
    if not slot.is_boundary:
        return shared
    if slot.inner is None:
        return None
    crossing = _group_crossing_result(slot.inner, shared, depth + 1)
    return shared if crossing is not None else None


def _alternative_crossing(
    alt_slots: list[_Slot], shared: _IntervalSet, depth: int
) -> _IntervalSet | None:
    local = shared
    for slot in alt_slots:
        narrowed = _crossing_slot_narrows(slot, local, depth)
        if narrowed is None:
            return None
        local = narrowed
    return local


def _group_crossing_result(
    alternatives: list[list[_Slot]], shared: _IntervalSet, depth: int
) -> _IntervalSet | None:
    if depth > _MAX_GROUP_CROSSING_DEPTH:
        return None
    combined: _IntervalSet | None = None
    for alt in alternatives:
        result = _alternative_crossing(alt, shared, depth)
        if result is None:
            continue
        combined = result if combined is None else combined.union(result)
    return combined


def _cross_non_pairing_slot(
    slot: _NonPairingSlot,
    shared: _IntervalSet,
    exact_state: _IntervalSet | None,
) -> tuple[_IntervalSet, str | None, _IntervalSet | None] | None:
    if slot.inner is None:
        if slot.is_boundary:
            return None
        return shared, None, None
    crossing = _group_crossing_result(slot.inner, shared, 0)
    group_state = _isolated_group_exact_state(slot.inner, 0)
    if crossing is None:
        fill = (
            _exact_overlap_fill_raw(exact_state, group_state)
            if slot.unbounded
            else None
        )
        if slot.is_boundary:
            if fill is None:
                return None
            return _IntervalSet.empty(), fill, group_state
        return shared, fill, group_state
    member = crossing.first_member()
    fill = chr(member) if slot.unbounded and member is not None else None
    result_shared = crossing if slot.is_boundary else shared
    return result_shared, fill, group_state


def _tail_pairing_intervals(slots: list[_Slot], start: int) -> list[_IntervalSet]:
    return [slot.intervals for slot in slots[start:] if isinstance(slot, _PairingAtom)]


def _fill_confirmed(left: _PairingAtom, right: _PairingAtom, fill: str) -> bool:
    left_predicate, right_predicate = left.predicate, right.predicate
    if left_predicate is None or right_predicate is None:
        return True
    return left_predicate(ord(fill)) and right_predicate(ord(fill))


def _left_confirms_fill(left: _PairingAtom, fill: str) -> bool:
    predicate = left.predicate
    if predicate is None:
        return True
    return predicate(ord(fill))


def _append_pairing_unit(
    units: list[tuple[str, str]],
    left: _PairingAtom,
    right: _PairingAtom,
    fill: str,
    tail: list[_IntervalSet],
    ctx: _StrayContext,
) -> None:
    if _fill_confirmed(left, right, fill):
        stray = choose_class_intersection_stray(
            ctx, fill, left.intervals, right.intervals, tail
        )
        units.append((fill, stray))


def _advance_pairing_chain(
    units: list[tuple[str, str]],
    left: _PairingAtom,
    shared: _IntervalSet,
    slot: _PairingAtom,
    exact_state: _IntervalSet | None,
    tail: list[_IntervalSet],
    ctx: _StrayContext,
) -> tuple[_IntervalSet, _IntervalSet | None, bool]:
    overlap = shared.intersection(slot.intervals)
    if not overlap.is_empty():
        if slot.unbounded:
            member = overlap.first_member()
            if member is None:
                raise RuntimeError("a non-empty interval set has no first member")
            _append_pairing_unit(units, left, slot, chr(member), tail, ctx)
        if not slot.allows_zero:
            shared = overlap
            exact_state = _narrow_exact_state_raw(exact_state, slot.intervals)
        return shared, exact_state, False
    exact_fill = _exact_overlap_fill_raw(exact_state, slot.intervals)
    if exact_fill is None:
        return shared, exact_state, not slot.allows_zero
    if slot.unbounded:
        _append_pairing_unit(units, left, slot, exact_fill, tail, ctx)
    if not slot.allows_zero:
        shared = overlap
        exact_state = None
    return shared, exact_state, False


def _pairing_units_from(
    slots: list[_Slot], start: int, ctx: _StrayContext
) -> list[tuple[str, str]]:
    left = slots[start]
    if not isinstance(left, _PairingAtom):
        return []
    shared = left.intervals
    exact_state: _IntervalSet | None = left.intervals
    units: list[tuple[str, str]] = []
    for index in range(start + 1, len(slots)):
        slot = slots[index]
        tail = _tail_pairing_intervals(slots, index + 1)
        if isinstance(slot, _NonPairingSlot):
            crossed = _cross_non_pairing_slot(slot, shared, exact_state)
            if crossed is None:
                break
            shared, fill, group_state = crossed
            if slot.is_boundary:
                exact_state = _narrow_exact_state_raw(exact_state, group_state)
            if fill is not None and _left_confirms_fill(left, fill):
                stray = choose_class_intersection_stray(
                    ctx, fill, left.intervals, shared, tail
                )
                units.append((fill, stray))
            continue
        shared, exact_state, should_stop = _advance_pairing_chain(
            units, left, shared, slot, exact_state, tail, ctx
        )
        if should_stop:
            break
    return units


def _flatten_alternatives(alternatives: list[list[_Slot]]) -> list[_Slot]:
    if len(alternatives) == 1:
        return alternatives[0]
    flat: list[_Slot] = []
    for index, alt in enumerate(alternatives):
        if index:
            flat.append(_NonPairingSlot(True, None))
        flat.extend(alt)
    return flat


def _units_in_group_alternatives(
    alternatives: list[list[_Slot]], ctx: _StrayContext
) -> list[tuple[str, str]]:
    return _units_in_slots(_flatten_alternatives(alternatives), ctx)


def _units_in_slots(slots: list[_Slot], ctx: _StrayContext) -> list[tuple[str, str]]:
    units: list[tuple[str, str]] = []
    for index, slot in enumerate(slots):
        if isinstance(slot, _NonPairingSlot):
            if slot.inner is not None:
                units.extend(_units_in_group_alternatives(slot.inner, ctx))
            continue
        if slot.unbounded:
            units.extend(_pairing_units_from(slots, index, ctx))
    return units


def _include_bounded_repeats(slots: list[_Slot]) -> list[_Slot]:
    result: list[_Slot] = []
    for slot in slots:
        repeating = slot.unbounded or (
            slot.max_repeat is not None and slot.max_repeat > 1
        )
        if isinstance(slot, _NonPairingSlot) and slot.inner is not None:
            slot = slot._replace(
                inner=[_include_bounded_repeats(alt) for alt in slot.inner]
            )
        result.append(slot._replace(unbounded=repeating))
    return result


def _class_intersection_probe_units(
    pattern: str,
    flags: int,
    ctx: _StrayContext | None = None,
    *,
    include_bounded: bool = False,
) -> list[tuple[str, str]]:
    slots = _pattern_slots(pattern, flags)
    if slots is None:
        return []
    if ctx is None:
        ctx = _build_stray_context(pattern, flags)
    if include_bounded:
        slots = _include_bounded_repeats(slots)
    return _units_in_slots(slots, ctx)


def _class_intersection_fills(pattern: str, flags: int) -> list[str]:
    return [fill for fill, _stray in _class_intersection_probe_units(pattern, flags)]
