from __future__ import annotations

import json
import signal
import subprocess
import sys
import time
from collections.abc import Callable, Iterable, Sequence
from typing import NamedTuple

from guard_core.detection_engine._redos_intervals import _IntervalSet
from guard_core.detection_engine._redos_parse_slots import (
    _NonPairingSlot,
    _PairingAtom,
    _pattern_slots,
    _Slot,
)
from guard_core.detection_engine._redos_structure import _find_group_end

_REACH_PROBE_STRAY_BYTE = "\x00"
_LEADING_PREFIX_METACHARS = frozenset(".^$*+?{}[]()|\\")
_STRAY_FALLBACK_CANDIDATES: tuple[str, ...] = (
    "\x00",
    "z",
    "\n",
    " ",
    "-",
    "\t",
    "\r",
    "9",
    "!",
    "~",
    "_",
    ".",
    "A",
    "\x1f",
    "\x7f",
    "/",
)
_STRAY_CANDIDATE_CAP = 16
_STRAY_VERIFY_FILL_COUNTS = (1, 2, 8)
_STRAY_VERIFY_TIMEOUT_SECONDS = 30.0
_STRAY_VERIFY_CPU_BUDGET_SECONDS = 0.5
_STRAY_VERIFY_CHILD_SCRIPT = (
    "import json, re, signal, sys\n"
    "if hasattr(signal, 'setitimer'):\n"
    f"    signal.setitimer(signal.ITIMER_PROF, {_STRAY_VERIFY_CPU_BUDGET_SECONDS})\n"
    "pattern, flags, cases = json.loads(sys.stdin.read())\n"
    "try:\n"
    "    compiled = re.compile(pattern, flags)\n"
    "except Exception:\n"
    "    print(json.dumps(None))\n"
    "    raise SystemExit(0)\n"
    "for candidate, probes in cases:\n"
    "    if all(compiled.search(probe) is None for probe in probes):\n"
    "        print(json.dumps(candidate))\n"
    "        raise SystemExit(0)\n"
    "print(json.dumps(None))\n"
)


def _unwrap_leading_transparent_group(pattern: str) -> str:
    text = pattern
    while text.startswith("(?:"):
        end = _find_group_end(text, 0)
        if end is None or end != len(text):
            break
        text = text[3 : end - 1]
    return text


def _leading_literal_prefix(pattern: str) -> str:
    text = _unwrap_leading_transparent_group(pattern)
    prefix: list[str] = []
    i = 0
    n = len(text)
    while i < n:
        c = text[i]
        if c == "\\" and i + 1 < n and not text[i + 1].isalnum():
            prefix.append(text[i + 1])
            i += 2
            continue
        if c in _LEADING_PREFIX_METACHARS:
            break
        prefix.append(c)
        i += 1
    return "".join(prefix)


def _fill_to_length(prefix: str, fill_char: str, stray: str, length: int) -> str:
    if length <= len(prefix):
        return prefix[:length]
    body_length = length - len(prefix)
    if body_length > 1:
        return prefix + fill_char * (body_length - 1) + stray
    return prefix + fill_char * body_length


def _repeat_probe_to_length(
    unit: str, length: int, stray: str = _REACH_PROBE_STRAY_BYTE
) -> str:
    if not unit:
        return unit
    reps = length // len(unit) + 1
    result = (unit * reps)[:length]
    homogeneous_unit = len(set(unit)) <= 1
    if homogeneous_unit or length % len(unit) == 0:
        result = result[:-1] + stray
    return result


def _stray_for_pair(left: _IntervalSet, right: _IntervalSet) -> str:
    member = left.union(right).complement().first_member()
    return chr(member) if member is not None else _REACH_PROBE_STRAY_BYTE


def _first_complement_char(intervals: _IntervalSet) -> str | None:
    member = intervals.complement().first_member()
    return chr(member) if member is not None else None


def _dedup_capped_candidates(candidates: Iterable[str | None]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for candidate in candidates:
        if candidate is None or candidate in seen:
            continue
        seen.add(candidate)
        result.append(candidate)
        if len(result) >= _STRAY_CANDIDATE_CAP:
            break
    return result


def _collect_pairing_intervals(slots: list[_Slot]) -> list[_IntervalSet]:
    collected: list[_IntervalSet] = []
    for slot in slots:
        if isinstance(slot, _PairingAtom):
            collected.append(slot.intervals)
        elif isinstance(slot, _NonPairingSlot) and slot.inner is not None:
            for alternative in slot.inner:
                collected.extend(_collect_pairing_intervals(alternative))
    return collected


def _pattern_class_union(pattern: str, flags: int) -> _IntervalSet:
    slots = _pattern_slots(pattern, flags)
    if slots is None:
        return _IntervalSet.empty()
    union = _IntervalSet.empty()
    for intervals in _collect_pairing_intervals(slots):
        union = union.union(intervals)
    return union


def _pattern_complement_chars(pattern: str, flags: int) -> list[str]:
    slots = _pattern_slots(pattern, flags)
    if slots is None:
        return []
    return list(
        dict.fromkeys(
            char
            for intervals in _collect_pairing_intervals(slots)
            if (char := _first_complement_char(intervals)) is not None
        )
    )


class _StrayContext(NamedTuple):
    pattern: str
    flags: int
    prefix: str
    pattern_union: _IntervalSet
    deadline: float | None = None


def _build_stray_context(
    pattern: str, flags: int, deadline: float | None = None
) -> _StrayContext:
    return _StrayContext(
        pattern,
        flags,
        _leading_literal_prefix(pattern),
        _pattern_class_union(pattern, flags),
        deadline,
    )


def _stray_verification_timeout(ctx: _StrayContext) -> float:
    if ctx.deadline is None:
        return _STRAY_VERIFY_TIMEOUT_SECONDS
    remaining = ctx.deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError(
            "Pattern validation probe construction exceeded its deadline"
        )
    return min(_STRAY_VERIFY_TIMEOUT_SECONDS, remaining)


def _choose_stray(
    candidates: list[str], verify: Callable[[str], bool], fallback: str
) -> str:
    for candidate in candidates:
        if verify(candidate):
            return candidate
    return fallback


def _first_bounded_forcing_candidate(
    ctx: _StrayContext, candidates: list[str], probes: list[list[str]]
) -> str | None:
    """Verify candidates in a killable child, never against untrusted regex inline.

    The child bounds its own CPU time (ITIMER_PROF, whose default action ends the
    process), so a safe pattern is never rejected because the machine is slow to
    start the child; the wall timeout only catches a child that never runs.
    """
    return _run_stray_verification_child(ctx, candidates, probes)


def _run_stray_verification_child(
    ctx: _StrayContext, candidates: list[str], probes: list[list[str]]
) -> str | None:
    timeout = _stray_verification_timeout(ctx)
    try:
        completed = subprocess.run(
            [sys.executable, "-S", "-I", "-c", _STRAY_VERIFY_CHILD_SCRIPT],
            input=json.dumps(
                [ctx.pattern, ctx.flags, list(zip(candidates, probes, strict=True))]
            ),
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        raise TimeoutError(
            "Pattern validation stray verification exceeded its "
            "killable-subprocess timeout"
        ) from exc
    except OSError as exc:
        raise TimeoutError(
            "Pattern validation stray verification killable-subprocess failed to run"
        ) from exc
    cpu_signal = getattr(signal, "SIGPROF", None)
    if cpu_signal is not None and completed.returncode == -cpu_signal:
        raise TimeoutError(
            "Pattern validation stray verification exceeded its CPU budget"
        )
    if completed.returncode != 0:
        raise TimeoutError(
            "Pattern validation stray verification "
            "killable-subprocess exited unexpectedly"
        )
    try:
        result = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise TimeoutError(
            "Pattern validation stray verification "
            "killable-subprocess returned malformed output"
        ) from exc
    if result is None:
        return None
    if isinstance(result, str) and result in candidates:
        return result
    raise TimeoutError(
        "Pattern validation stray verification "
        "killable-subprocess returned malformed output"
    )


def _class_intersection_stray_candidates(
    tail: Sequence[_IntervalSet],
    left: _IntervalSet,
    right: _IntervalSet,
    pattern_union: _IntervalSet,
) -> list[str]:
    ordered: list[str | None] = [
        _first_complement_char(intervals) for intervals in tail
    ]
    ordered.append(_first_complement_char(right))
    ordered.append(_first_complement_char(left.union(right)))
    ordered.append(_first_complement_char(pattern_union))
    ordered.extend(_STRAY_FALLBACK_CANDIDATES)
    return _dedup_capped_candidates(ordered)


def _class_intersection_probe_forces_failure(
    ctx: _StrayContext, fill_char: str, candidate: str
) -> bool:
    probes = [
        _fill_to_length(ctx.prefix, fill_char, candidate, len(ctx.prefix) + count + 1)
        for count in _STRAY_VERIFY_FILL_COUNTS
    ]
    return _first_bounded_forcing_candidate(ctx, [candidate], [probes]) == candidate


def choose_class_intersection_stray(
    ctx: _StrayContext,
    fill_char: str,
    left: _IntervalSet,
    right: _IntervalSet,
    tail: Sequence[_IntervalSet],
) -> str:
    candidates = _class_intersection_stray_candidates(
        tail, left, right, ctx.pattern_union
    )
    probes = [
        [
            _fill_to_length(
                ctx.prefix, fill_char, candidate, len(ctx.prefix) + count + 1
            )
            for count in _STRAY_VERIFY_FILL_COUNTS
        ]
        for candidate in candidates
    ]
    return _first_bounded_forcing_candidate(ctx, candidates, probes) or _stray_for_pair(
        left, right
    )


def _repeat_unit_stray_candidates(pattern_union: _IntervalSet) -> list[str]:
    ordered: list[str | None] = [_first_complement_char(pattern_union)]
    ordered.extend(_STRAY_FALLBACK_CANDIDATES)
    return _dedup_capped_candidates(ordered)


def choose_repeat_unit_stray(ctx: _StrayContext, unit: str) -> str:
    if not unit:
        return _REACH_PROBE_STRAY_BYTE
    candidates = _repeat_unit_stray_candidates(ctx.pattern_union)
    probes = [
        [
            _repeat_probe_to_length(unit, len(unit) * count, candidate)
            for count in _STRAY_VERIFY_FILL_COUNTS
        ]
        for candidate in candidates
    ]
    return (
        _first_bounded_forcing_candidate(ctx, candidates, probes)
        or _REACH_PROBE_STRAY_BYTE
    )
