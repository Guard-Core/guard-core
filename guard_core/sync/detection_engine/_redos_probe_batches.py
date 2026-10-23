import hashlib
import json
import math
from collections.abc import Callable, Iterable, Iterator
from typing import Protocol, TypeGuard

from guard_core.sync.detection_engine._redos_cpu_budget import ReachProbeCpuBudget

_REACH_PROBE_BATCH_SIZE = 128


class _ReachProbeTimingLike(Protocol):
    @property
    def samples_by_size(self) -> list[list[float]]: ...

    @property
    def load_factor(self) -> float: ...


def _probe_set_digest(probes: tuple[str, ...]) -> bytes:
    digest = hashlib.sha256()
    digest.update(len(probes).to_bytes(4, "big"))
    for probe in probes:
        encoded = probe.encode("utf-8", "surrogatepass")
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
    return digest.digest()


def _valid_timing_rows(
    timing: _ReachProbeTimingLike | None, expected_rows: int
) -> tuple[list[list[float]], float] | None:
    if timing is None:
        return None
    try:
        rows = timing.samples_by_size
        load_factor = timing.load_factor
    except (AttributeError, TypeError):
        return None
    if (
        not isinstance(rows, list)
        or len(rows) != expected_rows
        or not _valid_load_factor(load_factor)
    ):
        return None
    if not all(_valid_sample_row(row) for row in rows):
        return None
    return rows, float(load_factor)


def _valid_load_factor(value: object) -> bool:
    return _valid_sample(value) and value > 0


def _valid_sample(value: object) -> TypeGuard[int | float]:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        return False
    try:
        return math.isfinite(value) and value >= 0
    except OverflowError:
        return False


def _valid_sample_row(row: object) -> bool:
    return (
        isinstance(row, list)
        and bool(row)
        and all(_valid_sample(value) for value in row)
    )


def _decoded_rows_valid(rows: object) -> TypeGuard[list[list[float]]]:
    return (
        isinstance(rows, list)
        and bool(rows)
        and all(_valid_sample_row(row) for row in rows)
    )


def _decode_reach_timing(stdout: str) -> tuple[list[list[float]], float] | None:
    try:
        result = json.loads(stdout.strip())
    except json.JSONDecodeError:
        return None
    if not isinstance(result, dict) or "error" in result:
        return None
    rows, reference = result.get("results"), result.get("reference")
    if not _decoded_rows_valid(rows) or not _valid_sample(reference):
        return None
    return [sorted(float(value) for value in row) for row in rows], float(reference)


def _batched_reach_probe_timings(
    pattern: str,
    probe_sets: Iterable[tuple[str, ...]],
    budget: ReachProbeCpuBudget,
    flags: int,
    time_probes: Callable[..., _ReachProbeTimingLike | None],
) -> Iterator[tuple[tuple[str, ...], list[list[float]] | None, float]]:
    batch: list[tuple[str, ...]] = []
    for probes in probe_sets:
        batch.append(probes)
        if len(batch) < _REACH_PROBE_BATCH_SIZE:
            continue
        yield from _measure_probe_batch(pattern, batch, budget, flags, time_probes)
        batch = []
    if batch:
        yield from _measure_probe_batch(pattern, batch, budget, flags, time_probes)


def _measure_probe_batch(
    pattern: str,
    batch: list[tuple[str, ...]],
    budget: ReachProbeCpuBudget,
    flags: int,
    time_probes: Callable[..., _ReachProbeTimingLike | None],
) -> Iterator[tuple[tuple[str, ...], list[list[float]] | None, float]]:
    flattened = [probe for probes in batch for probe in probes]
    timing = time_probes(pattern, flattened, budget, flags)
    valid = _valid_timing_rows(timing, len(flattened))
    if valid is None:
        yield from ((probes, None, 1.0) for probes in batch)
        return
    rows, load_factor = valid
    offset = 0
    for probes in batch:
        next_offset = offset + len(probes)
        yield probes, rows[offset:next_offset], load_factor
        offset = next_offset
