import json
import logging
import math
import re
import subprocess
import sys
import time
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass

from guard_core.sync.detection_engine._redos_probe_batches import (
    _REACH_PROBE_BATCH_SIZE,
    _batched_reach_probe_timings,
    _decode_reach_timing,
    _probe_set_digest,
    _valid_timing_rows,
)
from guard_core.sync.detection_engine._redos_probe_fill import (
    _reach_probe_candidate_builders,
)
from guard_core.sync.detection_engine._redos_reach_probe import (
    _synthesize_reaching_probe,
)
from guard_core.sync.detection_engine._redos_repeat_alphabet import (
    _has_large_bounded_repeat,
)
from guard_core.sync.detection_engine._redos_structural_prefilters import (
    _first_structural_safety_violation,
)

logger = logging.getLogger("guard_core.sync.detection_engine.compiler")

_DEFAULT_PATTERN_FLAGS = re.IGNORECASE | re.MULTILINE

_PATTERN_SAFETY_PROBE_TIMEOUT_SECONDS = 2.0
_PATTERN_SAFETY_PROBE_PER_STRING_THRESHOLD_SECONDS = 0.05

_PATTERN_SAFETY_PROBE_CHILD_SCRIPT = (
    "import json, re, sys, time\n"
    "pattern, test_strings, threshold, flags = json.loads(sys.stdin.read())\n"
    "try:\n"
    "    compiled = re.compile(pattern, flags)\n"
    "except Exception as exc:\n"
    "    print(json.dumps({'safe': False, "
    "'reason': f'Pattern validation failed: {exc}'}))\n"
    "    raise SystemExit(0)\n"
    "for test_str in test_strings:\n"
    "    start = time.process_time()\n"
    "    compiled.search(test_str)\n"
    "    elapsed = time.process_time() - start\n"
    "    if elapsed > threshold:\n"
    "        reason = f'Pattern timed out on test string of length {len(test_str)}'\n"
    "        print(json.dumps({'safe': False, 'reason': reason}))\n"
    "        raise SystemExit(0)\n"
    "print(json.dumps({'safe': True, 'reason': 'Pattern appears safe'}))\n"
)


def _run_pattern_safety_probe_subprocess(
    pattern: str, test_strings: list[str], flags: int
) -> tuple[bool, str]:
    payload = json.dumps(
        [
            pattern,
            test_strings,
            _PATTERN_SAFETY_PROBE_PER_STRING_THRESHOLD_SECONDS,
            flags,
        ]
    )
    try:
        completed = subprocess.run(
            [sys.executable, "-S", "-I", "-c", _PATTERN_SAFETY_PROBE_CHILD_SCRIPT],
            input=payload,
            capture_output=True,
            text=True,
            timeout=_PATTERN_SAFETY_PROBE_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired:
        return (
            False,
            "Pattern validation probe exceeded the "
            f"{_PATTERN_SAFETY_PROBE_TIMEOUT_SECONDS}s killable-subprocess timeout",
        )
    except Exception as e:
        return False, f"Pattern validation probe failed to run: {str(e)}"

    if completed.returncode != 0 or not completed.stdout.strip():
        return (
            False,
            f"Pattern validation probe failed: {completed.stderr.strip()[:200]}",
        )

    try:
        result = json.loads(completed.stdout.strip())
        return bool(result["safe"]), str(result["reason"])
    except (json.JSONDecodeError, KeyError, TypeError) as e:
        return False, f"Pattern validation probe returned malformed output: {str(e)}"


_REACH_PROBE_SIZES = (4000, 8000, 16000, 32000)
_REACH_VERDICT_PROBE_SIZES = _REACH_PROBE_SIZES[-2:]
_REACH_PROBE_BUDGET_SECONDS = 0.05
_REFERENCE_SCAN_PATTERN = (
    r"(?i)/[0-9]*\s*(?:OR|AND|UNION|SELECT|INSERT|DELETE|DROP|CONCAT|CHAR|UPDATE)\b"
)
_REFERENCE_SCAN_PROBE_LENGTH = 32000
_REFERENCE_SCAN_SECONDS = 0.00229
_LOAD_FACTOR_FLOOR = 0.25
_LOAD_FACTOR_CEILING = 8.0
_REACH_PROBE_NOISE_FLOOR_SECONDS = 0.001
_REACH_PROBE_SAMPLE_COUNT = 5
_REACH_PROBE_LARGE_SAMPLE_SECONDS = 0.2
# The verdict forces the growth ratio to 1.0 while the 16000-char minimum
# sample stays under the noise floor, so one sample decides such probes and
# they cannot read over budget; at or above the trigger the full sample
# count is taken, which is also where host noise matters most.
_REACH_PROBE_FULL_SAMPLE_TRIGGER_SECONDS = _REACH_PROBE_NOISE_FLOOR_SECONDS
_PATTERN_SAFETY_DEFAULT_CAP = 262144
# Probe families multiply (pair sites x strays x prefixes x flood variants),
# and timing every set is wall-clock the verdict deadline cannot cover. A
# stride sample keeps every family and site represented while bounding the
# timed work; the cap only engages when the enumeration explodes.
_MAX_TIMED_PROBE_SETS = 512
# Sample times are normalized by a host load factor, but the wall-clock
# deadline is not: measuring a genuinely quadratic pattern costs seconds of
# CPU per probe set, and under a loaded runner the same CPU work needs a
# proportionally larger wall budget. The verdict deadline scales by the
# measured load factor, floored at the idle-host behavior and ceiled to
# stay inside the per-test wall budget.
_REACH_PROBE_DEADLINE_SCALE_CEILING_SECONDS = 240.0
_REFERENCE_LOAD_PROBE_TIMEOUT_SECONDS = 5.0

_REFERENCE_LOAD_CHILD_SCRIPT = (
    "import json, re, sys, time\n"
    "json.loads(sys.stdin.read())\n"
    f"reference_compiled = re.compile({_REFERENCE_SCAN_PATTERN!r})\n"
    f"reference_probe = '/' + '0' * {_REFERENCE_SCAN_PROBE_LENGTH}\n"
    "reference_times = []\n"
    f"for _ in range({_REACH_PROBE_SAMPLE_COUNT}):\n"
    "    start = time.process_time()\n"
    "    reference_compiled.search(reference_probe)\n"
    "    reference_times.append(time.process_time() - start)\n"
    "print(json.dumps({'reference': min(reference_times)}))\n"
)

_REACH_PROBE_TIMING_CHILD_SCRIPT = (
    "import json, math, re, signal, sys, time\n"
    "pattern, probes, samples, deadline, flags, trigger = json.loads(\n"
    "    sys.stdin.read())\n"
    "if hasattr(signal, 'alarm'):\n"
    "    signal.alarm(math.ceil(deadline))\n"
    "try:\n"
    "    compiled = re.compile(pattern, flags)\n"
    "except Exception as exc:\n"
    "    print(json.dumps({'error': str(exc)}))\n"
    "    raise SystemExit(0)\n"
    f"reference_compiled = re.compile({_REFERENCE_SCAN_PATTERN!r})\n"
    f"reference_probe = '/' + '0' * {_REFERENCE_SCAN_PROBE_LENGTH}\n"
    "reference_times = []\n"
    "for _ in range(samples):\n"
    "    start = time.process_time()\n"
    "    reference_compiled.search(reference_probe)\n"
    "    reference_times.append(time.process_time() - start)\n"
    "results = []\n"
    "for probe in probes:\n"
    "    start = time.process_time()\n"
    "    compiled.search(probe)\n"
    "    probe_times = [time.process_time() - start]\n"
    "    if probe_times[0] >= trigger:\n"
    "        for _ in range(samples - 1):\n"
    "            start = time.process_time()\n"
    "            compiled.search(probe)\n"
    "            probe_times.append(time.process_time() - start)\n"
    f"            if probe_times[-1] > {_REACH_PROBE_LARGE_SAMPLE_SECONDS}:\n"
    "                break\n"
    "    probe_times.sort()\n"
    "    results.append(probe_times)\n"
    "print(json.dumps({'results': results, 'reference': min(reference_times)}))\n"
)


@dataclass(frozen=True, slots=True)
class ReachProbeTiming:
    samples_by_size: list[list[float]]
    load_factor: float


def _load_factor(reference_seconds: float) -> float:
    raw = reference_seconds / _REFERENCE_SCAN_SECONDS
    return min(max(raw, _LOAD_FACTOR_FLOOR), _LOAD_FACTOR_CEILING)


def _measure_host_load_factor() -> float:
    try:
        completed = subprocess.run(
            [sys.executable, "-S", "-I", "-c", _REFERENCE_LOAD_CHILD_SCRIPT],
            input=json.dumps([]),
            capture_output=True,
            text=True,
            timeout=_REFERENCE_LOAD_PROBE_TIMEOUT_SECONDS,
        )
    except Exception:
        return 1.0
    try:
        result = json.loads(completed.stdout.strip())
        return _load_factor(float(result["reference"]))
    except (json.JSONDecodeError, KeyError, TypeError, ValueError):
        return 1.0


def _scaled_probe_deadline_seconds(load_factor: float) -> float:
    return min(
        _REACH_PROBE_COMBINED_TIMEOUT_SECONDS * max(load_factor, 1.0),
        _REACH_PROBE_DEADLINE_SCALE_CEILING_SECONDS,
    )


def _parse_reach_probe_child_output(stdout: str) -> ReachProbeTiming | None:
    decoded = _decode_reach_timing(stdout)
    if decoded is None:
        return None
    rows, reference = decoded
    return ReachProbeTiming(rows, _load_factor(reference))


_REACH_PROBE_CHILD_START_ALLOWANCE_SECONDS = 0.5
_REACH_PROBE_CHILD_TIMEOUT_SECONDS = (
    _PATTERN_SAFETY_PROBE_TIMEOUT_SECONDS + _REACH_PROBE_CHILD_START_ALLOWANCE_SECONDS
)
_REACH_PROBE_COMBINED_TIMEOUT_SECONDS = (
    _PATTERN_SAFETY_PROBE_TIMEOUT_SECONDS
    * len(_REACH_PROBE_SIZES)
    * _REACH_PROBE_SAMPLE_COUNT
)


def _remaining_budget(deadline: float) -> float:
    return deadline - time.monotonic()


def _clipped_timeout(default_timeout: float, deadline: float) -> float:
    return min(default_timeout, _remaining_budget(deadline))


def _run_reach_probe_child(
    pattern: str, probes: list[str], timeout: float, flags: int
) -> ReachProbeTiming | None:
    payload = json.dumps(
        [
            pattern,
            probes,
            _REACH_PROBE_SAMPLE_COUNT,
            timeout,
            flags,
            _REACH_PROBE_FULL_SAMPLE_TRIGGER_SECONDS,
        ]
    )
    try:
        completed = subprocess.run(
            [sys.executable, "-S", "-I", "-c", _REACH_PROBE_TIMING_CHILD_SCRIPT],
            input=payload,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except Exception:
        return None
    if completed.returncode != 0 or not completed.stdout.strip():
        return None
    return _parse_reach_probe_child_output(completed.stdout)


def _time_reach_probes_subprocess(
    pattern: str,
    probes: list[str],
    deadline: float,
    flags: int = _DEFAULT_PATTERN_FLAGS,
) -> ReachProbeTiming | None:
    timeout = _clipped_timeout(_REACH_PROBE_COMBINED_TIMEOUT_SECONDS, deadline)
    if timeout <= 0:
        return None
    return _run_reach_probe_child(pattern, probes, timeout, flags)


def _time_single_reach_probe_subprocess(
    pattern: str,
    probe: str,
    deadline: float,
    flags: int = _DEFAULT_PATTERN_FLAGS,
) -> ReachProbeTiming | None:
    timeout = _clipped_timeout(_REACH_PROBE_CHILD_TIMEOUT_SECONDS, deadline)
    if timeout <= 0:
        return None
    return _run_reach_probe_child(pattern, [probe], timeout, flags)


def _time_reach_probes_ascending(
    pattern: str,
    probes: list[str],
    deadline: float,
    flags: int = _DEFAULT_PATTERN_FLAGS,
) -> ReachProbeTiming | None:
    samples_by_size: list[list[float]] = []
    load_factor = _LOAD_FACTOR_CEILING
    for probe in probes:
        timing = _time_single_reach_probe_subprocess(pattern, probe, deadline, flags)
        if timing is None:
            return None
        samples_by_size.extend(timing.samples_by_size)
        load_factor = min(load_factor, timing.load_factor)
    return ReachProbeTiming(samples_by_size, load_factor)


def _median(samples: list[float]) -> float:
    return samples[len(samples) // 2]


def _reach_probe_verdict_from_samples(
    samples_by_size: list[list[float]], cap: int, load_factor: float = 1.0
) -> tuple[bool, float, float, float, float]:
    median_32 = _median(samples_by_size[-1]) / load_factor
    min_16 = samples_by_size[-2][0] / load_factor
    min_32 = samples_by_size[-1][0] / load_factor
    ratio = (
        max(min_32 / min_16, 1.0) if min_16 > _REACH_PROBE_NOISE_FLOOR_SECONDS else 1.0
    )
    doublings = math.log2(max(cap, 1) / _REACH_PROBE_SIZES[3])
    extrapolated = min_32 * (ratio**doublings) if ratio > 0 else min_32
    over_budget = extrapolated > _REACH_PROBE_BUDGET_SECONDS
    return over_budget, extrapolated, ratio, min_32, median_32


def _reach_probe_cost_reason(
    structural_violation: str | None,
    extrapolated: float,
    ratio: float,
    cap: int,
    min_32: float,
    median_32: float,
    load_factor: float = 1.0,
) -> str:
    if structural_violation is not None:
        return structural_violation
    return (
        f"Pattern extrapolated CPU cost at cap ({cap} chars) is {extrapolated:.3f}s, "
        f"exceeding the {_REACH_PROBE_BUDGET_SECONDS}s safety budget "
        f"(growth ratio {ratio:.2f}x per doubling, CPU time at 32000 chars: "
        f"min {min_32:.4f}s, median {median_32:.4f}s over "
        f"{_REACH_PROBE_SAMPLE_COUNT} runs, normalized by host load factor "
        f"{load_factor:.2f})"
    )


def _reach_probe_unreachable_reason(structural_violation: str | None) -> str:
    if structural_violation is not None:
        return structural_violation
    return (
        "Pattern validation probe could not construct a test string that "
        "reaches every quantified region of this pattern; rejecting rather "
        "than certifying safety on an unreachable probe"
    )


def _log_structural_disagreement(
    pattern: str, structural_violation: str, cap: int, reason: str
) -> None:
    from guard_core.sync._utils.detection_scan import _redact_pattern_source

    logger.warning(
        "guard_core pattern safety: structural rule flagged %r (%s) but %s; accepting",
        _redact_pattern_source(pattern),
        structural_violation,
        reason,
    )


def _reach_probe_timing_strategy(
    structural_violation: str | None, bounded_repeat_risk: bool = False
) -> Callable[[str, list[str], float, int], ReachProbeTiming | None]:
    if structural_violation is not None or bounded_repeat_risk:
        return _time_reach_probes_ascending
    return _time_reach_probes_subprocess


def _reach_probe_sizes_for_strategy(
    structural_violation: str | None, bounded_repeat_risk: bool = False
) -> tuple[int, ...]:
    if structural_violation is not None or bounded_repeat_risk:
        return _REACH_PROBE_SIZES
    return _REACH_VERDICT_PROBE_SIZES


def _unique_probe_sets(
    builders: list[Callable[[int], str]], probe_sizes: tuple[int, ...]
) -> Iterator[tuple[str, ...]]:
    seen: set[bytes] = set()
    for builder in builders:
        probes = tuple(builder(size) for size in probe_sizes)
        digest = _probe_set_digest(probes)
        if digest in seen:
            continue
        seen.add(digest)
        yield probes


def _stride_sampled_probe_sets(
    probe_sets: list[tuple[str, ...]], cap: int
) -> list[tuple[str, ...]]:
    total = len(probe_sets)
    if total <= cap:
        return probe_sets
    stride = math.ceil(total / cap)
    sampled = probe_sets[::stride]
    logger.debug(
        "guard_core pattern safety: timing %d of %d unique probe sets "
        "(stride %d) to fit the validation deadline",
        len(sampled),
        total,
        stride,
    )
    return sampled


def _direct_reach_probe_timings(
    pattern: str,
    probe_sets: Iterable[tuple[str, ...]],
    deadline: float,
    flags: int,
    time_probes: Callable[..., ReachProbeTiming | None],
) -> Iterator[tuple[tuple[str, ...], list[list[float]] | None, float]]:
    for probes in probe_sets:
        timing = time_probes(pattern, list(probes), deadline, flags)
        validated = _valid_timing_rows(timing, len(probes))
        if validated is None:
            yield probes, None, 1.0
        else:
            yield probes, *validated


def _timed_probe_results(
    pattern: str,
    builders: list[Callable[[int], str]],
    deadline: float,
    flags: int,
    structural_violation: str | None,
    bounded_repeat_risk: bool,
) -> Iterator[tuple[tuple[str, ...], list[list[float]] | None, float]]:
    time_probes = _reach_probe_timing_strategy(
        structural_violation, bounded_repeat_risk
    )
    probe_sizes = _reach_probe_sizes_for_strategy(
        structural_violation, bounded_repeat_risk
    )
    probe_sets = _stride_sampled_probe_sets(
        list(_unique_probe_sets(builders, probe_sizes)), _MAX_TIMED_PROBE_SETS
    )
    if (
        structural_violation is None
        and not bounded_repeat_risk
        and len(builders) >= _REACH_PROBE_BATCH_SIZE
    ):
        return _batched_reach_probe_timings(
            pattern,
            iter(probe_sets),
            deadline,
            flags,
            time_probes,
        )
    return _direct_reach_probe_timings(
        pattern,
        iter(probe_sets),
        deadline,
        flags,
        time_probes,
    )


def _retry_reach_probe_timing(
    pattern: str,
    probes: tuple[str, ...],
    deadline: float,
    flags: int,
    time_probes: Callable[..., ReachProbeTiming | None],
) -> ReachProbeTiming | None:
    validated = _valid_timing_rows(
        time_probes(pattern, list(probes), deadline, flags), len(probes)
    )
    return None if validated is None else ReachProbeTiming(*validated)


def _first_over_budget_reason(
    pattern: str,
    builders: list[Callable[[int], str]],
    cap: int,
    structural_violation: str | None,
    deadline: float,
    flags: int = _DEFAULT_PATTERN_FLAGS,
    bounded_repeat_risk: bool = False,
) -> str | None:
    time_probes = _reach_probe_timing_strategy(
        structural_violation, bounded_repeat_risk
    )
    timed_probe_results = _timed_probe_results(
        pattern, builders, deadline, flags, structural_violation, bounded_repeat_risk
    )
    for probes, sample_rows, load_factor in timed_probe_results:
        timing = (
            None if sample_rows is None else ReachProbeTiming(sample_rows, load_factor)
        )
        if timing is None:
            return (
                structural_violation
                or "Pattern validation probe exceeded the killable-subprocess "
                "timeout while measuring reach-probe cost at scale"
            )
        over, extrapolated, ratio, min_32, median_32 = (
            _reach_probe_verdict_from_samples(
                timing.samples_by_size, cap, timing.load_factor
            )
        )
        if over and _remaining_budget(deadline) > 0:
            retry = _retry_reach_probe_timing(
                pattern, probes, deadline, flags, time_probes
            )
            if retry is not None:
                timing = retry
                over, extrapolated, ratio, min_32, median_32 = (
                    _reach_probe_verdict_from_samples(
                        timing.samples_by_size, cap, timing.load_factor
                    )
                )
        if over:
            return _reach_probe_cost_reason(
                structural_violation,
                extrapolated,
                ratio,
                cap,
                min_32,
                median_32,
                timing.load_factor,
            )
    return None


def _reach_probe_cost_verdict(
    pattern: str,
    max_content_length: int | None,
    flags: int = _DEFAULT_PATTERN_FLAGS,
) -> tuple[bool, str]:
    deadline = time.monotonic() + _scaled_probe_deadline_seconds(
        _measure_host_load_factor()
    )
    cap = max_content_length if max_content_length else _PATTERN_SAFETY_DEFAULT_CAP
    structural_violation = _first_structural_safety_violation(pattern)
    bounded_repeat_risk = _has_large_bounded_repeat(pattern, flags)
    if _synthesize_reaching_probe(pattern) is None:
        return False, _reach_probe_unreachable_reason(structural_violation)

    try:
        builders = _reach_probe_candidate_builders(pattern, flags, deadline)
    except TimeoutError as exc:
        return False, structural_violation or str(exc)
    if _remaining_budget(deadline) <= 0:
        return False, "Pattern validation probe construction exceeded its deadline"
    if not builders:
        if structural_violation is not None:
            _log_structural_disagreement(
                pattern,
                structural_violation,
                cap,
                "no repeatable adversarial trigger could be extracted to time",
            )
        return True, "Pattern appears safe"

    over_budget_reason = _first_over_budget_reason(
        pattern,
        builders,
        cap,
        structural_violation,
        deadline,
        flags,
        bounded_repeat_risk,
    )
    if over_budget_reason is not None:
        return False, over_budget_reason

    if structural_violation is not None:
        _log_structural_disagreement(
            pattern,
            structural_violation,
            cap,
            f"the timed reach-probe measured it under budget and linear at cap {cap}",
        )
    return True, "Pattern appears safe"
