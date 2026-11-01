import json
import subprocess
import sys
from pathlib import Path

import pytest

from tests.host_load_factor import run_with_host_load_factor

_PROBE = Path(__file__).parent / "_scan_window_cap_removal_timing_probe.py"

_MAX_CPU_TIME_AT_LARGEST_SIZE_SECONDS = 0.10
_DOUBLING_RATIO_CEILING = 3.0
_NOISE_FLOOR_SECONDS = 0.001

_EXPECTED_LABELS = {
    "ldap_null_byte_attr",
    "ldap_null_byte_decoded_attr",
    "quote_splice",
}


def _assert_doubling_stays_linear(times: list[float], label: str) -> None:
    ratios: list[float] = []
    longest_run = current_run = 0
    for earlier, later in zip(times, times[1:], strict=False):
        if earlier < _NOISE_FLOOR_SECONDS:
            continue
        ratio = later / earlier
        ratios.append(ratio)
        if ratio >= _DOUBLING_RATIO_CEILING:
            current_run += 1
            longest_run = max(longest_run, current_run)
        else:
            current_run = 0
    assert longest_run < 2, (
        f"{label} CPU-time doubling ratio stayed super-linear across "
        f"consecutive doublings: ratios {ratios} across {times}"
    )


def _run_cap_removal_probe() -> tuple[dict[str, dict[str, list[float]]], float]:
    result, load_factor = run_with_host_load_factor(
        lambda: subprocess.run(
            [sys.executable, str(_PROBE)],
            capture_output=True,
            text=True,
            timeout=90,
        )
    )

    assert result.returncode == 0, (
        f"timing probe subprocess failed:\n{result.stdout}\n{result.stderr}"
    )

    measured: dict[str, dict[str, list[float]]] = json.loads(result.stdout)
    assert set(measured) == _EXPECTED_LABELS
    return measured, load_factor


def _assert_cap_removal_timings_within_bounds(
    measured: dict[str, dict[str, list[float]]], load_factor: float
) -> None:
    for label, series in measured.items():
        min_times = series["min"]
        median_times = series["median"]
        assert median_times[-1] / load_factor < _MAX_CPU_TIME_AT_LARGEST_SIZE_SECONDS, (
            f"{label} exceeded the 100ms CPU-time budget at the largest "
            f"adversarial fill (median of 5): {median_times[-1]:.4f}s"
        )
        _assert_doubling_stays_linear(min_times, label)


@pytest.mark.redos_timing
def test_the_three_converted_patterns_stay_under_the_cpu_time_budget() -> None:
    measured, load_factor = _run_cap_removal_probe()
    try:
        _assert_cap_removal_timings_within_bounds(measured, load_factor)
    except AssertionError:
        _assert_cap_removal_timings_within_bounds(*_run_cap_removal_probe())
