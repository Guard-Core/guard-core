import json
import subprocess
import sys
from pathlib import Path
from typing import Any, cast

_PROBE = Path(__file__).parent / "_scan_window_timing_probe.py"

_HANG_GUARD_SECONDS = 60
_BOUNDED_CPU_CEILING_SECONDS = 0.005
_LINEAR_GROWTH_CEILING = 3.0
_RAW_DOUBLING_RATIO_FLOOR = 3.0
_RAW_VS_BOUNDED_SLOWDOWN_FLOOR = 20.0


def _run_probe() -> dict[str, Any]:
    result = subprocess.run(
        [sys.executable, str(_PROBE)],
        capture_output=True,
        text=True,
        timeout=_HANG_GUARD_SECONDS,
    )
    assert result.returncode == 0, (
        f"timing probe subprocess failed:\n{result.stdout}\n{result.stderr}"
    )
    return cast(dict[str, Any], json.loads(result.stdout))


def test_bounded_scan_stays_under_five_milliseconds_on_all_three_fill_shapes() -> None:
    measured = _run_probe()["shapes"]

    for shape_name, shape_data in measured.items():
        sizes = shape_data["sizes"]
        bounded_min = [entry["min"] for entry in shape_data["bounded"]]
        # The ceiling is _BOUNDED_CPU_CEILING_SECONDS at the largest size and
        # scales linearly down. A breach has to repeat at every size: a
        # contention spike inflates one size's min-of-N (5.97ms against 5ms on
        # a loaded runner, 2.3ms measured idle), while a real regression, a
        # quadratic scan or a constant-factor slowdown, breaches all of them.
        ceilings = [_BOUNDED_CPU_CEILING_SECONDS * size / max(sizes) for size in sizes]
        assert any(
            cpu < ceiling for cpu, ceiling in zip(bounded_min, ceilings, strict=True)
        ), (
            f"{shape_name}: bounded CPU {bounded_min} exceeded the "
            f"{ceilings} ceilings at sizes={sizes}"
        )


def _assert_bounded_scan_grows_linearly() -> None:
    measured = _run_probe()["shapes"]

    for shape_name, shape_data in measured.items():
        bounded_min = [entry["min"] for entry in shape_data["bounded"]]
        growth = bounded_min[1] / bounded_min[0] if bounded_min[0] > 0 else 0.0
        assert growth < _LINEAR_GROWTH_CEILING, (
            f"{shape_name}: bounded CPU grew {growth:.2f}x for a 2x size "
            f"increase, across {bounded_min} (cpu seconds)"
        )


def test_bounded_scan_grows_linearly_across_a_size_doubling() -> None:
    try:
        _assert_bounded_scan_grows_linearly()
    except AssertionError:
        _assert_bounded_scan_grows_linearly()


def test_bounded_scan_is_dramatically_faster_than_raw_when_terminator_is_absent() -> (
    None
):
    demo = _run_probe()["raw_quadratic_demo"]

    raw_min = [entry["min"] for entry in demo["raw"]]
    bounded_min = [entry["min"] for entry in demo["bounded"]]

    assert raw_min[-1] / raw_min[0] > _RAW_DOUBLING_RATIO_FLOOR, (
        "raw quadratic search no longer demonstrates blowup across "
        f"{raw_min} (cpu seconds)"
    )
    assert raw_min[-1] > bounded_min[-1] * _RAW_VS_BOUNDED_SLOWDOWN_FLOOR, (
        "raw quadratic search was not dramatically slower than the bounded "
        f"scan at the largest fill: raw={raw_min[-1]:.6f}s "
        f"bounded={bounded_min[-1]:.6f}s"
    )
