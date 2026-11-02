import json
import signal
import subprocess
import sys

from guard_core.sync.detection_engine._redos_cost_arbiter import (
    _reach_probe_timing_child_script,
)
from guard_core.sync.detection_engine._redos_work_counter import NO_POLL_COUNTER_SOURCE

_NO_INSTRUCTION_COUNTER = "def build_work_counter():\n    return None\n"
_CPU_LIMIT_SECONDS = 100.0


def _reference_scan_timer_readings() -> tuple[list[float], float]:
    script = _reach_probe_timing_child_script(
        _NO_INSTRUCTION_COUNTER, NO_POLL_COUNTER_SOURCE
    )
    script = script.replace(
        "reference_times.append(time.process_time() - start)",
        "reference_times.append(time.process_time() - start); "
        "sys.stderr.write('REF %r\\n' % signal.getitimer(signal.ITIMER_PROF)[0])",
    ).replace(
        "poller = build_poll_counter()\n",
        "sys.stderr.write('AFTER %r\\n' % signal.getitimer(signal.ITIMER_PROF)[0])\n"
        "poller = build_poll_counter()\n",
    )
    payload = json.dumps(["a", ["a"], 5, _CPU_LIMIT_SECONDS, 0, 0.001, 0.25])
    completed = subprocess.run(
        [sys.executable, "-c", script],
        input=payload,
        capture_output=True,
        text=True,
        timeout=60,
        check=True,
    )
    lines = [line.split() for line in completed.stderr.splitlines()]
    during = [float(value) for tag, value in lines if tag == "REF"]
    after = [float(value) for tag, value in lines if tag == "AFTER"]
    assert len(after) == 1
    return during, after[0]


def test_the_reference_scan_runs_with_the_cpu_timers_disarmed() -> None:
    # An armed ITIMER_PROF made the 2 ms reference scans read 15 to 30 percent low on
    # Linux (python:3.14-slim: load factor 0.69 to 0.87 against 1.0 in a child with no
    # timer), which inflated every later sample of the child by the same share.
    during, _ = _reference_scan_timer_readings()
    assert during == [0.0] * 5
    assert hasattr(signal, "ITIMER_PROF")


def test_the_cpu_limit_is_armed_again_for_the_probes_with_what_remains() -> None:
    _, after = _reference_scan_timer_readings()
    assert 0.0 < after <= _CPU_LIMIT_SECONDS
