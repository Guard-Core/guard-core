import signal
import sys
import time

from tests.probe_child import run_probe_child


def test_a_probe_child_is_bounded_by_its_cpu_time_not_the_wall_clock() -> None:
    start = time.monotonic()
    completed = run_probe_child(
        [sys.executable, "-c", "while True: pass"], cpu_seconds=1
    )
    assert completed.returncode == -signal.SIGXCPU
    assert time.monotonic() - start < 8


def test_a_probe_child_hands_back_its_output() -> None:
    completed = run_probe_child(
        [sys.executable, "-c", "print('ok')"], cpu_seconds=30, check=True
    )
    assert completed.stdout == "ok\n"
