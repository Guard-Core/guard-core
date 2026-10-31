import os
import signal
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable
from typing import NamedTuple

# A child limits itself by CPU time, never by the wall clock: an ITIMER_PROF timer
# (SIGPROF, default action) at its CPU limit kills it, and a loaded host that leaves
# it waiting in the run queue spends none of that limit. An ITIMER_VIRTUAL timer
# writes one byte to stderr per heartbeat of its own CPU time, so the parent can tell
# a child that makes no CPU progress from one that is only scheduled late. The
# prelude expects `cpu_limit` and `heartbeat` to be defined; `disarm` runs before the
# report (a timer firing after the interpreter dropped its handlers kills the child
# by its default action).
CPU_LIMIT_PRELUDE = (
    "import os, signal\n"
    "for _name in ('SIGPROF', 'SIGVTALRM'):\n"
    "    if hasattr(signal, _name):\n"
    "        signal.signal(getattr(signal, _name), signal.SIG_DFL)\n"
    "def beat(signum, frame):\n"
    "    try:\n"
    "        os.write(2, b'.')\n"
    "    except OSError:\n"
    "        pass\n"
    "def arm():\n"
    "    if hasattr(signal, 'setitimer'):\n"
    "        signal.setitimer(signal.ITIMER_PROF, cpu_limit)\n"
    "        signal.signal(signal.SIGVTALRM, beat)\n"
    "        signal.setitimer(signal.ITIMER_VIRTUAL, heartbeat, heartbeat)\n"
    "def disarm():\n"
    "    if hasattr(signal, 'setitimer'):\n"
    "        for _timer in (signal.ITIMER_VIRTUAL, signal.ITIMER_PROF):\n"
    "            signal.setitimer(_timer, 0)\n"
)

HEARTBEAT_CPU_SECONDS = 0.25
# Wall time is only the backstop for a child that reports no CPU progress at all
# (stopped, or starved of every slice): a late-scheduled child still beats within
# 0.25 CPU seconds, so this window holds down to a 1% share of one core.
STALL_WALL_SECONDS = 30.0
STALL_POLL_SECONDS = 0.5


class ChildResult(NamedTuple):
    returncode: int
    stdout: str
    stderr: str


def killed_by_cpu_limit(result: ChildResult) -> bool:
    cpu_signal = getattr(signal, "SIGPROF", None)
    return cpu_signal is not None and result.returncode == -cpu_signal


def communicate_until_stalled(
    process: "subprocess.Popen[str]",
    payload: str,
    progress_marks: Callable[[], int],
    stall_seconds: float,
) -> tuple[str, str] | None:
    last_marks = 0
    last_progress = time.monotonic()
    pending: str | None = payload
    while True:
        try:
            return process.communicate(pending, timeout=STALL_POLL_SECONDS)
        except subprocess.TimeoutExpired:
            pending = None
        marks = progress_marks()
        now = time.monotonic()
        if marks != last_marks:
            last_marks, last_progress = marks, now
        elif now - last_progress > stall_seconds:
            process.kill()
            process.communicate()
            return None


def run_limited_child(
    script: str, payload: str, cpu_limit: float
) -> ChildResult | None:
    """Run a python child; None means it showed no CPU progress for the stall window.

    Without setitimer (Windows) the child can neither beat nor kill itself, so the
    stall window falls back to the CPU limit, the old wall-clock behavior there.
    """
    stall_seconds = STALL_WALL_SECONDS if hasattr(signal, "setitimer") else cpu_limit
    # The payload goes in through a file, never a pipe: on Python 3.10 to 3.13 a
    # communicate() retry after a timeout does not resume writing the input, so a
    # child that starts late would wait forever for the rest of a payload larger than
    # the pipe buffer and be killed as stalled.
    with tempfile.TemporaryFile() as heartbeats, tempfile.TemporaryFile() as stdin:
        stdin.write(payload.encode())
        stdin.seek(0)
        process = subprocess.Popen(
            [sys.executable, "-S", "-I", "-c", script],
            stdin=stdin,
            stdout=subprocess.PIPE,
            stderr=heartbeats,
            text=True,
        )
        output = communicate_until_stalled(
            process,
            "",
            lambda: os.fstat(heartbeats.fileno()).st_size,
            stall_seconds,
        )
        if output is None:
            return None
        heartbeats.seek(0)
        stderr = heartbeats.read().decode(errors="replace").replace(".", "")
    return ChildResult(process.returncode, output[0], stderr)
