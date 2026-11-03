import subprocess
import sys
from collections.abc import Callable

_WALL_PER_CPU_SECOND = 10


def _limit_cpu_seconds(seconds: int) -> Callable[[], None]:
    def apply() -> None:
        import resource

        resource.setrlimit(resource.RLIMIT_CPU, (seconds, seconds + 1))

    return apply


def run_probe_child(
    args: list[str], cpu_seconds: int, check: bool = False
) -> subprocess.CompletedProcess[str]:
    # A timing child is bounded by the CPU it burns, which does not stretch with host
    # load; the wall timeout is only a backstop for a child that hangs without burning
    # CPU, and is wide enough for a loaded host (LEDGER 6.517).
    return subprocess.run(
        args,
        capture_output=True,
        text=True,
        timeout=cpu_seconds * _WALL_PER_CPU_SECOND,
        preexec_fn=None if sys.platform == "win32" else _limit_cpu_seconds(cpu_seconds),
        check=check,
    )
