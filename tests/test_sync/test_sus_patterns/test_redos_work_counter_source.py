import subprocess
import sys

from guard_core.sync.detection_engine._redos_work_counter import WORK_COUNTER_SOURCE

_CHILD = (
    "import re, sys\n"
    + WORK_COUNTER_SOURCE
    + "build_work_counter()\nprint('ctypes.util' in sys.modules)\n"
)


def test_building_the_counter_does_not_import_the_library_finder() -> None:
    completed = subprocess.run(
        [sys.executable, "-I", "-c", _CHILD],
        capture_output=True,
        text=True,
        check=True,
        timeout=60,
    )
    assert completed.stdout.strip() == "False"
