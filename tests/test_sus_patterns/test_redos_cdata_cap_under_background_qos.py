import shutil
import subprocess
import sys
from collections.abc import Iterator

import pytest

pytestmark = pytest.mark.redos_timing

_CDATA_PATTERN = r"<!\[CDATA\[.*?\]\]>"
_SAFE_CAP = 1000
_UNSAFE_CAP = 16000
# The lowest mirror caps, 3 to 7 percent over the cost budget: 3.10 at 13000, 3.14 at
# 12000 (3.11 and later share 3.14's regex engine and its instruction counts).
_LOWEST_MIRROR_CAP = 13000 if sys.version_info < (3, 11) else 12000
_NEAR_BUDGET_CAPS = sorted({_LOWEST_MIRROR_CAP, 13000})
_REPEATS = 12
_BUSY_LOOPS = 4
_BUSY_LOOP_SOURCE = (
    "import os\nparent = os.getppid()\nwhile os.getppid() == parent: pass"
)
_CHILD_SOURCE = (
    "import sys\n"
    "from guard_core.detection_engine.compiler import PatternCompiler\n"
    "safe, _ = PatternCompiler().validate_pattern_safety(\n"
    "    sys.argv[1], max_content_length=int(sys.argv[2])\n"
    ")\n"
    "print('SAFE' if safe else 'UNSAFE')\n"
)


@pytest.fixture
def busy_loops() -> Iterator[None]:
    loops = [
        subprocess.Popen([sys.executable, "-c", _BUSY_LOOP_SOURCE])
        for _ in range(_BUSY_LOOPS)
    ]
    try:
        yield
    finally:
        for loop in loops:
            loop.terminate()
        for loop in loops:
            loop.wait()


def _background_prefix() -> list[str]:
    taskpolicy = shutil.which("taskpolicy")
    return [taskpolicy, "-b"] if taskpolicy else []


def _verdicts_in_fresh_processes(cap: int) -> list[str]:
    command = [
        *_background_prefix(),
        sys.executable,
        "-I",
        "-W",
        "ignore",
        "-c",
        _CHILD_SOURCE,
        _CDATA_PATTERN,
        str(cap),
    ]
    return [
        subprocess.run(
            command, capture_output=True, text=True, check=True, timeout=300
        ).stdout.strip()
        for _ in range(_REPEATS)
    ]


@pytest.mark.usefixtures("busy_loops")
def test_the_safe_cdata_pattern_is_accepted_on_every_core_beside_busy_loops() -> None:
    assert _verdicts_in_fresh_processes(_SAFE_CAP) == ["SAFE"] * _REPEATS


@pytest.mark.usefixtures("busy_loops")
def test_the_cdata_pattern_is_refused_with_margin_on_every_core_beside_busy_loops() -> (
    None
):
    assert _verdicts_in_fresh_processes(_UNSAFE_CAP) == ["UNSAFE"] * _REPEATS


@pytest.mark.usefixtures("busy_loops")
@pytest.mark.parametrize("cap", _NEAR_BUDGET_CAPS)
def test_the_cdata_pattern_just_over_the_work_budget_is_refused_beside_busy_loops(
    cap: int,
) -> None:
    assert _verdicts_in_fresh_processes(cap) == ["UNSAFE"] * _REPEATS
