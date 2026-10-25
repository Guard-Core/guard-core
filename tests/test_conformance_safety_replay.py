import subprocess
import sys
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parent.parent
_RUNNER = _REPO_ROOT / "specs" / "fixtures" / "tools" / "run_fixtures.py"


@pytest.mark.redos_timing
def test_every_safety_gates_case_replays_on_the_reference_engine() -> None:
    completed = subprocess.run(
        [sys.executable, str(_RUNNER), "--safety-only"],
        capture_output=True,
        text=True,
        cwd=_REPO_ROOT,
        timeout=3600,
    )
    assert completed.returncode == 0, (
        completed.stdout[-4000:] + completed.stderr[-2000:]
    )
    assert "conformance green:" in completed.stdout
