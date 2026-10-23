import subprocess
import sys
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parent.parent
_GENERATOR = _REPO_ROOT / "specs" / "fixtures" / "tools" / "generate_safety_gates.py"


@pytest.mark.redos_timing
def test_committed_safety_gates_equal_a_fresh_regeneration() -> None:
    completed = subprocess.run(
        [sys.executable, str(_GENERATOR), "--check"],
        capture_output=True,
        text=True,
        cwd=_REPO_ROOT,
        timeout=1800,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr[-2000:]
