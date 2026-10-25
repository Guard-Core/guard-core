import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

_REPO_ROOT = Path(__file__).resolve().parent.parent
_CASES = Path("specs") / "fixtures" / "cases"
_GENERATOR = Path("specs") / "fixtures" / "tools" / "generate_fixtures.py"


def _masked(directory: Path, name: str) -> str:
    sys.path.insert(0, str(_REPO_ROOT / "specs" / "fixtures" / "tools"))
    from host_dependent_fields import without_host_fields

    payload: Any = json.loads((directory / name).read_text())
    return json.dumps(without_host_fields(name, payload), indent=2)


@pytest.mark.redos_timing
def test_committed_corpus_equals_a_fresh_regeneration_in_a_scratch_copy(
    tmp_path: Path,
) -> None:
    shutil.copytree(_REPO_ROOT / "specs", tmp_path / "specs")
    (tmp_path / "guard_core").symlink_to(_REPO_ROOT / "guard_core")
    (tmp_path / "tests").symlink_to(_REPO_ROOT / "tests")

    completed = subprocess.run(
        [sys.executable, str(tmp_path / _GENERATOR)],
        capture_output=True,
        text=True,
        cwd=tmp_path,
        env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
        timeout=3000,
    )
    assert completed.returncode == 0, (
        completed.stdout[-2000:] + completed.stderr[-2000:]
    )
    assert "determinism proof: second full regeneration byte-identical" in (
        completed.stdout
    )

    committed_dir = _REPO_ROOT / _CASES
    fresh_dir = tmp_path / _CASES
    names = sorted(path.name for path in committed_dir.glob("*.json"))
    assert names == sorted(path.name for path in fresh_dir.glob("*.json"))

    stale = [
        name
        for name in names
        if _masked(committed_dir, name) != _masked(fresh_dir, name)
    ]
    assert not stale, f"committed suites a fresh run would change: {stale}"
