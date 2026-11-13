import os
import subprocess
import sys
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parent.parent
_TOOLS = _REPO_ROOT / "specs" / "fixtures" / "tools"
_CASES = _REPO_ROOT / "specs" / "fixtures" / "cases"
_GENERATED_KINDS = ["detect", "pipeline", "events", "redis", "misconfiguration"]

_PROBE = (
    "import asyncio, sys\n"
    "from pathlib import Path\n"
    "import generate_fixtures as g\n"
    "from guard_core.models import SecurityConfig\n"
    "out = Path(sys.argv[1])\n"
    "config = SecurityConfig(**g.STAGED_FIELDS)\n"
    "async def main():\n"
    "    for kind in sys.argv[2].split(','):\n"
    "        suites = await g.run_corpus(config, only=kind)\n"
    "        for name, payload in suites.items():\n"
    "            (out / f'{name}.json').write_text(g.suite_bytes(payload))\n"
    "asyncio.run(main())\n"
)


def _generate(out: Path, kinds: list[str]) -> None:
    completed = subprocess.run(
        [sys.executable, "-c", _PROBE, str(out), ",".join(kinds)],
        capture_output=True,
        text=True,
        cwd=_REPO_ROOT,
        env={
            **os.environ,
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONPATH": str(_TOOLS),
        },
        timeout=900,
    )
    assert completed.returncode == 0, completed.stderr[-2000:]


def _drifted(out: Path) -> list[str]:
    return sorted(
        path.name
        for path in out.glob("*.json")
        if path.read_text() != (_CASES / path.name).read_text()
    )


@pytest.mark.parametrize("kind", ["pipeline", "events", "redis", "misconfiguration"])
def test_a_suite_generated_alone_equals_the_committed_bytes(
    kind: str, tmp_path: Path
) -> None:
    _generate(tmp_path, [kind])

    assert list(tmp_path.glob("*.json"))
    assert _drifted(tmp_path) == []


def test_the_suites_generated_in_reverse_order_equal_the_committed_bytes(
    tmp_path: Path,
) -> None:
    _generate(tmp_path, list(reversed(_GENERATED_KINDS)))

    assert len(list(tmp_path.glob("*.json"))) > 20
    assert _drifted(tmp_path) == []
