import os
import subprocess
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent


def test_every_async_test_has_its_sync_twin_or_is_listed_as_async_only() -> None:
    env = {
        **os.environ,
        "PATH": f"{Path(sys.executable).parent}{os.pathsep}{os.environ['PATH']}",
    }

    result = subprocess.run(  # noqa: S603
        [sys.executable, str(_ROOT / "scripts" / "unasync.py"), "--check"],
        cwd=_ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )

    assert (result.returncode, result.stdout.strip()) == (
        0,
        "OK: sync code is up to date",
    ), result.stdout + result.stderr
