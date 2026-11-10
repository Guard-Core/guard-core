import json
import os
import subprocess
import sys
from pathlib import Path

from guard_core import __version__

_ROOT = Path(__file__).resolve().parent.parent
_TOOLS = _ROOT / "specs" / "fixtures" / "tools"
_CASES = sorted((_ROOT / "specs" / "fixtures" / "cases").glob("*.json"))
_PRIVATE_REDIS = "redis://127.0.0.1:6538/9"
_PROBE = (
    "import json, events_harness as h;"
    "print(json.dumps([h.EVENTS_REDIS_URL, h._normalize(h.EVENTS_REDIS_URL)]))"
)


def test_every_fixture_file_is_stamped_with_the_engine_version() -> None:
    assert _CASES
    stamps = {
        path.name: json.loads(path.read_text())["engine_version"] for path in _CASES
    }

    assert {name: stamp for name, stamp in stamps.items() if stamp != __version__} == {}


def test_fixture_redis_override_wins_and_the_corpus_keeps_the_canonical_url() -> None:
    env = {
        **os.environ,
        "GUARD_CORE_FIXTURE_REDIS_URL": _PRIVATE_REDIS,
        "GUARD_CORE_CORPUS_REDIS_URL": "redis://other:1/0",
        "REDIS_URL": "redis://another:2/0",
    }

    out = subprocess.run(  # noqa: S603
        [sys.executable, "-c", _PROBE],
        cwd=_TOOLS,
        env={**env, "PYTHONPATH": f"{_ROOT}{os.pathsep}{_TOOLS}"},
        capture_output=True,
        text=True,
        check=True,
    ).stdout

    assert json.loads(out) == [_PRIVATE_REDIS, "redis://localhost:6379/0"]
