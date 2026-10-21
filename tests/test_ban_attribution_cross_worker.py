import json
import os
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path
from typing import IO

import pytest

from tests.conftest import REDIS_URL

WORKERS = Path(__file__).resolve().parent.parent / "scripts" / "ban_attribution_workers"
ROOT = Path(__file__).resolve().parent.parent
DYNAMIC = {"matched_rule_type": "dynamic", "matched_rule_id": "R"}


class _Worker:
    def __init__(self, script: str, prefix: str, duration: int) -> None:
        self.script = script
        self.errors: IO[str] = tempfile.TemporaryFile("w+")
        env = dict(os.environ)
        # A runner that layers packages over its environment (uv run --with)
        # hands them to this process through sys.path only.
        env["PYTHONPATH"] = os.pathsep.join([str(ROOT), *sys.path])
        self.process = subprocess.Popen(
            [sys.executable, str(WORKERS / script), REDIS_URL, prefix, str(duration)],
            cwd=ROOT,
            env=env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=self.errors,
            text=True,
        )
        assert self._read()["ready"] is True

    def _read(self) -> dict[str, object]:
        assert self.process.stdout is not None
        line = self.process.stdout.readline()
        if not line:
            self.process.kill()
            self.errors.seek(0)
            raise AssertionError(f"{self.script} gave no answer: {self.errors.read()}")
        answer: dict[str, object] = json.loads(line)
        return answer

    def ask(self, command: str) -> dict[str, object]:
        assert self.process.stdin is not None
        self.process.stdin.write(command + "\n")
        self.process.stdin.flush()
        return self._read()

    def close(self) -> None:
        assert self.process.stdin is not None and self.process.stdout is not None
        self.process.stdin.close()
        self.process.wait(timeout=30)
        self.process.stdout.close()
        self.errors.close()


@pytest.mark.parametrize("script", ["async_worker.py", "sync_worker.py"])
@pytest.mark.parametrize("duration", [3600, 7200])
def test_two_workers_that_apply_the_set_at_different_times_stamp_alike(
    script: str, duration: int
) -> None:
    prefix = f"wp23-xw:{uuid.uuid4().hex}:"
    first = _Worker(script, prefix, duration)
    try:
        second = _Worker(script, prefix, duration)
        try:
            first.ask("apply")
            before_second = first.ask("ask")
            time.sleep(1.5)
            later = second.ask("apply")
            answers = (before_second, first.ask("ask"), second.ask("ask"))
        finally:
            second.close()
    finally:
        first.close()

    assert later["owned"] == []
    assert [answer["banned"] for answer in answers] == [True, True, True]
    assert [answer["stamp"] for answer in answers] == [DYNAMIC, DYNAMIC, DYNAMIC]
