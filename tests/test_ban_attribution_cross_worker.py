import json
import subprocess
import sys
import time
import uuid
from pathlib import Path

import pytest

from tests.conftest import REDIS_URL

WORKERS = Path(__file__).resolve().parent.parent / "scripts" / "ban_attribution_workers"
ROOT = Path(__file__).resolve().parent.parent
DYNAMIC = {"matched_rule_type": "dynamic", "matched_rule_id": "R"}


def _start(script: str, prefix: str, duration: int) -> subprocess.Popen[str]:
    process = subprocess.Popen(
        [sys.executable, str(WORKERS / script), REDIS_URL, prefix, str(duration)],
        cwd=ROOT,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    assert process.stdout is not None
    assert json.loads(process.stdout.readline())["ready"] is True
    return process


def _ask(process: subprocess.Popen[str], command: str) -> dict[str, object]:
    assert process.stdin is not None and process.stdout is not None
    process.stdin.write(command + "\n")
    process.stdin.flush()
    answer: dict[str, object] = json.loads(process.stdout.readline())
    return answer


@pytest.mark.parametrize("script", ["async_worker.py", "sync_worker.py"])
@pytest.mark.parametrize("duration", [3600, 7200])
def test_two_workers_that_apply_the_set_at_different_times_stamp_alike(
    script: str, duration: int
) -> None:
    prefix = f"wp23-xw:{uuid.uuid4().hex}:"
    first = _start(script, prefix, duration)
    second = _start(script, prefix, duration)
    try:
        _ask(first, "apply")
        before_second = _ask(first, "ask")
        time.sleep(1.5)
        later = _ask(second, "apply")
        answers = (before_second, _ask(first, "ask"), _ask(second, "ask"))
    finally:
        for process in (first, second):
            assert process.stdin is not None
            process.stdin.close()
            process.wait(timeout=30)
            assert process.stdout is not None
            process.stdout.close()

    assert later["owned"] == []
    assert [answer["banned"] for answer in answers] == [True, True, True]
    assert [answer["stamp"] for answer in answers] == [DYNAMIC, DYNAMIC, DYNAMIC]
