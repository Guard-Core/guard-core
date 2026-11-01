import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

from guard_core.sync.detection_engine import _redos_limited_child as limited_child
from guard_core.sync.detection_engine._redos_limited_child import (
    child_is_running_or_finished,
    communicate_until_stalled,
)

_SPIN = "while True: pass"
_ONE_C_CALL = "print(sum(range(2 * 10**8)))"


def _spawn(script: str) -> "subprocess.Popen[str]":
    return subprocess.Popen(
        [sys.executable, "-c", script],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        text=True,
    )


def _stop_child(process: "subprocess.Popen[str]") -> None:
    process.kill()
    process.communicate()


def test_a_child_that_waits_for_a_cpu_slice_is_not_stalled_by_the_wall_clock(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(limited_child, "STALL_POLL_SECONDS", 0.1)
    started = tmp_path / "started"
    process = _spawn(f"open({str(started)!r}, 'w').close()\n{_ONE_C_CALL}")
    while not started.exists():
        time.sleep(0.05)
    output = communicate_until_stalled(process, "", lambda: 0, 0.3)
    assert output is not None
    assert output[0].strip() == str(sum(range(2 * 10**8)))


def test_a_runnable_child_reads_as_running() -> None:
    process = _spawn(_SPIN)
    try:
        assert child_is_running_or_finished(process.pid)
    finally:
        _stop_child(process)


def test_a_child_that_exited_before_it_was_reaped_reads_as_finished() -> None:
    process = _spawn("pass")
    try:
        deadline = time.monotonic() + 30.0
        while (
            limited_child._process_state(process.pid) != "Z"
            and time.monotonic() < deadline
        ):
            time.sleep(0.05)
        assert child_is_running_or_finished(process.pid)
    finally:
        _stop_child(process)


def test_a_sleeping_child_does_not_read_as_running() -> None:
    process = _spawn("import time; time.sleep(60)")
    try:
        time.sleep(0.3)
        assert not child_is_running_or_finished(process.pid)
    finally:
        _stop_child(process)


def test_a_stopped_child_does_not_read_as_running_and_is_killed_as_stalled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(limited_child, "STALL_POLL_SECONDS", 0.1)
    process = _spawn(_SPIN)
    os.kill(process.pid, signal.SIGSTOP)
    time.sleep(0.3)
    assert not child_is_running_or_finished(process.pid)
    assert communicate_until_stalled(process, "", lambda: 0, 0.4) is None
    assert process.returncode != 0


def test_a_child_whose_state_cannot_be_read_is_not_running(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def refuse(*args: object, **kwargs: object) -> None:
        raise OSError("no ps")

    monkeypatch.setattr(limited_child, "open", refuse, raising=False)
    monkeypatch.setattr(limited_child.subprocess, "run", refuse)
    assert not child_is_running_or_finished(os.getpid())


def test_an_empty_state_listing_is_not_running(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        limited_child,
        "open",
        lambda *a, **k: (_ for _ in ()).throw(OSError("no proc")),
        raising=False,
    )
    monkeypatch.setattr(
        limited_child.subprocess,
        "run",
        lambda *a, **k: subprocess.CompletedProcess(a, 1, stdout="\n", stderr=""),
    )
    assert not child_is_running_or_finished(os.getpid())


class _FakeProcStat:
    def __init__(self, content: bytes) -> None:
        self.content = content

    def __enter__(self) -> "_FakeProcStat":
        return self

    def __exit__(self, *exc: object) -> None:
        return None

    def read(self) -> bytes:
        return self.content


def test_the_state_comes_from_proc_after_the_command_name_that_may_hold_spaces(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        limited_child,
        "open",
        lambda *a, **k: _FakeProcStat(b"123 (py (x) y) R 1 2 3"),
        raising=False,
    )
    assert limited_child._process_state(123) == "R"


def test_a_proc_entry_without_a_state_falls_back_to_ps(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        limited_child,
        "open",
        lambda *a, **k: _FakeProcStat(b"garbage"),
        raising=False,
    )
    monkeypatch.setattr(
        limited_child.subprocess,
        "run",
        lambda *a, **k: subprocess.CompletedProcess(a, 0, stdout="S+\n", stderr=""),
    )
    assert limited_child._process_state(123) == "S"
