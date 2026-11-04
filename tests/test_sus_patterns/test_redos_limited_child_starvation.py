import os
import signal
import subprocess
import sys
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import IO

import pytest

from guard_core.detection_engine import _redos_limited_child as limited_child
from guard_core.detection_engine._redos_limited_child import (
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
    monkeypatch.setattr(limited_child.shutil, "which", lambda name: "/bin/ps")
    monkeypatch.setattr(
        limited_child.subprocess,
        "run",
        lambda *a, **k: subprocess.CompletedProcess(a, 0, stdout="S+\n", stderr=""),
    )
    assert limited_child._process_state(123) == "S"


def test_ps_is_run_by_the_path_the_host_resolves_for_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        limited_child,
        "open",
        lambda *a, **k: _FakeProcStat(b"garbage"),
        raising=False,
    )
    monkeypatch.setattr(limited_child.shutil, "which", lambda name: "/opt/bin/ps")
    commands: list[list[str]] = []

    def record(
        command: list[str], **kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, stdout="R\n", stderr="")

    monkeypatch.setattr(limited_child.subprocess, "run", record)
    assert limited_child._process_state(123) == "R"
    assert commands[0][0] == "/opt/bin/ps"


def test_a_host_without_ps_leaves_the_state_unknown(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        limited_child,
        "open",
        lambda *a, **k: _FakeProcStat(b"garbage"),
        raising=False,
    )
    monkeypatch.setattr(limited_child.shutil, "which", lambda name: None)
    assert limited_child._process_state(123) is None


_READ_PAYLOAD_LENGTH = "import sys; print(len(sys.stdin.read()))"


def _run_in_a_fresh_thread(work: Callable[[], None]) -> None:
    # the scratch files are per thread, so a fresh thread starts with none
    worker = threading.Thread(target=work)
    worker.start()
    worker.join(timeout=60)
    assert not worker.is_alive()


def _files_opened_by_one_call(
    monkeypatch: pytest.MonkeyPatch, payload: str, script: str
) -> tuple[int, "limited_child.ChildResult | None"]:
    results: list[limited_child.ChildResult | None] = []
    opened: list[IO[bytes]] = []
    real = limited_child.tempfile.TemporaryFile

    def counting() -> IO[bytes]:
        handle: IO[bytes] = real()
        opened.append(handle)
        return handle

    def work() -> None:
        limited_child.run_limited_child("pass", "", 30.0)
        opened.clear()
        monkeypatch.setattr(limited_child.tempfile, "TemporaryFile", counting)
        results.append(limited_child.run_limited_child(script, payload, 30.0))

    _run_in_a_fresh_thread(work)
    return len(opened), results[0]


def test_a_second_large_payload_in_one_thread_opens_no_new_file(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    outcomes: list[tuple[int, str]] = []
    opened: list[IO[bytes]] = []
    real = limited_child.tempfile.TemporaryFile

    def counting() -> IO[bytes]:
        handle: IO[bytes] = real()
        opened.append(handle)
        return handle

    def work() -> None:
        limited_child.run_limited_child("pass", "x" * (1 << 16), 30.0)
        monkeypatch.setattr(limited_child.tempfile, "TemporaryFile", counting)
        for size in (1 << 15, 4097, 1 << 16):
            result = limited_child.run_limited_child(
                _READ_PAYLOAD_LENGTH, "x" * size, 30.0
            )
            assert result is not None
            outcomes.append((size, result.stdout.strip()))

    _run_in_a_fresh_thread(work)
    assert outcomes == [(size, str(size)) for size in (1 << 15, 4097, 1 << 16)]
    assert opened == []


@pytest.mark.parametrize("size", [0, 1, 512, 4096])
def test_a_payload_that_fits_the_pipe_buffer_reaches_the_child_without_a_file(
    monkeypatch: pytest.MonkeyPatch, size: int
) -> None:
    opened, result = _files_opened_by_one_call(
        monkeypatch, "x" * size, _READ_PAYLOAD_LENGTH
    )
    assert result is not None
    assert result.stdout.strip() == str(size)
    assert opened == 0


@pytest.mark.parametrize("size", [4097, 1 << 20])
def test_a_larger_payload_still_reaches_the_child_through_a_file(
    monkeypatch: pytest.MonkeyPatch, size: int
) -> None:
    opened, result = _files_opened_by_one_call(
        monkeypatch, "x" * size, _READ_PAYLOAD_LENGTH
    )
    assert result is not None
    assert result.stdout.strip() == str(size)
    assert opened == 1


def test_a_multibyte_payload_is_measured_in_bytes_for_the_pipe_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    count = 4096 // 2 + 1
    opened, result = _files_opened_by_one_call(
        monkeypatch, "\u00e9" * count, _READ_PAYLOAD_LENGTH
    )
    assert result is not None
    assert result.stdout.strip() == str(count)
    assert opened == 1


def test_a_child_that_never_reads_its_payload_is_collected_without_an_error() -> None:
    result = limited_child.run_limited_child("pass", "x" * 4096, 30.0)
    assert result is not None
    assert result.returncode == 0


def test_a_child_reads_only_its_own_stderr_though_the_heartbeat_file_is_reused() -> (
    None
):
    noisy = limited_child.run_limited_child(
        "import sys; sys.stderr.write('first child')", "", 30.0
    )
    quiet = limited_child.run_limited_child("pass", "", 30.0)
    noisy_again = limited_child.run_limited_child(
        "import sys; sys.stderr.write('third')", "", 30.0
    )
    assert noisy is not None
    assert quiet is not None
    assert noisy_again is not None
    assert (noisy.stderr, quiet.stderr, noisy_again.stderr) == (
        "first child",
        "",
        "third",
    )


def test_each_thread_keeps_its_own_heartbeat_file() -> None:
    files: list[IO[bytes]] = []
    done = threading.Barrier(2)

    def take() -> None:
        files.append(limited_child._heartbeat_file())
        done.wait(timeout=30)

    workers = [threading.Thread(target=take) for _ in range(2)]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join(timeout=30)
    assert len(files) == 2
    assert files[0] is not files[1]
    assert all(handle.closed for handle in files)
