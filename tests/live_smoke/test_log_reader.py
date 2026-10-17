from __future__ import annotations

from datetime import datetime, timedelta, timezone, tzinfo
from types import SimpleNamespace
from typing import Any

import pytest
from typing_extensions import Self

from tests.live_smoke import driver

VM_START = datetime(2026, 10, 17, 1, 0, 0, tzinfo=timezone.utc)
HOST_AHEAD_OF_VM = timedelta(seconds=1)


class _FakeDockerLogs:
    """A container log on the VM clock; the host clock runs ahead of it."""

    def __init__(self) -> None:
        self.vm_now = VM_START
        self.lines: list[tuple[datetime, str]] = []

    def write(self, text: str, after: timedelta = timedelta(milliseconds=5)) -> None:
        self.vm_now += after
        self.lines.append((self.vm_now, text))

    def compose(self, *args: str, **_: Any) -> Any:
        selected = list(self.lines)
        if "--since" in args:
            cutoff = datetime.fromisoformat(args[args.index("--since") + 1])
            selected = [item for item in selected if item[0] >= cutoff]
        if "--tail" in args:
            selected = selected[-int(args[args.index("--tail") + 1]) :]
        stamped = "--timestamps" in args
        out = [
            f"app-1  | {stamp.strftime('%Y-%m-%dT%H:%M:%S.%f')}000Z {text}"
            if stamped
            else f"app-1  | {text}"
            for stamp, text in selected
        ]
        return SimpleNamespace(stdout="\n".join(out), returncode=0)


@pytest.fixture
def docker_logs(monkeypatch: pytest.MonkeyPatch) -> _FakeDockerLogs:
    fake = _FakeDockerLogs()
    monkeypatch.setattr(driver, "_compose", fake.compose)

    class _HostClock(datetime):
        @classmethod
        def now(cls, tz: tzinfo | None = None) -> Self:
            return cls.fromtimestamp((fake.vm_now + HOST_AHEAD_OF_VM).timestamp(), tz)

    monkeypatch.setattr(driver, "datetime", _HostClock)
    return fake


def test_a_line_logged_right_after_the_mark_is_seen_despite_host_clock_skew(
    docker_logs: _FakeDockerLogs,
) -> None:
    docker_logs.write("startup")
    reader = driver.LogReader("app")

    mark = reader.mark()
    docker_logs.write("dropping oldest event")

    assert any("dropping oldest event" in line for line in reader.lines_since(mark))


def test_a_line_logged_before_the_mark_is_not_returned(
    docker_logs: _FakeDockerLogs,
) -> None:
    docker_logs.write("before the mark")
    reader = driver.LogReader("app")

    mark = reader.mark()
    docker_logs.write("after the mark")

    lines = reader.lines_since(mark)
    assert not any("before the mark" in line for line in lines)
    assert any("after the mark" in line for line in lines)


def test_an_empty_log_marks_the_beginning(docker_logs: _FakeDockerLogs) -> None:
    reader = driver.LogReader("app")

    mark = reader.mark()
    docker_logs.write("first line ever")

    assert any("first line ever" in line for line in reader.lines_since(mark))
