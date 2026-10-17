from __future__ import annotations

from datetime import datetime, timedelta, timezone, tzinfo
from types import SimpleNamespace
from typing import Any

import pytest
from typing_extensions import Self

from tests.live_smoke import driver

VM_START_NS = int(datetime(2026, 10, 17, 1, 0, 0, tzinfo=timezone.utc).timestamp()) * (
    10**9
)
HOST_AHEAD_OF_VM = timedelta(seconds=1)


def _format(stamp_ns: int) -> str:
    seconds, nanos = divmod(stamp_ns, 10**9)
    moment = datetime.fromtimestamp(seconds, timezone.utc)
    return f"{moment.strftime('%Y-%m-%dT%H:%M:%S')}.{nanos:09d}Z"


def _parse(stamp: str) -> int:
    whole, fraction = stamp.removesuffix("+00:00").rstrip("Z").split(".")
    moment = datetime.strptime(whole, "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
    return int(moment.timestamp()) * 10**9 + int(fraction.ljust(9, "0"))


class _FakeDockerLogs:
    """Container logs stamped to the nanosecond on the VM clock."""

    def __init__(self) -> None:
        self.vm_now_ns = VM_START_NS
        self.lines: list[tuple[int, str]] = []

    def write(self, text: str, after_ns: int = 5_000_000) -> None:
        self.vm_now_ns += after_ns
        self.lines.append((self.vm_now_ns, text))

    def compose(self, *args: str, **_: Any) -> Any:
        selected = list(self.lines)
        if "--since" in args:
            cutoff = _parse(args[args.index("--since") + 1])
            selected = [item for item in selected if item[0] >= cutoff]
        if "--tail" in args:
            selected = selected[-int(args[args.index("--tail") + 1]) :]
        stamped = "--timestamps" in args
        out = [
            f"app-1  | {_format(stamp)} {text}" if stamped else f"app-1  | {text}"
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
            ahead_ns = fake.vm_now_ns + int(HOST_AHEAD_OF_VM.total_seconds() * 10**9)
            return cls.fromtimestamp(ahead_ns / 10**9, tz)

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


def test_a_line_in_the_same_microsecond_as_the_newest_one_is_seen(
    docker_logs: _FakeDockerLogs,
) -> None:
    docker_logs.write("newest at .123456100")
    docker_logs.lines[-1] = (
        docker_logs.vm_now_ns - docker_logs.vm_now_ns % 1000 + 100,
        "newest",
    )
    reader = driver.LogReader("app")

    mark = reader.mark()
    docker_logs.lines.append((docker_logs.lines[-1][0] + 800, "next in the burst"))

    assert any("next in the burst" in line for line in reader.lines_since(mark))
    assert not any("newest" in line for line in reader.lines_since(mark))


def test_the_mark_carries_over_a_second_boundary(docker_logs: _FakeDockerLogs) -> None:
    whole_second = VM_START_NS + 7 * 10**9
    docker_logs.lines.append((whole_second - 1, "last nanosecond of the second"))
    reader = driver.LogReader("app")

    mark = reader.mark()
    docker_logs.lines.append((whole_second, "first nanosecond of the next one"))

    assert mark.endswith(".000000000Z")
    assert any("first nanosecond" in line for line in reader.lines_since(mark))


def test_the_newest_stamp_wins_when_several_containers_log(
    docker_logs: _FakeDockerLogs, monkeypatch: pytest.MonkeyPatch
) -> None:
    older = f"app-1  | {_format(VM_START_NS + 10)} one"
    newer = f"app-2  | {_format(VM_START_NS + 20)} two"
    monkeypatch.setattr(
        driver,
        "_compose",
        lambda *args, **_: SimpleNamespace(stdout=f"{newer}\n{older}", returncode=0),
    )

    mark = driver.LogReader("app").mark()

    assert _parse(mark) == VM_START_NS + 21


def test_the_current_boot_text_keeps_the_startup_lines_before_the_mark(
    docker_logs: _FakeDockerLogs,
) -> None:
    docker_logs.write("Starting gunicorn 25.0")
    docker_logs.write("OTEL handler disabled")
    reader = driver.LogReader("app")

    mark = reader.mark()
    docker_logs.write("a request")

    assert not any("OTEL handler disabled" in line for line in reader.lines_since(mark))
    assert "OTEL handler disabled" in reader.current_boot_text()


def test_the_current_boot_text_drops_the_previous_boot(
    docker_logs: _FakeDockerLogs,
) -> None:
    docker_logs.write("Starting gunicorn 25.0")
    docker_logs.write("OTEL handler disabled")
    docker_logs.write("Starting gunicorn 25.0")
    docker_logs.write("healthy boot")

    text = driver.LogReader("app").current_boot_text()

    assert "healthy boot" in text
    assert "OTEL handler disabled" not in text
