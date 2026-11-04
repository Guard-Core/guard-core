import errno
import re
import sys
import types
from collections.abc import Callable, Iterator

import pytest

from guard_core.sync.detection_engine import _redos_work_counter as work_counter

_X86_UNIT = 2.0e-10
_AARCH_UNIT = 4.0e-10


class _FakeSyscall:
    def __init__(self, outcome: int) -> None:
        self.outcome = outcome
        self.calls: list[tuple[object, ...]] = []
        self.restype: object = None
        self.argtypes: object = None

    def __call__(self, *args: object) -> int:
        self.calls.append(args)
        return self.outcome


def _instruction_counts() -> Iterator[int]:
    total = 1000
    for _ in range(7):
        yield total
        total += 1000
    while True:
        yield total
        total += 5000


def _build(
    monkeypatch: pytest.MonkeyPatch,
    *,
    units: dict[str, float],
    machine: str = "x86_64",
    syscall_outcome: int = 7,
    reads: Callable[[int, int], bytes] | None = None,
    platform: str = "linux",
) -> tuple[Callable[[re.Pattern[str], str], float] | None, _FakeSyscall]:
    import ctypes
    import os

    syscall = _FakeSyscall(syscall_outcome)
    libc = types.SimpleNamespace(syscall=syscall)
    counts = _instruction_counts()
    monkeypatch.setattr(sys, "platform", platform)
    monkeypatch.setattr(os, "uname", lambda: types.SimpleNamespace(machine=machine))
    monkeypatch.setattr(ctypes, "CDLL", lambda *args, **kwargs: libc)
    monkeypatch.setattr(
        os,
        "read",
        reads or (lambda fd, size: next(counts).to_bytes(8, sys.byteorder)),
    )
    namespace: dict[str, object] = {"re": re}
    exec(work_counter.work_counter_source(units), namespace)
    builder = namespace["build_work_counter"]
    assert callable(builder)
    return builder(), syscall


def test_an_open_counter_reports_scaled_instructions(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    counter, syscall = _build(monkeypatch, units={"x86_64": _X86_UNIT})
    assert callable(counter)
    scale = _X86_UNIT / work_counter.WORK_UNIT_SECONDS
    assert counter(re.compile("a"), "a") == pytest.approx(4000 * scale, rel=0.01)
    number, attribute, pid, cpu, group, flags = syscall.calls[0]
    assert (number, pid, cpu, group, flags) == (298, 0, -1, -1, 0)
    assert isinstance(attribute, bytes) and len(attribute) == 64
    kind, size, config, flag_bits = (
        int.from_bytes(attribute[0:4], sys.byteorder),
        int.from_bytes(attribute[4:8], sys.byteorder),
        int.from_bytes(attribute[8:16], sys.byteorder),
        int.from_bytes(attribute[40:48], sys.byteorder),
    )
    assert (kind, size, config) == (0, 64, 1)
    assert flag_bits == 0x60


def test_each_architecture_uses_its_own_syscall_number_and_unit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    units = {"x86_64": _X86_UNIT, "aarch64": _AARCH_UNIT}
    counter, syscall = _build(monkeypatch, units=units, machine="aarch64")
    assert callable(counter)
    assert syscall.calls[0][0] == 241
    scale = _AARCH_UNIT / work_counter.WORK_UNIT_SECONDS
    assert counter(re.compile("a"), "a") == pytest.approx(4000 * scale, rel=0.01)


@pytest.mark.parametrize("machine", ["x86_64", "aarch64", "riscv64"])
def test_an_architecture_without_a_calibrated_unit_keeps_the_fallback(
    monkeypatch: pytest.MonkeyPatch, machine: str
) -> None:
    counter, syscall = _build(monkeypatch, units={}, machine=machine)
    assert counter is None
    assert syscall.calls == []


def test_an_unknown_architecture_keeps_the_fallback_even_with_a_unit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    counter, syscall = _build(
        monkeypatch, units={"riscv64": _X86_UNIT}, machine="riscv64"
    )
    assert counter is None
    assert syscall.calls == []


@pytest.mark.parametrize(
    "refusal",
    [errno.EPERM, errno.EACCES, errno.ENOENT, errno.ENODEV, errno.EOPNOTSUPP],
)
def test_a_refused_open_keeps_the_fallback(
    monkeypatch: pytest.MonkeyPatch, refusal: int
) -> None:
    import ctypes

    monkeypatch.setattr(ctypes, "get_errno", lambda: refusal)
    counter, syscall = _build(
        monkeypatch, units={"x86_64": _X86_UNIT}, syscall_outcome=-1
    )
    assert counter is None
    assert len(syscall.calls) == 1


def _zero_read(fd: int, size: int) -> bytes:
    return (0).to_bytes(8, sys.byteorder)


def _short_read(fd: int, size: int) -> bytes:
    return b""


def _failing_read(fd: int, size: int) -> bytes:
    raise OSError(errno.EIO, "read failed")


@pytest.mark.parametrize("reads", [_zero_read, _short_read, _failing_read])
def test_a_zero_or_failing_read_keeps_the_fallback(
    monkeypatch: pytest.MonkeyPatch, reads: Callable[[int, int], bytes]
) -> None:
    counter, _ = _build(monkeypatch, units={"x86_64": _X86_UNIT}, reads=reads)
    assert counter is None


def test_no_ctypes_keeps_the_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    import ctypes

    def refuse(*args: object, **kwargs: object) -> None:
        raise OSError("no libc")

    counter, _ = _build(monkeypatch, units={"x86_64": _X86_UNIT})
    assert callable(counter)
    monkeypatch.setattr(ctypes, "CDLL", refuse)
    namespace: dict[str, object] = {"re": re}
    exec(work_counter.work_counter_source({"x86_64": _X86_UNIT}), namespace)
    builder = namespace["build_work_counter"]
    assert callable(builder)
    assert builder() is None


def test_another_platform_still_keeps_the_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    counter, syscall = _build(
        monkeypatch, units={"x86_64": _X86_UNIT}, platform="win32"
    )
    assert counter is None
    assert syscall.calls == []


def test_no_linux_architecture_is_calibrated_until_the_band_has_measured_one() -> None:
    assert work_counter.LINUX_UNIT_SECONDS == {}
    assert work_counter.WORK_UNIT_SECONDS == 5.1e-11
