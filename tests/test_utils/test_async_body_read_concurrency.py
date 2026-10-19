import asyncio
import logging

import pytest

from guard_core._utils.body_reader import _safe_read


class _Probe:
    def __init__(self, hold: float) -> None:
        self.hold = hold
        self.in_flight = 0
        self.peak = 0

    async def read(self) -> bytes:
        self.in_flight += 1
        self.peak = max(self.peak, self.in_flight)
        try:
            await asyncio.sleep(self.hold)
            return b"body"
        finally:
            self.in_flight -= 1


async def test_at_most_max_concurrent_reads_are_in_flight(  # async-only
) -> None:
    probe = _Probe(hold=0.03)

    results = await asyncio.gather(
        *(_safe_read(probe.read, 2.0, max_concurrent=2) for _ in range(8))
    )

    assert results == [b"body"] * 8
    assert probe.peak == 2


async def test_a_read_waiting_past_the_timeout_gives_up_and_logs(  # async-only
    caplog: pytest.LogCaptureFixture,
) -> None:
    probe = _Probe(hold=0.5)
    first = asyncio.ensure_future(_safe_read(probe.read, 2.0, max_concurrent=1))
    await asyncio.sleep(0.01)

    with caplog.at_level(logging.WARNING, logger="guard_core"):
        second = await _safe_read(probe.read, 0.05, max_concurrent=1)

    assert second is None
    assert "Body read concurrency limit reached (max_concurrent=1)" in caplog.text
    assert await first == b"body"


async def test_the_slot_is_released_after_each_kind_of_end(  # async-only
) -> None:
    from guard_core._utils.body_reader import _body_read_slots

    async def slow() -> bytes:
        await asyncio.sleep(1)
        return b"late"

    async def failing() -> bytes:
        raise RuntimeError("adapter failed")

    async def fine() -> bytes:
        return b"ok"

    assert await _safe_read(slow, 0.02, max_concurrent=3) is None
    assert await _safe_read(failing, 0.5, max_concurrent=3) is None
    assert await _safe_read(fine, 0.5, max_concurrent=3) == b"ok"
    assert _body_read_slots[3] == []


async def test_a_cancelled_read_releases_its_slot(  # async-only
) -> None:
    from guard_core._utils.body_reader import _body_read_slots

    probe = _Probe(hold=5)
    task = asyncio.ensure_future(_safe_read(probe.read, 10, max_concurrent=4))
    await asyncio.sleep(0.01)
    assert len(_body_read_slots[4]) == 1

    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    assert _body_read_slots[4] == []
