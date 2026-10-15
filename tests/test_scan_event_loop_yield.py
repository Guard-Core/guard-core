import asyncio
import concurrent.futures
import threading
from collections.abc import AsyncGenerator

import pytest

from guard_core.detection_engine import compiler as compiler_module
from guard_core.detection_engine.compiler import _await_regex_future
from guard_core.handlers._suspatterns_regex import _WINDOWED_PATTERN_FINDERS
from guard_core.handlers.suspatterns_handler import SusPatternsManager
from guard_core.models import SecurityConfig


@pytest.fixture(autouse=True)
async def _reset_suspatterns_singleton() -> AsyncGenerator[None, None]:
    original_instance = SusPatternsManager._instance
    original_config = SusPatternsManager._config

    SusPatternsManager._instance = None
    SusPatternsManager._config = None

    yield

    SusPatternsManager._instance = original_instance
    SusPatternsManager._config = original_config


async def test_await_regex_future_returns_result_and_yields_to_loop() -> None:
    ticks: list[int] = []

    async def ticker() -> None:
        for i in range(3):
            ticks.append(i)
            await asyncio.sleep(0)

    task = asyncio.create_task(ticker())
    future = compiler_module.shared_regex_executor().submit(lambda: "done")

    assert await _await_regex_future(future, 5.0) == "done"
    await task
    assert ticks == [0, 1, 2]


async def test_await_regex_future_timeout_is_concurrent_timeout() -> None:
    release = threading.Event()
    future = compiler_module.shared_regex_executor().submit(release.wait, 5.0)
    try:
        with pytest.raises(concurrent.futures.TimeoutError):
            await _await_regex_future(future, 0.01)
    finally:
        release.set()


async def test_other_tasks_run_between_patterns_during_a_scan() -> None:
    manager = SusPatternsManager()
    manager.configure(SecurityConfig())
    patterns = await manager.get_all_compiled_patterns()
    windowed = [
        p for p, _ctx, _cat in patterns if p.pattern in _WINDOWED_PATTERN_FINDERS
    ]
    assert windowed

    ran: list[str] = []

    async def other_request() -> None:
        ran.append("other")

    other = asyncio.create_task(other_request())
    start_count = len(ran)

    await manager._check_regex_pattern(
        windowed[0], "hello world", "127.0.0.1", 0.0, "sqli"
    )

    assert start_count == 0
    assert ran == ["other"]
    await other


async def test_pattern_loop_yields_to_other_tasks_once_a_slice_elapses() -> None:
    from unittest.mock import patch

    manager = SusPatternsManager()
    manager.configure(SecurityConfig())
    ticks = iter(x * 0.01 for x in range(1_000_000))
    ran_at: list[int] = []
    progress = {"patterns": 0}
    real = manager._check_regex_pattern

    async def counting(*args: object, **kwargs: object) -> object:
        progress["patterns"] += 1
        return await real(*args, **kwargs)  # type: ignore[arg-type]

    async def other_request() -> None:
        ran_at.append(progress["patterns"])

    other = asyncio.create_task(other_request())
    with (
        patch("guard_core.handlers._suspatterns_regex.time") as fake_time,
        patch.object(manager, "_check_regex_pattern", counting),
    ):
        fake_time.monotonic = lambda: next(ticks)
        await manager._check_regex_patterns("hello world", "127.0.0.1", None)

    await other
    all_patterns = await manager.get_all_compiled_patterns()
    assert ran_at
    assert ran_at[0] < len(all_patterns)
    assert ran_at[0] <= 2
