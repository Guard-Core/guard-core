import asyncio
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from guard_core.handlers.ipban_handler import ip_ban_manager


@pytest.mark.asyncio
async def test_bans_added_and_removed_during_the_pass_do_not_break_it() -> None:
    expiry = time.time() + 600
    for index in range(6000):
        ip_ban_manager.banned_ips[f"10.{index // 250}.{index % 250}.1"] = expiry
    stop = asyncio.Event()
    churned = [0]

    async def churn() -> None:
        while not stop.is_set():
            ip_ban_manager.banned_ips[f"172.16.0.{churned[0] % 250}"] = expiry
            ip_ban_manager._purge_banned_ip(f"10.20.{churned[0] % 250}.1")
            churned[0] += 1
            await asyncio.sleep(0)

    task = asyncio.create_task(churn())
    await asyncio.sleep(0)
    try:
        await ip_ban_manager.unban_inside(["10.0.0.0/12"])
    finally:
        stop.set()
        await task

    assert churned[0] > 0
    assert "10.0.0.1" not in ip_ban_manager.banned_ips
    assert "10.15.249.1" not in ip_ban_manager.banned_ips
    assert "172.16.0.0" in ip_ban_manager.banned_ips


@pytest.mark.asyncio
async def test_unban_events_are_sent_in_batches_with_a_yield_between_them() -> None:
    expiry = time.time() + 600
    for index in range(450):
        ip_ban_manager.banned_ips[f"10.30.{index // 250}.{index % 250}"] = expiry
    agent = MagicMock()
    agent.send_event = AsyncMock()
    ip_ban_manager.agent_handler = agent
    yields = [0]
    real_sleep = asyncio.sleep

    async def counting_sleep(delay: float) -> None:
        yields[0] += 1
        await real_sleep(delay)

    try:
        with patch("guard_core.handlers._ipban_queries.asyncio.sleep", counting_sleep):
            await ip_ban_manager.unban_inside(["10.30.0.0/16"])
    finally:
        ip_ban_manager.agent_handler = None

    assert agent.send_event.await_count == 450
    assert yields[0] >= 450 // 100
