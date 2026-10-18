import logging
from collections.abc import Generator
from typing import Any
from unittest.mock import AsyncMock, Mock, patch

import pytest

from guard_core.handlers import _ipban_bans
from guard_core.handlers.ipban_handler import IPBanManager
from guard_core.models import SecurityConfig

LOGGER = "guard_core.handlers.ipban"


@pytest.fixture(autouse=True)
def reset_singleton() -> Generator[None, None, None]:
    IPBanManager._instance = None
    yield
    IPBanManager._instance = None


def _manager() -> IPBanManager:
    manager = IPBanManager()
    manager.redis_handler = None
    manager.config = SecurityConfig(
        enable_redis=False, trusted_proxies=("10.1.0.0/16",)
    )
    manager.agent_handler = Mock(send_event=AsyncMock())
    return manager


def _refusals(caplog: pytest.LogCaptureFixture) -> list[str]:
    return [
        r.getMessage() for r in caplog.records if "Refused to ban" in r.getMessage()
    ]


class _Clock:
    def __init__(self, now: float) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


async def test_a_loopback_refusal_names_loopback_space(
    caplog: pytest.LogCaptureFixture,
) -> None:
    manager = _manager()

    with caplog.at_level(logging.WARNING, logger=LOGGER):
        await manager.ban_ip("127.0.0.1", 600, "rate_limit_exceeded")

    assert _refusals(caplog) == [
        "Refused to ban 127.0.0.1: overlaps loopback space and would self-DoS this "
        "deployment. If unexpected, trusted_proxies is likely unset "
        "behind a reverse proxy; see docs/configuration/security-config.md"
    ]


async def test_a_trusted_proxy_refusal_names_the_proxy_space(
    caplog: pytest.LogCaptureFixture,
) -> None:
    manager = _manager()

    with caplog.at_level(logging.WARNING, logger=LOGGER):
        await manager.ban_ip("10.1.2.3", 600, "rate_limit_exceeded")

    assert _refusals(caplog) == [
        "Refused to ban 10.1.2.3: overlaps a configured trusted proxy space and "
        "would self-DoS this deployment. If unexpected, trusted_proxies is likely "
        "unset behind a reverse proxy; see docs/configuration/security-config.md"
    ]


async def test_the_refusal_event_states_the_reason_and_the_ban_it_stopped() -> None:
    manager = _manager()

    await manager.ban_ip("127.0.0.1", 600, "rate_limit_exceeded")

    (event,) = [c.args[0] for c in manager.agent_handler.send_event.call_args_list]
    assert event.reason == (
        "Refused to ban 127.0.0.1: loopback would self-DoS this deployment"
    )
    assert event.action_taken == "ban_refused"
    assert event.handler_name == "ip_ban"
    assert event.metadata == {
        "duration": 600,
        "refusal": "loopback",
        "ban_reason": "rate_limit_exceeded",
    }


async def test_a_failing_agent_send_is_logged_and_does_not_fail_the_refusal(
    caplog: pytest.LogCaptureFixture,
) -> None:
    manager = _manager()
    manager.agent_handler.send_event = AsyncMock(side_effect=RuntimeError("boom"))

    with caplog.at_level(logging.ERROR, logger=LOGGER):
        banned = await manager.ban_ip("127.0.0.1", 600, "rate_limit_exceeded")

    assert banned is False
    assert [r.getMessage() for r in caplog.records] == [
        "Failed to send ban refused event to agent: boom"
    ]


async def test_a_refusal_is_reported_again_the_moment_its_window_ends(
    caplog: pytest.LogCaptureFixture,
) -> None:
    manager = _manager()
    clock = _Clock(0.5)

    with (
        caplog.at_level(logging.WARNING, logger=LOGGER),
        patch.object(_ipban_bans.time, "time", clock),
    ):
        await manager.ban_ip("127.0.0.1", 600, "rate_limit_exceeded")
        clock.now = 600.4
        await manager.ban_ip("127.0.0.1", 600, "rate_limit_exceeded")
        clock.now = 600.5
        await manager.ban_ip("127.0.0.1", 600, "rate_limit_exceeded")

    assert len(_refusals(caplog)) == 2


async def test_a_full_table_drops_expired_entries_before_the_oldest_live_one(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(_ipban_bans, "_MAX_TRACKED_REFUSED_BANS", 2)
    manager = _manager()
    clock = _Clock(0.0)

    with patch.object(_ipban_bans.time, "time", clock):
        await manager.ban_ip("127.0.0.1", 700, "rate_limit_exceeded")
        await manager.ban_ip("127.0.0.2", 600, "rate_limit_exceeded")
        clock.now = 600.0
        await manager.ban_ip("127.0.0.3", 600, "rate_limit_exceeded")

    tracked: Any = manager.refused_ban_reported_until
    assert set(tracked) == {"127.0.0.1", "127.0.0.3"}


async def test_a_full_table_of_live_entries_drops_the_oldest(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(_ipban_bans, "_MAX_TRACKED_REFUSED_BANS", 2)
    manager = _manager()

    with patch.object(_ipban_bans.time, "time", _Clock(0.0)):
        for ip in ("127.0.0.1", "127.0.0.2", "127.0.0.3"):
            await manager.ban_ip(ip, 600, "rate_limit_exceeded")

    assert set(manager.refused_ban_reported_until) == {"127.0.0.2", "127.0.0.3"}


async def test_the_refusal_table_holds_at_most_ten_thousand_ips() -> None:
    manager = _manager()
    manager.agent_handler = None

    with patch.object(_ipban_bans.time, "time", _Clock(0.0)):
        for index in range(10_001):
            ip = f"127.{index >> 16 & 255}.{index >> 8 & 255}.{index & 255}"
            await manager.ban_ip(ip, 600, "rate_limit_exceeded")

    assert len(manager.refused_ban_reported_until) == 10_000
