import ipaddress
import logging
import sys
import time
from collections.abc import Generator
from types import ModuleType
from unittest.mock import AsyncMock, MagicMock

import pytest
from pydantic import BaseModel, ConfigDict

from guard_core.handlers.ipban_handler import IPBanManager, reset_global_state
from tests.ipban_redis_fake import fake_ban_redis


def _scan_iter_of(keys: list[str]) -> object:
    async def scan_iter(*_args: object, **_kwargs: object) -> object:
        for key in keys:
            yield str(key)

    return scan_iter


@pytest.fixture(autouse=True)
def reset_singleton() -> Generator[None, None, None]:
    IPBanManager._instance = None
    yield
    IPBanManager._instance = None


@pytest.fixture(autouse=True)
def fake_guard_agent() -> Generator[None, None, None]:
    module = ModuleType("guard_agent")

    class _SecurityEvent(BaseModel):
        model_config = ConfigDict(extra="allow")

    module.__dict__["SecurityEvent"] = _SecurityEvent
    sys.modules["guard_agent"] = module
    yield
    del sys.modules["guard_agent"]


@pytest.mark.asyncio
async def test_initialize_redis_assigns_handler() -> None:
    manager = IPBanManager()
    redis = AsyncMock()
    await manager.initialize_redis(redis)
    assert manager.redis_handler is redis


@pytest.mark.asyncio
async def test_initialize_agent_assigns_handler() -> None:
    manager = IPBanManager()
    agent = AsyncMock()
    await manager.initialize_agent(agent)
    assert manager.agent_handler is agent


@pytest.mark.asyncio
async def test_ban_exact_ip_sends_event_when_agent_handler_present() -> None:
    manager = IPBanManager()
    manager.redis_handler = None
    agent = AsyncMock()
    manager.agent_handler = agent

    await manager.ban_ip("10.0.0.20", duration=60, reason="r")

    agent.send_event.assert_awaited_once()
    sent = agent.send_event.call_args.args[0]
    assert sent.ip_address == "10.0.0.20"
    assert sent.action_taken == "banned"


@pytest.mark.asyncio
async def test_send_ban_event_logs_error_when_agent_raises(
    caplog: pytest.LogCaptureFixture,
) -> None:
    manager = IPBanManager()
    manager.redis_handler = None
    agent = AsyncMock()
    agent.send_event.side_effect = RuntimeError("boom")
    manager.agent_handler = agent

    caplog.set_level(logging.ERROR, logger="guard_core.handlers.ipban")
    await manager.ban_ip("10.0.0.21", duration=60, reason="r")

    errors = [r for r in caplog.records if r.levelno == logging.ERROR]
    assert any("Failed to send ban event" in r.getMessage() for r in errors)


@pytest.mark.asyncio
async def test_unban_removes_local_entry_and_calls_redis_delete() -> None:
    manager = IPBanManager()
    redis = AsyncMock()
    manager.redis_handler = redis

    manager.banned_ips["10.0.0.30"] = time.time() + 60
    agent = AsyncMock()
    manager.agent_handler = agent

    await manager.unban_ip("10.0.0.30")

    assert "10.0.0.30" not in manager.banned_ips
    redis.write_atomically.assert_awaited_once_with(
        sets=(),
        deletes=[
            ("banned_ips", "10.0.0.30"),
            ("ban_floors:banned_ips", "10.0.0.30"),
        ],
        increment=("ban_version", "counter"),
    )
    redis.delete.assert_any_call("rate_limit", "violations:10.0.0.30")
    redis.forget_detection_strikes.assert_called_once_with("10.0.0.30")
    agent.send_event.assert_awaited_once()
    sent = agent.send_event.call_args.args[0]
    assert sent.action_taken == "unbanned"


@pytest.mark.asyncio
async def test_unban_when_ip_absent_and_no_redis_no_agent_is_noop() -> None:
    manager = IPBanManager()
    manager.redis_handler = None
    manager.agent_handler = None

    await manager.unban_ip("10.0.0.31")

    assert "10.0.0.31" not in manager.banned_ips


@pytest.mark.asyncio
async def test_send_unban_event_logs_error_when_agent_raises(
    caplog: pytest.LogCaptureFixture,
) -> None:
    manager = IPBanManager()
    manager.redis_handler = None
    agent = AsyncMock()
    agent.send_event.side_effect = RuntimeError("kaboom")
    manager.agent_handler = agent

    caplog.set_level(logging.ERROR, logger="guard_core.handlers.ipban")
    await manager.unban_ip("10.0.0.32")

    errors = [r for r in caplog.records if r.levelno == logging.ERROR]
    assert any("Failed to send unban event" in r.getMessage() for r in errors)


@pytest.mark.asyncio
async def test_is_ip_banned_clears_expired_local_entry_and_returns_false() -> None:
    manager = IPBanManager()
    manager.redis_handler = None
    manager.banned_ips["10.0.0.40"] = time.time() - 1

    assert await manager.is_ip_banned("10.0.0.40") is False
    assert "10.0.0.40" not in manager.banned_ips


@pytest.mark.asyncio
async def test_is_ip_banned_uses_redis_when_local_miss() -> None:
    manager = IPBanManager()
    redis = fake_ban_redis(str(time.time() + 60))
    manager.redis_handler = redis

    assert await manager.is_ip_banned("10.0.0.41") is True
    redis.get_many.assert_awaited_once_with(
        [("banned_ips", "10.0.0.41"), ("ban_version", "counter")]
    )


@pytest.mark.asyncio
async def test_check_redis_exact_returns_false_when_no_entry() -> None:
    manager = IPBanManager()
    manager.redis_handler = fake_ban_redis(None)

    assert await manager.is_ip_banned("10.0.0.42") is False


@pytest.mark.asyncio
async def test_check_redis_exact_deletes_expired_entry_and_returns_false() -> None:
    manager = IPBanManager()
    redis = fake_ban_redis(str(time.time() - 10))
    manager.redis_handler = redis

    assert await manager.is_ip_banned("10.0.0.43") is False
    redis.delete.assert_awaited_once_with("banned_ips", "10.0.0.43")


@pytest.mark.asyncio
async def test_reset_clears_local_state_and_redis_keys() -> None:
    manager = IPBanManager()

    redis = MagicMock()
    redis.config = MagicMock()
    redis.config.redis_prefix = "guard:"
    conn = AsyncMock()
    conn.scan_iter = _scan_iter_of(["guard:banned_ips:1", "guard:banned_ips:2"])
    redis.get_connection = MagicMock(
        return_value=AsyncMock(
            __aenter__=AsyncMock(return_value=conn),
            __aexit__=AsyncMock(return_value=None),
        )
    )
    manager.redis_handler = redis

    manager.banned_ips["x"] = time.time() + 60
    manager.banned_networks.append(
        (ipaddress.ip_network("10.0.0.0/24"), time.time() + 60)
    )

    await manager.reset()

    assert len(manager.banned_ips) == 0
    assert manager.banned_networks == []
    assert conn.unlink.call_args_list[0].args == (
        "guard:banned_ips:1",
        "guard:banned_ips:2",
    )


@pytest.mark.asyncio
async def test_reset_with_no_redis_and_no_keys_skips_delete() -> None:
    manager = IPBanManager()

    redis = MagicMock()
    redis.config = MagicMock()
    redis.config.redis_prefix = "guard:"
    conn = AsyncMock()
    conn.scan_iter = _scan_iter_of([])
    redis.get_connection = MagicMock(
        return_value=AsyncMock(
            __aenter__=AsyncMock(return_value=conn),
            __aexit__=AsyncMock(return_value=None),
        )
    )
    manager.redis_handler = redis

    await manager.reset()

    conn.unlink.assert_not_awaited()


@pytest.mark.asyncio
async def test_reset_without_redis_just_clears_local() -> None:
    manager = IPBanManager()
    manager.redis_handler = None
    manager.banned_ips["x"] = time.time() + 60

    await manager.reset()

    assert len(manager.banned_ips) == 0


@pytest.mark.asyncio
async def test_reset_global_state_replaces_module_singleton() -> None:
    from guard_core.handlers import ipban_handler

    ipban_handler.ip_ban_manager = IPBanManager()
    original = ipban_handler.ip_ban_manager
    IPBanManager._instance = None

    await reset_global_state()

    assert ipban_handler.ip_ban_manager is not original
    assert isinstance(ipban_handler.ip_ban_manager, IPBanManager)


@pytest.mark.asyncio
async def test_reset_global_state_clears_a_populated_singleton() -> None:
    from guard_core.handlers import ipban_handler

    manager = IPBanManager()
    manager.banned_ips["203.0.113.250"] = True
    manager.banned_networks = [(ipaddress.ip_network("203.0.113.0/24"), 0.0)]
    manager.redis_handler = AsyncMock()
    manager.agent_handler = AsyncMock()

    await reset_global_state()

    after_reset = ipban_handler.ip_ban_manager
    assert after_reset is manager
    assert "203.0.113.250" not in after_reset.banned_ips
    assert after_reset.banned_networks == []
    assert after_reset.redis_handler is None
    assert after_reset.agent_handler is None
