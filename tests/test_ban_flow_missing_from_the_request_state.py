import logging
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from guard_core.core.checks import _rate_limit_ban_first
from guard_core.core.checks._ban_flow import NO_BAN_FLOW, BanFlow
from guard_core.core.checks._pending_ban import PendingBan, resolve_pending_ban
from guard_core.core.checks._rate_limit_ban_first import (
    NO_RATE_LIMIT_HANDLER,
    NO_STATUS_REPLY,
    ban_first_rate_limit,
    finish_tiers,
    resolve_ban_and_rate,
)
from guard_core.core.checks.implementations.ip_security import IpSecurityCheck
from guard_core.core.checks.implementations.rate_limit import RateLimitCheck
from guard_core.handlers import ratelimit_handler
from guard_core.handlers.ipban_handler import IPBanManager
from guard_core.handlers.ratelimit_handler import RateLimitBlock, RateLimitManager
from guard_core.handlers.redis_handler import RedisManager
from guard_core.models import SecurityConfig
from tests.conftest import REDIS_URL, suite_redis_prefix

CLIENT = "198.51.100.77"


class _Rig:
    """The IP and rate-limit checks over a real Redis, wired as the pipeline does."""

    def __init__(self, **overrides: object) -> None:
        fields: dict[str, Any] = dict(
            enable_redis=True,
            redis_url=REDIS_URL,
            redis_prefix=suite_redis_prefix("wp303"),
            auto_ban_threshold=10**6,
            enable_penetration_detection=False,
            enable_rate_limiting=True,
            rate_limit=3,
            rate_limit_window=60,
            ban_on_hostile_signals=True,
        )
        fields.update(overrides)
        self.config = SecurityConfig(**fields)
        self.redis = RedisManager(self.config)

    async def start(self) -> None:
        await self.redis.initialize()
        self.manager = IPBanManager()
        self.manager.redis_handler = None
        await self.manager.reset()
        self.manager.config = self.config
        await self.manager.initialize_redis(self.redis)
        limiter = RateLimitManager(self.config)
        await limiter.initialize_redis(self.redis)
        middleware = MagicMock()
        middleware.config = self.config
        middleware.logger = logging.getLogger("wp303")
        middleware.suspicious_request_counts = {}
        middleware.rate_limit_handler = limiter
        middleware.geo_ip_handler = None
        middleware.route_resolver.should_bypass_check = lambda *_: False
        middleware.event_bus.agent_handler = None

        async def create_error_response(
            status_code: int, default_message: str
        ) -> object:
            return SimpleNamespace(status_code=status_code, headers={})

        async def record(**kwargs: object) -> None:
            return None

        middleware.create_error_response = create_error_response
        middleware.event_bus.send_middleware_event = record
        self.middleware = middleware
        self.ip_check = IpSecurityCheck(middleware)
        self.rate_check = RateLimitCheck(middleware)
        for check in (self.ip_check, self.rate_check):
            check.ip_ban_manager = self.manager

    async def ban_in_redis_only(self, ip: str) -> None:
        await self.redis.set_key("banned_ips", ip, str(time.time() + 300), 300)
        self.manager.banned_ips.clear()

    async def stop(self) -> None:
        self.manager.redis_handler = self.redis
        await self.manager.reset()
        self.manager.redis_handler = None
        await self.redis.delete_pattern("*")
        await self.redis.close()


@asynccontextmanager
async def _rig(**overrides: object) -> AsyncIterator[_Rig]:
    rig = _Rig(**overrides)
    await rig.start()
    try:
        yield rig
    finally:
        await rig.stop()


def _request(ip: str) -> MagicMock:
    request = MagicMock()
    request.state.client_ip = ip
    request.state.route_config = None
    request.state.is_whitelisted = False
    request.state.whitelist_entry = None
    request.state.is_exempt = False
    request.state.guard_exclusion_scoped = False
    request.state.untrusted_forwarded_for = None
    request.headers = SimpleNamespace(
        get=lambda name, default="": {"user-agent": "curl/8"}.get(
            name.lower(), default
        ),
        keys=lambda: ["User-Agent"],
        __contains__=lambda name: name == "User-Agent",
    )
    request.method = "GET"
    request.url_path = "/x"
    return request


async def _pending_ban_and_rate(rig: _Rig, ip: str) -> tuple[MagicMock, PendingBan]:
    """Run the IP and rate-limit checks by hand: the ban read and the rate-limit
    count are left pending together, for one script to settle."""
    request = _request(ip)
    assert await rig.ip_check.check(request) is None
    assert await rig.rate_check.check(request) is None
    flow = request.state.guard_ban_flow
    assert isinstance(flow, BanFlow)
    assert flow.pending is not None
    assert flow.pending.rate is not None
    return request, flow.pending


async def test_a_denying_list_without_a_ban_flow_on_the_state_is_refused() -> None:
    async with _rig(blacklist=[CLIENT]) as rig:
        with pytest.raises(AttributeError, match=NO_BAN_FLOW):
            await rig.ip_check._static_denial_verdict(SimpleNamespace(), CLIENT, None)


async def test_a_strike_without_a_ban_flow_on_the_state_is_refused() -> None:
    async with _rig() as rig:
        with pytest.raises(AttributeError, match=NO_BAN_FLOW):
            rig.ip_check._fused_strike_for(SimpleNamespace(), CLIENT, "ip_list")


async def test_a_banned_client_without_a_ban_flow_on_the_state_is_refused() -> None:
    async with _rig() as rig:
        await rig.ban_in_redis_only(CLIENT)
        request, pending = await _pending_ban_and_rate(rig, CLIENT)
        request.state.guard_ban_flow = None
        assert pending.rate is not None

        with pytest.raises(AttributeError, match=NO_BAN_FLOW):
            await resolve_ban_and_rate(request, pending, pending.rate, None)


async def test_a_rate_limited_client_without_a_ban_flow_on_the_state_is_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(ratelimit_handler, "log_activity", AsyncMock())
    async with _rig(rate_limit=1) as rig:
        first, _ = await _pending_ban_and_rate(rig, CLIENT)
        assert await resolve_pending_ban(first) is None
        request, pending = await _pending_ban_and_rate(rig, CLIENT)
        request.state.guard_ban_flow = None
        assert pending.rate is not None

        with pytest.raises(AttributeError, match=NO_BAN_FLOW):
            await resolve_ban_and_rate(request, pending, pending.rate, None)


async def test_a_script_reply_without_a_status_is_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async with _rig() as rig:
        _, pending = await _pending_ban_and_rate(rig, CLIENT)
        assert pending.rate is not None
        monkeypatch.setattr(
            _rate_limit_ban_first, "_evalsha", AsyncMock(return_value=[None])
        )

        with pytest.raises(TypeError, match=NO_STATUS_REPLY):
            await ban_first_rate_limit(
                pending,
                rig.redis,
                CLIENT,
                [plan.tier for plan in pending.rate.plans],
                rig.config,
                None,
            )


async def test_finishing_the_tiers_without_a_rate_limit_handler_is_refused() -> None:
    async with _rig() as rig:
        request, pending = await _pending_ban_and_rate(rig, CLIENT)
        assert pending.rate is not None
        rig.middleware.rate_limit_handler = None

        with pytest.raises(AttributeError, match=NO_RATE_LIMIT_HANDLER):
            await finish_tiers(
                pending.rate.check, request, CLIENT, pending.rate.plans, None
            )


async def test_reporting_a_block_without_a_rate_limit_handler_is_refused() -> None:
    async with _rig() as rig:
        request, pending = await _pending_ban_and_rate(rig, CLIENT)
        assert pending.rate is not None
        plan = pending.rate.plans[0]
        block = RateLimitBlock(0, 99, SimpleNamespace(status_code=429, headers={}))
        rig.middleware.rate_limit_handler = None

        with pytest.raises(AttributeError, match=NO_RATE_LIMIT_HANDLER):
            await pending.rate.check._report_block(request, CLIENT, plan, block)
