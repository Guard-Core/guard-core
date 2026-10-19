import logging
import os
import time
import uuid
from collections.abc import AsyncGenerator
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from guard_core.handlers._ipban_rule_exempt import (
    DYNAMIC_RULE_BAN_REASON,
    rule_ban_target,
)
from guard_core.handlers.dynamic_rule_handler import DynamicRuleManager
from guard_core.handlers.ipban_handler import ip_ban_manager
from guard_core.handlers.redis_handler import RedisManager
from guard_core.models import DynamicRules, SecurityConfig

REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379")
IP = "198.51.100.90"
OTHER = "198.51.100.91"
THIRD = "198.51.100.92"
NETWORK = "203.0.113.0/24"
INSIDE_NETWORK = "203.0.113.9"
VERSION = ("ban_version", "counter")


@dataclass
class Fleet:
    manager: DynamicRuleManager
    agent: Any
    redis: RedisManager | None

    async def apply(
        self, version: int, ips: list[str], whitelist: list[str] | None = None
    ) -> None:
        self.agent.get_dynamic_rules.return_value = DynamicRules(
            rule_id="R",
            version=version,
            timestamp=datetime.now(timezone.utc),
            ip_blacklist=ips,
            ip_whitelist=whitelist or [],
            ip_ban_duration=3600,
        )
        await self.manager.update_rules()

    async def expiry(self, ip: str) -> float | None:
        if self.redis is None:
            return ip_ban_manager.banned_ips.get(ip)
        held = await self.redis.get_key("banned_ips", ip)
        return float(held) if held else None

    async def remaining(self, ip: str) -> float:
        expiry = await self.expiry(ip)
        return 0.0 if expiry is None else expiry - time.time()

    async def version(self) -> int:
        if self.redis is None:
            return 0
        return int(await self.redis.get_key(*VERSION) or 0)

    def unban_events(self) -> list[Any]:
        sent = [call.args[0] for call in self.agent.send_event.call_args_list]
        return [event for event in sent if event.action_taken == "unbanned"]


async def _open_fleet(on_redis: bool) -> Fleet:
    config = SecurityConfig(
        redis_url=REDIS_URL,
        redis_prefix=f"wp20-revoke:{uuid.uuid4().hex}:",
        enable_redis=on_redis,
        enable_agent=True,
        agent_api_key="k",
        enable_dynamic_rules=True,
    )
    redis = RedisManager(config) if on_redis else None
    if redis is not None:
        await redis.initialize()
    ip_ban_manager.config = config
    ip_ban_manager.redis_handler = redis
    ip_ban_manager.banned_ips.clear()
    ip_ban_manager.banned_networks.clear()
    ip_ban_manager._rule_owned_expiries.clear()
    ip_ban_manager._rule_floor_expiries.clear()
    ip_ban_manager._forget_shared_state()
    DynamicRuleManager._instance = None
    manager = DynamicRuleManager(config)
    manager.redis_handler = redis
    agent = MagicMock()
    agent.send_event = AsyncMock()
    agent.get_dynamic_rules = AsyncMock()
    manager.agent_handler = agent
    ip_ban_manager.agent_handler = agent
    return Fleet(manager, agent, redis)


async def _close_fleet(fleet: Fleet) -> None:
    ip_ban_manager.agent_handler = None
    if fleet.redis is not None:
        await fleet.redis.delete_pattern("*")
        await fleet.redis.close()


@pytest.fixture(params=["redis", "memory"])
async def fleet(request: pytest.FixtureRequest) -> AsyncGenerator[Fleet, None]:
    opened = await _open_fleet(request.param == "redis")
    yield opened
    await _close_fleet(opened)


@pytest.fixture
async def redis_fleet() -> AsyncGenerator[Fleet, None]:
    opened = await _open_fleet(True)
    yield opened
    await _close_fleet(opened)


@pytest.fixture
async def memory_fleet() -> AsyncGenerator[Fleet, None]:
    opened = await _open_fleet(False)
    yield opened
    await _close_fleet(opened)


@pytest.mark.parametrize("foreign_seconds", [86400, 60])
async def test_a_ban_written_over_a_rule_ban_keeps_its_expiry_when_the_rule_drops_it(
    fleet: Fleet, foreign_seconds: int
) -> None:
    await fleet.apply(1, [IP])
    await ip_ban_manager.ban_ip(IP, foreign_seconds, "auto_ban")

    await fleet.apply(2, [OTHER])

    assert await ip_ban_manager.is_ip_banned(IP)
    remaining = await fleet.remaining(IP)
    assert foreign_seconds - 5 < remaining <= foreign_seconds


async def test_a_floor_rewrite_sends_one_event_with_its_outcome_and_remaining_seconds(
    fleet: Fleet,
) -> None:
    await fleet.apply(1, [IP])
    await ip_ban_manager.ban_ip(IP, 60, "auto_ban")
    before = await fleet.version()

    await fleet.apply(2, [OTHER])

    (event,) = fleet.unban_events()
    assert (event.ip_address, event.reason) == (IP, "dynamic_rule_revoked")
    assert event.metadata["action"] == "unban"
    assert event.metadata["outcome"] == "rewritten_to_floor"
    assert 50 < event.metadata["remaining_seconds"] <= 60
    assert await fleet.version() == before + (1 if fleet.redis else 0)


async def test_a_rule_ban_nothing_else_touched_is_lifted_with_one_event_and_one_bump(
    fleet: Fleet,
) -> None:
    await fleet.apply(1, [IP, OTHER, THIRD])
    before = await fleet.version()

    await fleet.apply(2, ["198.51.100.99"])

    assert not await ip_ban_manager.is_ip_banned(IP)
    events = fleet.unban_events()
    assert sorted(event.ip_address for event in events) == [IP, OTHER, THIRD]
    assert all(event.reason == "dynamic_rule_revoked" for event in events)
    assert all("outcome" not in event.metadata for event in events)
    assert await fleet.version() == before + (1 if fleet.redis else 0)


async def test_a_longer_foreign_ban_leaves_no_event_and_no_version_bump(
    fleet: Fleet,
) -> None:
    await fleet.apply(1, [IP])
    await ip_ban_manager.ban_ip(IP, 86400, "auto_ban")
    before = await fleet.version()

    await fleet.apply(2, [OTHER])

    assert fleet.unban_events() == []
    assert await fleet.version() == before


async def test_an_ip_the_rule_never_owned_is_left_alone_and_reports_nothing(
    fleet: Fleet,
) -> None:
    await ip_ban_manager.ban_ip(IP, 3600, "auto_ban")
    before = await fleet.version()

    assert await ip_ban_manager.revoke_rule_ban(IP) == 0
    await ip_ban_manager.settle_rule_revocations([(IP, 0), (OTHER, 3)])

    assert await ip_ban_manager.is_ip_banned(IP)
    assert fleet.unban_events() == []
    assert await fleet.version() == before


async def test_the_whitelist_path_still_unbans_a_foreign_ban(fleet: Fleet) -> None:
    await ip_ban_manager.ban_ip(IP, 86400, "auto_ban")
    assert await ip_ban_manager.is_ip_banned(IP)

    await fleet.apply(1, [OTHER], whitelist=[IP])

    assert not await ip_ban_manager.is_ip_banned(IP)


@pytest.mark.parametrize(
    ("first", "second"),
    [
        ("2001:DB8::1", "2001:db8::1"),
        ("2001:db8:0:0:0:0:0:1", "2001:db8::1"),
        ("2001:db8::1", "2001:DB8:0:0:0:0:0:1"),
    ],
)
async def test_a_textual_variant_of_a_listed_ip_is_not_revoked(
    fleet: Fleet, first: str, second: str
) -> None:
    await fleet.apply(1, [first])
    await fleet.apply(2, [second])

    assert await ip_ban_manager.is_ip_banned("2001:db8::1")
    assert fleet.unban_events() == []


async def test_a_variant_that_leaves_the_set_is_revoked_by_canonical_form(
    fleet: Fleet,
) -> None:
    await fleet.apply(1, ["2001:DB8:0:0:0:0:0:1"])
    assert await ip_ban_manager.is_ip_banned("2001:db8::1")

    await fleet.apply(2, [OTHER])

    assert not await ip_ban_manager.is_ip_banned("2001:db8::1")


async def test_a_network_listed_with_host_bits_is_not_revoked_by_its_normalized_form(
    fleet: Fleet,
) -> None:
    await fleet.apply(1, ["203.0.113.5/24"])
    await fleet.apply(2, [NETWORK])

    assert await ip_ban_manager.is_ip_banned(INSIDE_NETWORK)
    assert fleet.unban_events() == []


async def test_a_network_rule_ban_is_lifted_when_the_rule_drops_it(
    fleet: Fleet,
) -> None:
    await fleet.apply(1, [NETWORK])
    assert await ip_ban_manager.is_ip_banned(INSIDE_NETWORK)

    await fleet.apply(2, [OTHER])

    assert not await ip_ban_manager.is_ip_banned(INSIDE_NETWORK)
    assert [event.ip_address for event in fleet.unban_events()] == [NETWORK]


async def test_a_longer_foreign_network_ban_survives_the_revoke(fleet: Fleet) -> None:
    await fleet.apply(1, [NETWORK])
    await ip_ban_manager.ban_ip(NETWORK, 86400, "auto_ban")

    await fleet.apply(2, [OTHER])

    assert await ip_ban_manager.is_ip_banned(INSIDE_NETWORK)
    assert fleet.unban_events() == []


async def test_a_shorter_foreign_network_ban_takes_over_at_its_own_expiry(
    fleet: Fleet,
) -> None:
    await fleet.apply(1, [NETWORK])
    await ip_ban_manager.ban_ip(NETWORK, 60, "auto_ban")

    await fleet.apply(2, [OTHER])

    assert await ip_ban_manager.is_ip_banned(INSIDE_NETWORK)
    (event,) = fleet.unban_events()
    assert event.metadata["outcome"] == "rewritten_to_floor"
    assert 0 < event.metadata["remaining_seconds"] <= 60


async def test_a_rule_that_rewrites_its_own_longer_ban_hides_no_foreign_ban(
    fleet: Fleet,
) -> None:
    await ip_ban_manager.ban_ip(IP, 7200, DYNAMIC_RULE_BAN_REASON)
    await ip_ban_manager.ban_ip(IP, 3600, DYNAMIC_RULE_BAN_REASON)
    await ip_ban_manager.ban_ip(IP, 14400, DYNAMIC_RULE_BAN_REASON)

    assert await ip_ban_manager.revoke_rule_ban(IP) == 1
    assert not await ip_ban_manager.is_ip_banned(IP)


async def test_a_shorter_foreign_ban_over_an_unowned_ban_records_no_floor(
    fleet: Fleet,
) -> None:
    await ip_ban_manager.ban_ip(IP, 3600, "auto_ban")
    await ip_ban_manager.ban_ip(IP, 60, "auto_ban")

    assert await ip_ban_manager.revoke_rule_ban(IP) == 0
    assert await ip_ban_manager.is_ip_banned(IP)


async def test_the_listing_reads_the_owned_set_and_the_unlisted_ones_go(
    fleet: Fleet,
) -> None:
    await fleet.apply(1, [IP, NETWORK])

    assert sorted(await ip_ban_manager.owned_rule_ban_targets()) == sorted(
        [IP, NETWORK]
    )


async def test_a_failing_owned_listing_is_logged_and_the_local_ownership_still_revokes(
    fleet: Fleet, caplog: pytest.LogCaptureFixture
) -> None:
    await fleet.apply(1, [IP])
    with (
        patch.object(
            ip_ban_manager,
            "owned_rule_ban_targets",
            AsyncMock(side_effect=RuntimeError("listing")),
        ),
        caplog.at_level(logging.ERROR),
    ):
        await fleet.apply(2, [OTHER])

    assert "Failed to list the bans a dynamic rule owns: listing" in caplog.text
    assert not await ip_ban_manager.is_ip_banned(IP)


async def test_version_zero_revokes_every_owned_ban_through_the_same_path(
    fleet: Fleet,
) -> None:
    await fleet.apply(1, [IP, NETWORK])
    await ip_ban_manager.ban_ip(OTHER, 60, "auto_ban")
    before = await fleet.version()

    await fleet.manager._revoke_all_owned()

    assert not await ip_ban_manager.is_ip_banned(IP)
    assert not await ip_ban_manager.is_ip_banned(INSIDE_NETWORK)
    assert await ip_ban_manager.is_ip_banned(OTHER)
    assert await fleet.version() == before + (1 if fleet.redis else 0)


def test_rule_ban_target_names_the_namespace_and_the_canonical_key() -> None:
    assert rule_ban_target("2001:DB8::1") == ("banned_ips", "2001:db8::1")
    assert rule_ban_target("203.0.113.5/24") == ("banned_networks", NETWORK)
    assert rule_ban_target("203.0.113.0/33") == ("banned_ips", "203.0.113.0/33")


async def test_a_memory_ban_written_before_redis_was_attached_is_revoked_by_its_owner(
    redis_fleet: Fleet,
) -> None:
    ip_ban_manager.redis_handler = None
    await ip_ban_manager.ban_ip(IP, 3600, DYNAMIC_RULE_BAN_REASON)
    ip_ban_manager.redis_handler = redis_fleet.redis

    assert await ip_ban_manager.revoke_rule_ban(IP) == 1
    assert not await ip_ban_manager.is_ip_banned(IP)


@pytest.mark.usefixtures("memory_fleet")
async def test_an_expired_or_missing_memory_ownership_reports_gone() -> None:
    ip_ban_manager._rule_owned_expiries["banned_ips:" + IP] = time.time() - 1
    ip_ban_manager._rule_owned_expiries["banned_ips:" + OTHER] = time.time() + 600

    assert await ip_ban_manager.revoke_rule_ban(IP) == 0
    assert await ip_ban_manager.revoke_rule_ban(OTHER) == 0
    assert ip_ban_manager._rule_owned_expiries == {}


@pytest.mark.usefixtures("memory_fleet")
async def test_an_expired_floor_is_dropped_with_the_rule_ban() -> None:
    await ip_ban_manager.ban_ip(IP, 3600, DYNAMIC_RULE_BAN_REASON)
    ip_ban_manager._rule_floor_expiries["banned_ips:" + IP] = time.time() - 1

    assert await ip_ban_manager.revoke_rule_ban(IP) == 1
    assert not await ip_ban_manager.is_ip_banned(IP)
    assert ip_ban_manager._rule_floor_expiries == {}


async def test_a_rewrite_event_without_a_live_ban_reports_zero_seconds(
    fleet: Fleet,
) -> None:
    await ip_ban_manager.settle_rule_revocations([(IP, 2)])

    (event,) = fleet.unban_events()
    assert event.metadata["remaining_seconds"] == 0


async def test_disowning_a_ban_removes_only_its_entry_from_the_shared_owned_set(
    fleet: Fleet,
) -> None:
    await fleet.apply(1, [IP, NETWORK, OTHER])

    await ip_ban_manager.disown_rule_ban(IP)
    await ip_ban_manager.disown_rule_ban("203.0.113.7/24")

    remaining = await ip_ban_manager.owned_rule_ban_targets()
    assert sorted(remaining) == sorted([OTHER] if fleet.redis else [IP, NETWORK, OTHER])
    assert await ip_ban_manager.is_ip_banned(IP)


@pytest.mark.usefixtures("memory_fleet")
async def test_a_plain_mapping_store_takes_the_floor_rewrite_too() -> None:
    with patch.object(ip_ban_manager, "banned_ips", {}):
        await ip_ban_manager.ban_ip(IP, 3600, DYNAMIC_RULE_BAN_REASON)
        await ip_ban_manager.ban_ip(IP, 60, "auto_ban")

        assert await ip_ban_manager.revoke_rule_ban(IP) == 2
        assert 0 < ip_ban_manager.banned_ips[IP] - time.time() <= 60


async def test_a_rule_ban_written_over_a_shorter_foreign_ban_revokes_to_that_ban(
    fleet: Fleet,
) -> None:
    await ip_ban_manager.ban_ip(IP, 60, "auto_ban")
    await ip_ban_manager.ban_ip(IP, 3600, DYNAMIC_RULE_BAN_REASON)

    assert await ip_ban_manager.revoke_rule_ban(IP) == 2
    assert await ip_ban_manager.is_ip_banned(IP)
    assert 0 < await fleet.remaining(IP) <= 60
