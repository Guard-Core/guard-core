import logging
import os
import time
import uuid
from collections.abc import Generator
from typing import Any
from unittest.mock import MagicMock

import pytest
from pydantic import ValidationError

from guard_core.models import SecurityConfig
from guard_core.sync.handlers._ipban_recidive import escalated_duration
from guard_core.sync.handlers.ipban_handler import IPBanManager
from guard_core.sync.handlers.redis_handler import RedisManager

REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379")
HOST = "8.8.8.8"
IDENTITY = "2001:db8:0:1::/64"
HOST_IN_IDENTITY = "2001:db8:0:1::5"
THIRTY_DAYS = 30 * 86400


@pytest.fixture(autouse=True)
def reset_singleton() -> Generator[None, None, None]:
    IPBanManager._instance = None
    yield
    IPBanManager._instance = None


@pytest.fixture
def live_redis() -> Generator[RedisManager, None]:
    config = SecurityConfig(
        redis_url=REDIS_URL, redis_prefix=f"wp6-recidive:{uuid.uuid4().hex}:"
    )
    manager = RedisManager(config)
    manager.initialize()
    yield manager
    manager.delete_pattern("*")
    manager.close()


def _manager(**settings: Any) -> IPBanManager:
    manager = IPBanManager()
    manager.redis_handler = None
    manager.config = SecurityConfig(
        enable_redis=False, enable_recidive=True, **settings
    )
    return manager


def _remaining(manager: IPBanManager, key: str) -> float:
    return manager.banned_ips[key] - time.time()


def _expire_naturally(manager: IPBanManager, key: str) -> None:
    manager.banned_ips[key] = time.time() - 1


def test_the_recidive_fields_default_to_off_with_the_agreed_values() -> None:
    config = SecurityConfig(enable_redis=False)

    assert config.enable_recidive is False
    assert config.recidive_factor == 2.0
    assert config.recidive_window == 86400
    assert config.recidive_max_duration == 604800


@pytest.mark.parametrize(
    "settings",
    [
        {"recidive_factor": 1},
        {"recidive_factor": 0.5},
        {"recidive_window": 0},
        {"recidive_max_duration": 0},
    ],
)
def test_out_of_range_recidive_values_are_rejected(settings: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        SecurityConfig(enable_redis=False, **settings)


def test_the_cap_must_cover_the_auto_ban_duration_when_recidive_is_on() -> None:
    with pytest.raises(ValidationError, match="recidive_max_duration"):
        SecurityConfig(
            enable_redis=False,
            enable_recidive=True,
            auto_ban_duration=THIRTY_DAYS,
            recidive_max_duration=604800,
        )


def test_a_long_auto_ban_duration_is_fine_while_recidive_is_off() -> None:
    config = SecurityConfig(enable_redis=False, auto_ban_duration=THIRTY_DAYS)

    assert config.enable_recidive is False


def test_each_earlier_ban_multiplies_the_duration_by_the_factor() -> None:
    assert escalated_duration(3600, 0, 2.0, 604800) == 3600
    assert escalated_duration(3600, 1, 2.0, 604800) == 7200
    assert escalated_duration(3600, 3, 2.0, 604800) == 28800
    assert escalated_duration(100, 2, 1.5, 10_000) == 225


def test_the_escalated_duration_stops_at_the_cap() -> None:
    assert escalated_duration(3600, 20, 2.0, 604800) == 604800
    assert escalated_duration(3600, 5000, 2.0, 604800) == 604800


def test_a_thirty_day_base_stays_at_or_above_thirty_days() -> None:
    for prior in (0, 1, 4):
        assert escalated_duration(THIRTY_DAYS, prior, 2.0, 604800) == THIRTY_DAYS


def test_a_ban_after_a_natural_expiry_inside_the_window_lasts_twice_as_long() -> None:
    manager = _manager()
    manager._ban_ip_escalating(HOST, 3600, "rate_limit_exceeded")
    assert 3500 < _remaining(manager, HOST) <= 3600
    _expire_naturally(manager, HOST)

    manager._ban_ip_escalating(HOST, 3600, "rate_limit_exceeded")

    assert 7100 < _remaining(manager, HOST) <= 7200


def test_the_third_ban_lasts_four_times_as_long() -> None:
    manager = _manager()
    for _ in range(2):
        manager._ban_ip_escalating(HOST, 100, "t")
        _expire_naturally(manager, HOST)

    manager._ban_ip_escalating(HOST, 100, "t")

    assert 390 < _remaining(manager, HOST) <= 400


def test_a_ban_while_one_is_active_neither_changes_it_nor_counts() -> None:
    manager = _manager()
    manager._ban_ip_escalating(HOST, 100, "t")
    before = manager.banned_ips[HOST]

    assert manager._ban_ip_escalating(HOST, 100, "t") is True

    assert manager.banned_ips[HOST] == before
    assert manager.recidive_history[HOST][0] == 1


def test_the_escalated_duration_never_exceeds_the_cap() -> None:
    manager = _manager(auto_ban_duration=100, recidive_max_duration=500)
    for _ in range(6):
        manager._ban_ip_escalating(HOST, 100, "t")
        _expire_naturally(manager, HOST)

    manager._ban_ip_escalating(HOST, 100, "t")

    assert 400 < _remaining(manager, HOST) <= 500


def test_a_base_above_the_cap_is_applied_as_it_is() -> None:
    manager = _manager(auto_ban_duration=100, recidive_max_duration=500)
    manager._ban_ip_escalating(HOST, THIRTY_DAYS, "t")
    _expire_naturally(manager, HOST)

    manager._ban_ip_escalating(HOST, THIRTY_DAYS, "t")

    assert _remaining(manager, HOST) > THIRTY_DAYS - 10


def test_a_ban_after_the_window_started_over() -> None:
    manager = _manager(recidive_window=10)
    manager._ban_ip_escalating(HOST, 100, "t")
    _expire_naturally(manager, HOST)
    count, _ = manager.recidive_history[HOST]
    manager.recidive_history[HOST] = (count, time.time() - 1)

    manager._ban_ip_escalating(HOST, 100, "t")

    assert 90 < _remaining(manager, HOST) <= 100


def test_a_manager_without_the_flag_never_escalates() -> None:
    manager = IPBanManager()
    manager.redis_handler = None
    manager.config = SecurityConfig(enable_redis=False)
    for _ in range(2):
        manager._ban_ip_escalating(HOST, 100, "t")
        _expire_naturally(manager, HOST)

    manager._ban_ip_escalating(HOST, 100, "t")

    assert 90 < _remaining(manager, HOST) <= 100
    assert manager.recidive_history == {}


def test_a_ban_that_is_not_escalating_neither_escalates_nor_counts() -> None:
    manager = _manager()
    for _ in range(3):
        manager.ban_ip(HOST, 100, "manual")
        _expire_naturally(manager, HOST)

    assert manager.recidive_history == {}
    manager.ban_ip(HOST, 100, "manual")
    assert 90 < _remaining(manager, HOST) <= 100


def test_an_operator_network_ban_neither_escalates_nor_counts() -> None:
    manager = _manager()

    manager._ban_ip_escalating("198.18.0.0/24", 100, "t")

    assert manager.recidive_history == {}


def test_a_refused_ban_is_not_counted() -> None:
    manager = _manager()

    assert manager._ban_ip_escalating("127.0.0.1", 100, "t") is False

    assert manager.recidive_history == {}


def test_a_grouped_identity_escalates_as_one_client() -> None:
    manager = _manager()
    manager._ban_ip_escalating(IDENTITY, 100, "t", grouped=True)
    _expire_naturally(manager, IDENTITY)

    manager._ban_ip_escalating(IDENTITY, 100, "t", grouped=True)

    assert 190 < _remaining(manager, IDENTITY) <= 200


def test_the_ban_event_carries_the_applied_duration_and_the_count() -> None:
    manager = _manager()
    manager.agent_handler = MagicMock()
    manager._ban_ip_escalating(HOST, 100, "t")
    _expire_naturally(manager, HOST)

    manager._ban_ip_escalating(HOST, 100, "t")

    last = manager.agent_handler.send_event.call_args_list[-1].args[0]
    assert last.metadata == {"duration": 200, "recidive_count": 2}


def test_the_ban_log_carries_the_duration_and_the_count(
    caplog: pytest.LogCaptureFixture,
) -> None:
    manager = _manager()
    manager._ban_ip_escalating(HOST, 100, "t")
    _expire_naturally(manager, HOST)

    with caplog.at_level(logging.INFO, logger="guard_core.sync.handlers.ipban"):
        manager._ban_ip_escalating(HOST, 100, "t")

    assert any(
        "Banned 8.8.8.8 for 200 seconds (ban 2 " in message
        for message in caplog.messages
    )


def test_unban_ip_forgets_the_history_in_memory() -> None:
    manager = _manager()
    manager._ban_ip_escalating(HOST, 100, "t")

    manager.unban_ip(HOST)
    manager._ban_ip_escalating(HOST, 100, "t")

    assert 90 < _remaining(manager, HOST) <= 100
    assert manager.recidive_history[HOST][0] == 1


def test_unbanning_one_address_of_a_group_forgets_the_identity_history() -> None:
    manager = _manager()
    manager._ban_ip_escalating(IDENTITY, 100, "t", grouped=True)

    manager.unban_ip(HOST_IN_IDENTITY)

    assert IDENTITY not in manager.recidive_history


def test_unbanning_a_range_forgets_its_history() -> None:
    manager = _manager()
    manager._ban_ip_escalating(IDENTITY, 100, "t", grouped=True)

    manager.unban_ip(IDENTITY)

    assert manager.recidive_history == {}


def test_the_range_whitelist_forgets_the_history_inside_it() -> None:
    manager = _manager()
    manager._ban_ip_escalating(HOST, 100, "t")
    manager._ban_ip_escalating("1.1.1.1", 100, "t")

    manager.unban_inside(["8.8.8.0/24"])
    manager.forget_strikes_inside(["8.8.8.0/24"])

    assert list(manager.recidive_history) == ["1.1.1.1"]


def test_reset_forgets_every_history() -> None:
    manager = _manager()
    manager._ban_ip_escalating(HOST, 100, "t")

    manager.reset()

    assert manager.recidive_history == {}


def test_the_history_store_is_bounded_by_the_ban_cap() -> None:
    manager = _manager(banned_ips_max_entries=2)
    for index in range(4):
        manager._ban_ip_escalating(f"8.8.0.{index + 1}", 100 + index, "t")

    assert len(manager.recidive_history) == 2


def test_the_live_counter_lives_for_the_window_plus_the_applied_ban(
    live_redis: RedisManager,
) -> None:
    manager = _manager(recidive_window=1000)
    manager.redis_handler = live_redis
    manager.config = SecurityConfig(
        redis_url=REDIS_URL,
        redis_prefix=live_redis.config.redis_prefix,
        enable_recidive=True,
        recidive_window=1000,
    )

    manager._ban_ip_escalating(HOST, 100, "t")

    with live_redis.get_connection() as conn:
        key = f"{live_redis.config.redis_prefix}recidive:{HOST}"
        assert int(conn.get(key)) == 1
        assert 1090 < conn.ttl(key) <= 1100


def test_two_workers_share_one_history_through_redis(
    live_redis: RedisManager,
) -> None:
    config = SecurityConfig(
        redis_url=REDIS_URL,
        redis_prefix=live_redis.config.redis_prefix,
        enable_recidive=True,
    )
    first = _manager()
    first.redis_handler = live_redis
    first.config = config
    first._ban_ip_escalating(HOST, 100, "t")
    live_redis.delete("banned_ips", HOST)
    first.banned_ips.clear()

    second = _manager()
    second.redis_handler = live_redis
    second.config = config
    second._ban_ip_escalating(HOST, 100, "t")

    stored = float(live_redis.get_key("banned_ips", HOST))
    assert 190 < stored - time.time() <= 200


def test_only_one_of_two_simultaneous_writers_wins_the_ban(
    live_redis: RedisManager,
) -> None:
    config = SecurityConfig(
        redis_url=REDIS_URL,
        redis_prefix=live_redis.config.redis_prefix,
        enable_recidive=True,
    )
    manager = _manager()
    manager.redis_handler = live_redis
    manager.config = config

    manager._ban_ip_escalating(HOST, 100, "t")
    manager.banned_ips.clear()
    manager._ban_ip_escalating(HOST, 100, "t")

    assert int(live_redis.get_key("recidive", HOST)) == 1


def test_unban_ip_forgets_the_history_in_redis(live_redis: RedisManager) -> None:
    manager = _manager()
    manager.redis_handler = live_redis
    manager.config = SecurityConfig(
        redis_url=REDIS_URL,
        redis_prefix=live_redis.config.redis_prefix,
        enable_recidive=True,
    )
    manager._ban_ip_escalating(HOST, 100, "t")
    assert live_redis.get_key("recidive", HOST) is not None

    manager.unban_ip(HOST)

    assert live_redis.get_key("recidive", HOST) is None


def test_a_slash_64_unban_forgets_the_identity_history_in_redis(
    live_redis: RedisManager,
) -> None:
    manager = _manager()
    manager.redis_handler = live_redis
    manager.config = SecurityConfig(
        redis_url=REDIS_URL,
        redis_prefix=live_redis.config.redis_prefix,
        enable_recidive=True,
    )
    manager._ban_ip_escalating(IDENTITY, 100, "t", grouped=True)
    assert live_redis.get_key("recidive", IDENTITY) is not None

    manager.unban_ip(HOST_IN_IDENTITY)

    assert live_redis.get_key("recidive", IDENTITY) is None


def test_the_range_whitelist_forgets_the_history_in_redis(
    live_redis: RedisManager,
) -> None:
    manager = _manager()
    manager.redis_handler = live_redis
    manager.config = SecurityConfig(
        redis_url=REDIS_URL,
        redis_prefix=live_redis.config.redis_prefix,
        enable_recidive=True,
    )
    manager._ban_ip_escalating(HOST, 100, "t")
    manager._ban_ip_escalating("1.1.1.1", 100, "t")

    manager.forget_strikes_inside(["8.8.8.0/24"])

    assert live_redis.get_key("recidive", HOST) is None
    assert live_redis.get_key("recidive", "1.1.1.1") is not None


def test_reset_forgets_every_history_in_redis(live_redis: RedisManager) -> None:
    manager = _manager()
    manager.redis_handler = live_redis
    manager.config = SecurityConfig(
        redis_url=REDIS_URL,
        redis_prefix=live_redis.config.redis_prefix,
        enable_recidive=True,
    )
    manager._ban_ip_escalating(HOST, 100, "t")

    manager.reset()

    assert live_redis.get_key("recidive", HOST) is None


def test_a_natural_expiry_inside_the_window_escalates_through_redis(
    live_redis: RedisManager,
) -> None:
    manager = _manager()
    manager.redis_handler = live_redis
    manager.config = SecurityConfig(
        redis_url=REDIS_URL,
        redis_prefix=live_redis.config.redis_prefix,
        enable_recidive=True,
    )
    manager._ban_ip_escalating(HOST, 3600, "t")
    live_redis.delete("banned_ips", HOST)
    manager.banned_ips.clear()

    manager._ban_ip_escalating(HOST, 3600, "t")

    stored = float(live_redis.get_key("banned_ips", HOST))
    assert 7100 < stored - time.time() <= 7200


def test_an_unreadable_redis_count_falls_back_to_this_process() -> None:
    manager = _manager()
    manager.redis_handler = MagicMock()
    manager.redis_handler.get_key = MagicMock(side_effect=RuntimeError("down"))
    manager.redis_handler.incr = MagicMock(side_effect=RuntimeError("down"))
    manager.redis_handler.set_key_if_absent = MagicMock(
        side_effect=RuntimeError("down")
    )
    manager._ban_ip_escalating(HOST, 100, "t")
    _expire_naturally(manager, HOST)

    manager._ban_ip_escalating(HOST, 100, "t")

    assert 190 < _remaining(manager, HOST) <= 200
