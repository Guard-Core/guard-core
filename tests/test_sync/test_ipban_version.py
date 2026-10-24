import os
import time
import uuid
from collections.abc import Generator
from unittest.mock import patch

import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.sync.handlers.ipban_handler import IPBanManager
from guard_core.sync.handlers.redis_handler import RedisManager
from tests.test_sync.engine_redis_commands import (
    engine_commands_sent,
    engine_redis_url,
    unwatch_engine_commands,
)

REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379")
OPERATOR_NETWORK = "198.51.100.0/24"
IN_NETWORK = "198.51.100.7"
HOST = "203.0.113.20"


@pytest.fixture(autouse=True)
def reset_singleton() -> Generator[None, None, None]:
    IPBanManager._instance = None
    yield
    IPBanManager._instance = None


@pytest.fixture
def live_redis() -> Generator[RedisManager, None]:
    config = SyncSecurityConfig(
        redis_url=engine_redis_url(REDIS_URL),
        redis_prefix=f"wp6-ver:{uuid.uuid4().hex}:",
    )
    manager = RedisManager(config)
    manager.initialize()
    yield manager
    manager.delete_pattern("*")
    manager.close()
    unwatch_engine_commands(config.redis_url)


def _worker(redis: RedisManager) -> IPBanManager:
    IPBanManager._instance = None
    manager = IPBanManager()
    manager.redis_handler = redis
    manager.config = SyncSecurityConfig(enable_redis=False)
    manager._VERSION_RECHECK_SECONDS = 0.05
    return manager


def _version(redis: RedisManager) -> int:
    return int(redis.get_key("ban_version", "counter") or 0)


def _commands(redis: RedisManager, name: str) -> int:
    return engine_commands_sent(redis.config.redis_url, name)


def test_an_operator_cidr_ban_is_enforced_on_the_worker_that_made_it(
    live_redis: RedisManager,
) -> None:
    worker = _worker(live_redis)

    worker.ban_ip(OPERATOR_NETWORK, 600, "operator")

    assert worker.is_ip_banned(IN_NETWORK) is True
    assert worker.is_ip_banned("198.51.101.7") is False


def test_an_operator_cidr_ban_is_enforced_on_another_worker(
    live_redis: RedisManager,
) -> None:
    writer = _worker(live_redis)
    reader = _worker(live_redis)
    assert reader.is_ip_banned(IN_NETWORK) is False

    writer.ban_ip(OPERATOR_NETWORK, 600, "operator")

    assert reader.is_ip_banned(IN_NETWORK) is True


def test_an_expired_redis_cidr_ban_is_not_enforced(
    live_redis: RedisManager,
) -> None:
    import time

    live_redis.set_key(
        "banned_networks", OPERATOR_NETWORK, str(time.time() - 5), ttl=60
    )
    reader = _worker(live_redis)

    assert reader.is_ip_banned(IN_NETWORK) is False


def test_a_cidr_unban_lifts_the_ban_on_another_worker(
    live_redis: RedisManager,
) -> None:
    writer = _worker(live_redis)
    reader = _worker(live_redis)
    writer.ban_ip(OPERATOR_NETWORK, 600, "operator")
    assert reader.is_ip_banned(IN_NETWORK) is True

    writer.unban_ip(OPERATOR_NETWORK)
    time.sleep(0.1)

    assert reader.is_ip_banned(IN_NETWORK) is False


def test_an_unban_reaches_a_worker_that_holds_the_ban_as_a_positive(
    live_redis: RedisManager,
) -> None:
    holder = _worker(live_redis)
    admin = _worker(live_redis)
    holder.ban_ip(HOST, 600, "t")
    assert holder.is_ip_banned(HOST) is True

    admin.unban_ip(HOST)
    time.sleep(0.1)

    assert holder.is_ip_banned(HOST) is False


def test_only_operator_bans_and_unbans_bump_the_version(
    live_redis: RedisManager,
) -> None:
    worker = _worker(live_redis)

    worker.ban_ip(HOST, 600, "threshold_exceeded")
    worker.ban_ip("2001:db8:0:1::/64", 600, "rate_limit_exceeded", grouped=True)
    assert _version(live_redis) == 0

    worker.ban_ip(OPERATOR_NETWORK, 600, "operator")
    assert _version(live_redis) == 1
    worker.unban_ip(HOST)
    assert _version(live_redis) == 2
    worker.unban_ip(OPERATOR_NETWORK)
    assert _version(live_redis) == 3
    worker.ban_ip("198.51.100.77", 600, "threshold_exceeded")
    assert _version(live_redis) == 3
    worker.unban_inside(["198.51.100.0/24"])
    assert _version(live_redis) == 4
    worker.reset()
    assert _version(live_redis) == 5


def test_a_thousand_auto_bans_cause_no_index_reload_on_another_worker(
    live_redis: RedisManager,
) -> None:
    writer = _worker(live_redis)
    reader = _worker(live_redis)
    reader.is_ip_banned(HOST)
    reloads = 0
    original = reader._reload_operator_networks

    def counting_reload() -> None:
        nonlocal reloads
        reloads += 1
        original()

    with patch.object(reader, "_reload_operator_networks", counting_reload):
        for index in range(1000):
            writer.ban_ip(f"10.9.{index // 256}.{index % 256}", 600, "t")
        reader.is_ip_banned("10.9.0.1")
        reader.is_ip_banned("192.0.2.1")

    assert reloads == 0


def test_a_clean_request_reads_the_version_in_its_one_command(
    live_redis: RedisManager,
) -> None:
    worker = _worker(live_redis)
    worker.is_ip_banned(HOST)
    mget_before = _commands(live_redis, "mget")
    get_before = _commands(live_redis, "get")

    worker.is_ip_banned("203.0.113.21")

    assert _commands(live_redis, "mget") - mget_before == 1
    assert _commands(live_redis, "get") - get_before == 0


def test_banned_clients_cost_one_version_read_per_interval_in_total(
    live_redis: RedisManager,
) -> None:
    worker = _worker(live_redis)
    worker._VERSION_RECHECK_SECONDS = 60.0
    for index in range(50):
        worker.ban_ip(f"203.0.113.{index + 30}", 600, "t")
    get_before = _commands(live_redis, "get")
    mget_before = _commands(live_redis, "mget")

    for index in range(50):
        for _ in range(5):
            assert worker.is_ip_banned(f"203.0.113.{index + 30}") is True

    assert _commands(live_redis, "get") - get_before <= 1
    assert _commands(live_redis, "mget") - mget_before == 0


def test_a_cidr_ban_survives_a_restart_of_the_worker(
    live_redis: RedisManager,
) -> None:
    _worker(live_redis).ban_ip(OPERATOR_NETWORK, 600, "operator")

    assert _worker(live_redis).is_ip_banned(IN_NETWORK) is True


def test_reset_clears_operator_cidr_bans_for_every_worker(
    live_redis: RedisManager,
) -> None:
    writer = _worker(live_redis)
    reader = _worker(live_redis)
    writer.ban_ip(OPERATOR_NETWORK, 600, "operator")
    writer.ban_ip("2001:db8:0:1::/64", 600, "t", grouped=True)
    assert reader.is_ip_banned(IN_NETWORK) is True

    writer.reset()
    time.sleep(0.1)

    assert reader.is_ip_banned(IN_NETWORK) is False
    assert reader.is_ip_banned("2001:db8:0:1::5") is False


def test_the_operator_network_index_answers_by_prefix_length() -> None:
    from ipaddress import ip_address, ip_network

    from guard_core.sync.handlers._ipban_cache import _OperatorNetworks

    index = _OperatorNetworks(
        {
            ip_network("10.0.0.0/8"): 200.0,
            ip_network("192.168.1.0/24"): 50.0,
            ip_network("2001:db8::/32"): 200.0,
        }
    )

    assert index.covers(ip_address("10.9.9.9"), 100.0) is True
    assert index.covers(ip_address("192.168.1.9"), 100.0) is False
    assert index.covers(ip_address("192.168.1.9"), 10.0) is True
    assert index.covers(ip_address("2001:db8::1"), 100.0) is True
    assert index.covers(ip_address("172.16.0.1"), 100.0) is False
