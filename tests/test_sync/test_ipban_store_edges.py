import logging
import os
import time
import uuid
from collections.abc import Generator
from typing import Any
from unittest.mock import MagicMock

import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.sync.handlers._ipban_cache import _BanStore
from guard_core.sync.handlers.ipban_handler import IPBanManager
from guard_core.sync.handlers.redis_handler import RedisManager
from tests.test_sync.ipban_redis_fake import (
    fake_ban_redis,
    pipeline_of,
    redis_with_connection,
    scanning,
)


@pytest.fixture(autouse=True)
def reset_singleton() -> Generator[None, None, None]:
    IPBanManager._instance = None
    yield
    IPBanManager._instance = None


def _store(maxsize: int = 2) -> _BanStore:
    return _BanStore(maxsize=maxsize, on_evict=lambda *_: None)


def test_a_stale_heap_entry_is_skipped_when_the_store_evicts() -> None:
    evicted: list[str] = []
    store = _BanStore(maxsize=2, on_evict=lambda key, _expiry: evicted.append(key))
    expiry = time.time() + 1000
    store["a"] = expiry
    store["a"] = expiry + 500
    store["b"] = expiry + 100

    store["c"] = expiry + 200

    assert evicted == ["b"]
    assert sorted(store) == ["a", "c"]


def test_evicting_from_a_heap_with_only_stale_entries_changes_nothing() -> None:
    store = _store()
    store["a"] = time.time() + 1000
    del store["a"]

    store._evict_closest_to_expiry()

    assert len(store) == 0


def test_the_heap_is_rebuilt_when_it_outgrows_the_live_entries() -> None:
    store = _store()
    expiry = time.time() + 1000
    for step in range(1100):
        store["a"] = expiry + step

    assert len(store._heap) < 1100
    assert store["a"] == expiry + 1099


def test_the_capacity_of_a_plain_dict_store_is_left_alone() -> None:
    manager = IPBanManager()
    manager.banned_ips = {}

    manager.set_capacity(5)

    assert manager.banned_ips == {}


def test_get_many_without_redis_enabled_returns_nothing_found() -> None:
    redis = RedisManager(SyncSecurityConfig(enable_redis=False))

    found = redis.get_many([("banned_ips", "1.1.1.1"), ("ban_version", "x")])

    assert found == [None, None]


def test_an_unreadable_or_unparsable_operator_ban_is_skipped() -> None:
    manager = IPBanManager()
    connection = MagicMock()
    connection.scan_iter = scanning(
        "guard:banned_networks:198.51.100.0/24",
        "guard:banned_networks:not-a-network",
        "guard:banned_networks:203.0.113.0/24",
    )
    connection.mget = MagicMock(return_value=["9999999999.0", "9999999999.0", None])
    manager.redis_handler = redis_with_connection(connection)

    expiries = manager._read_operator_expiries(manager.redis_handler)

    assert [str(network) for network in expiries] == ["198.51.100.0/24"]


def test_a_malformed_identity_is_checked_in_redis_when_it_is_on() -> None:
    manager = IPBanManager()
    manager.redis_handler = fake_ban_redis(ban_value=str(time.time() + 1000))

    assert manager.is_ip_banned("malformed-xff@9.9.9.9") is True


def test_a_malformed_identity_is_not_banned_without_redis() -> None:
    manager = IPBanManager()
    manager.redis_handler = None

    assert manager.is_ip_banned("malformed-xff@9.9.9.9") is False


def test_a_failed_eviction_event_is_logged(
    caplog: pytest.LogCaptureFixture,
) -> None:
    manager = IPBanManager()
    manager.agent_handler = MagicMock()
    manager.agent_handler.send_event = MagicMock(side_effect=RuntimeError("down"))

    with caplog.at_level(logging.ERROR, logger="guard_core.sync.handlers.ipban"):
        manager._send_ban_evicted_event(
            manager.agent_handler, "8.8.8.8", time.time() + 60, 1, 10
        )

    assert any("Failed to send ban evicted event" in m for m in caplog.messages)


def test_the_recidive_history_drops_expired_entries_before_evicting_a_live_one() -> (
    None
):
    manager = IPBanManager()
    manager.config = SyncSecurityConfig(enable_redis=False, banned_ips_max_entries=2)
    manager.recidive_history = {
        "8.8.8.8": (1, time.time() - 5),
        "8.8.4.4": (1, time.time() + 500),
    }

    manager._remember_recidive("1.1.1.1", 1, time.time() + 500)

    assert sorted(manager.recidive_history) == ["1.1.1.1", "8.8.4.4"]


CARVED = "2001:db8:0:1::5/128"
BASE = "2001:db8:0:1::/64"


def _carve_manager(connection: Any) -> IPBanManager:
    manager = IPBanManager()
    manager.config = SyncSecurityConfig(enable_redis=False)
    manager.redis_handler = redis_with_connection(connection)
    return manager


def test_a_key_that_is_not_a_network_is_never_a_carve() -> None:
    manager = IPBanManager()
    manager.config = SyncSecurityConfig(enable_redis=False)

    assert manager._base_identity_if_carve_is_gone("not-a-network") is None


def test_a_carve_that_expired_between_scan_and_read_is_not_moved() -> None:
    connection = MagicMock()
    connection.scan_iter = scanning(f"guard:banned_identities:{CARVED}")
    connection.get = MagicMock(return_value=None)
    connection.pttl = MagicMock(return_value=5000)
    manager = _carve_manager(connection)

    assert manager._rewrite_redis_carves(manager.redis_handler) == 0


def test_a_carve_without_a_ttl_is_not_moved() -> None:
    connection = MagicMock()
    connection.scan_iter = scanning(f"guard:banned_identities:{CARVED}")
    connection.get = MagicMock(return_value="123.0")
    connection.pttl = MagicMock(return_value=-1)
    manager = _carve_manager(connection)

    assert manager._rewrite_redis_carves(manager.redis_handler) == 0


def test_a_carve_keeps_a_longer_ban_of_its_base_identity() -> None:
    connection = MagicMock()
    connection.scan_iter = scanning(f"guard:banned_identities:{CARVED}")
    connection.get = MagicMock(return_value="123.0")
    connection.pttl = MagicMock(side_effect=[5000, 90000, -2, -2])
    pipe = MagicMock()
    pipe.set = MagicMock()
    pipe.delete = MagicMock()
    pipe.incr = MagicMock()
    pipe.execute = MagicMock()
    connection.pipeline = pipeline_of(pipe)
    manager = _carve_manager(connection)

    assert manager._rewrite_redis_carves(manager.redis_handler) == 1

    pipe.set.assert_not_called()
    pipe.delete.assert_called_once_with(
        f"guard:banned_identities:{CARVED}",
        f"guard:ban_floors:banned_identities:{CARVED}",
    )
    pipe.incr.assert_called_once_with("guard:ban_version:counter")
    pipe.execute.assert_called_once()


def test_a_carve_the_whitelist_still_produces_is_left_in_redis() -> None:
    connection = MagicMock()
    connection.scan_iter = scanning(f"guard:banned_identities:{CARVED}")
    connection.get = MagicMock()
    manager = _carve_manager(connection)
    manager.config = SyncSecurityConfig(
        enable_redis=False, whitelist=["2001:db8:0:1::5"]
    )

    assert manager._rewrite_redis_carves(manager.redis_handler) == 0

    connection.get.assert_not_called()


def test_a_grouped_ban_of_text_that_is_not_a_network_is_refused() -> None:
    manager = IPBanManager()
    manager.redis_handler = None

    with pytest.raises(ValueError, match="Invalid identity"):
        manager.ban_ip("not-a-network", 60, "t", grouped=True)


@pytest.fixture
def live_redis() -> Generator[RedisManager, None]:
    config = SyncSecurityConfig(
        redis_url=os.environ.get("REDIS_URL", "redis://localhost:6379"),
        redis_prefix=f"wp6-edges:{uuid.uuid4().hex}:",
    )
    manager = RedisManager(config)
    manager.initialize()
    yield manager
    manager.delete_pattern("*")
    manager.close()


def test_write_atomically_does_nothing_when_redis_is_off() -> None:
    redis = RedisManager(SyncSecurityConfig(enable_redis=False))

    redis.write_atomically(sets=[("ns", "k", "v", None)], deletes=[("ns", "j")])

    assert redis.get_key("ns", "k") is None


def test_write_atomically_sets_and_deletes_without_a_counter(
    live_redis: RedisManager,
) -> None:
    live_redis.set_key("ns", "old", "1")

    live_redis.write_atomically(sets=[("ns", "new", "2", 60)], deletes=[("ns", "old")])

    assert live_redis.get_key("ns", "new") == "2"
    assert live_redis.get_key("ns", "old") is None
    assert live_redis.get_key("ban_version", "counter") is None


def test_a_failed_version_bump_is_logged(
    caplog: pytest.LogCaptureFixture,
) -> None:
    manager = IPBanManager()
    manager.redis_handler = MagicMock()
    manager.redis_handler.incr = MagicMock(side_effect=OSError("down"))

    with caplog.at_level(logging.WARNING, logger="guard_core.sync.handlers.ipban"):
        manager._bump_ban_version()

    assert any("could not be advanced" in message for message in caplog.messages)
