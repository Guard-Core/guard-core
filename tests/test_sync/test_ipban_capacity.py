import ipaddress
import logging
import time
from collections.abc import Generator
from unittest.mock import MagicMock, Mock

import pytest
from pydantic import ValidationError

from guard_core.models import SecurityConfig
from guard_core.sync.core.initialization.handler_initializer import HandlerInitializer
from guard_core.sync.handlers._ipban_cache import _BanStore
from guard_core.sync.handlers.ipban_handler import IPBanManager, ip_ban_manager

DEFAULT_CAP = 100_000


@pytest.fixture(autouse=True)
def reset_singleton() -> Generator[None, None, None]:
    IPBanManager._instance = None
    yield
    IPBanManager._instance = None


def test_the_cap_is_a_config_field_defaulting_to_one_hundred_thousand() -> None:
    assert SecurityConfig(enable_redis=False).banned_ips_max_entries == DEFAULT_CAP
    assert IPBanManager.MAX_LOCAL_BANS == DEFAULT_CAP


def test_a_cap_below_one_is_rejected() -> None:
    with pytest.raises(ValidationError):
        SecurityConfig(enable_redis=False, banned_ips_max_entries=0)


def test_the_initializer_sizes_the_store_from_the_field() -> None:
    config = SecurityConfig(
        enable_redis=False, lazy_init=False, banned_ips_max_entries=3
    )

    try:
        HandlerInitializer(config=config).initialize_redis_handlers()
        store = ip_ban_manager.banned_ips
        assert isinstance(store, _BanStore)
        assert store.maxsize == 3
    finally:
        ip_ban_manager.set_capacity(DEFAULT_CAP)


def test_lowering_the_cap_evicts_the_bans_closest_to_expiry() -> None:
    manager = IPBanManager()
    manager.redis_handler = None
    for index, duration in enumerate([300, 100, 200, 400]):
        manager.ban_ip(f"8.8.0.{index + 1}", duration, "t")

    store = manager.banned_ips
    assert isinstance(store, _BanStore)
    store.resize(2)

    assert manager.is_ip_banned("8.8.0.4") is True
    assert manager.is_ip_banned("8.8.0.1") is True
    assert manager.is_ip_banned("8.8.0.2") is False
    assert manager.is_ip_banned("8.8.0.3") is False


def test_every_memory_only_eviction_is_reported_and_the_warning_is_sampled(
    caplog: pytest.LogCaptureFixture,
) -> None:
    manager = IPBanManager()
    manager.redis_handler = None
    manager.agent_handler = Mock(send_event=MagicMock())
    store = manager.banned_ips
    assert isinstance(store, _BanStore)
    store.resize(1)
    caplog.set_level(logging.WARNING, logger="guard_core.sync.handlers.ipban")

    for index in range(102):
        manager.ban_ip(f"8.8.{index // 256}.{index % 256}", 600 + index, "t")

    sent = [call.args[0] for call in manager.agent_handler.send_event.call_args_list]
    evictions = [event for event in sent if event.event_type == "ip_ban_evicted"]
    assert [event.metadata["evictions"] for event in evictions] == list(range(1, 102))
    warnings = [r for r in caplog.records if "evicted" in r.getMessage()]
    assert len(warnings) == 2


def test_one_ban_over_the_real_cap_evicts_the_one_closest_to_expiry(
    caplog: pytest.LogCaptureFixture,
) -> None:
    manager = IPBanManager()
    manager.redis_handler = None
    manager.agent_handler = Mock(send_event=MagicMock())
    caplog.set_level(logging.WARNING, logger="guard_core.sync.handlers.ipban")
    base = int(ipaddress.IPv4Address("11.0.0.0"))
    shortest = str(ipaddress.IPv4Address(base))

    started = time.perf_counter()
    manager.ban_ip(shortest, 1_000, "t")
    for index in range(1, DEFAULT_CAP + 1):
        manager.ban_ip(str(ipaddress.IPv4Address(base + index)), 2_000, "t")
    elapsed = time.perf_counter() - started

    print(f"banned {DEFAULT_CAP + 1} addresses in {elapsed:.2f} s")
    assert len(manager.banned_ips) == DEFAULT_CAP
    assert manager.is_ip_banned(shortest) is False
    assert manager.is_ip_banned(str(ipaddress.IPv4Address(base + 1))) is True
    sent = [call.args[0] for call in manager.agent_handler.send_event.call_args_list]
    evictions = [event for event in sent if event.event_type == "ip_ban_evicted"]
    assert len(evictions) == 1
    assert evictions[0].ip_address == shortest
    assert 0 < evictions[0].metadata["remaining_seconds"] <= 1_000
    assert len([r for r in caplog.records if "evicted" in r.getMessage()]) == 1
    assert ip_ban_manager is not None
