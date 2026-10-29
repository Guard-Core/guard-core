import logging
import re
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, Mock, call

import pytest

from guard_core._security_headers_defaults import _DEFAULT_SECURITY_HEADERS_CONFIG
from guard_core.core.events.composite_handler import CompositeAgentHandler
from guard_core.core.events.logfire_handler import LogfireHandler
from guard_core.core.initialization.handler_initializer import HandlerInitializer
from guard_core.detection_engine.binary_prefix import match_has_text_neighbourhood
from guard_core.detection_engine.compiler import submit_to_regex_executor
from guard_core.detection_engine.encoding_decoders import repair_lost_overlong_bytes
from guard_core.handlers import _redis_handler_support as redis_types
from guard_core.handlers._ipban_migration import _close_if_unusable
from guard_core.handlers._ipban_prefix_contract import enforce_prefix_length_contract
from guard_core.handlers._security_headers_apply import (
    apply_security_headers_settings,
)
from guard_core.handlers.ipban_handler import ip_ban_manager_for
from guard_core.handlers.ipinfo_handler import IPInfoManager
from guard_core.handlers.redis_handler import RedisManager
from guard_core.handlers.security_headers_handler import SecurityHeadersManager
from guard_core.models import SecurityConfig


async def test_a_composite_skips_the_stats_of_a_handler_that_has_none() -> None:
    without_stats = Mock(spec=["send_event"])
    with_stats = Mock(spec=["get_stats"])
    with_stats.get_stats.return_value = {"events_sent": 2}
    composite = CompositeAgentHandler([without_stats, with_stats])

    assert composite.get_stats() == {"events_sent": 2}


def test_the_logfire_handler_reports_no_stats() -> None:
    assert LogfireHandler(MagicMock(logfire_service_name="svc")).get_stats() == {}


def test_a_match_has_no_text_neighbourhood_without_a_binary_prefix() -> None:
    match = re.search("b", "abc")
    assert match is not None

    assert match_has_text_neighbourhood(None, match) is False


def test_the_regex_executor_reports_how_long_the_work_ran() -> None:
    ran_for: list[float] = []

    future, started = submit_to_regex_executor(lambda: "done", ran_for=ran_for)

    assert future.result(timeout=5) == "done"
    assert len(started) == 1
    assert len(ran_for) == 1
    assert ran_for[0] >= 0.0


def test_a_chain_of_lost_traversal_segments_is_repaired_in_bounded_passes() -> None:
    lost_segment = "..\ufffd\ufffd"

    assert repair_lost_overlong_bytes(f"/a/{lost_segment * 3}etc") == "/a/../../../etc"
    assert (
        repair_lost_overlong_bytes(f"/a/{lost_segment * 5}etc")
        == f"/a/../../../../{lost_segment}etc"
    )


class _NoCloseAttribute:
    close = None


def test_an_object_without_the_awaited_member_is_closed_when_it_can_be() -> None:
    closer = MagicMock()
    unusable = SimpleNamespace(close=closer)

    assert _close_if_unusable(unusable, "__aenter__") is False
    closer.assert_called_once_with()


def test_an_object_whose_close_is_not_callable_is_left_alone() -> None:
    assert _close_if_unusable(_NoCloseAttribute(), "__aenter__") is False
    assert _close_if_unusable(object(), "__aenter__") is False


async def test_a_config_without_an_ipv6_prefix_length_records_nothing() -> None:
    redis_handler = MagicMock()
    redis_handler.set_key_if_absent = AsyncMock()
    redis_handler.get_key = AsyncMock()
    config = Mock(spec=[])

    await enforce_prefix_length_contract(
        redis_handler, config, logging.getLogger("wp303")
    )

    redis_handler.set_key_if_absent.assert_not_awaited()
    redis_handler.get_key.assert_not_awaited()


async def test_a_redis_that_cannot_record_the_prefix_length_is_logged_not_fatal(
    caplog: pytest.LogCaptureFixture,
) -> None:
    redis_handler = MagicMock()
    redis_handler.config.redis_prefix = "wp303:"
    redis_handler.set_key_if_absent = AsyncMock(side_effect=ConnectionError("down"))
    config = SecurityConfig(enable_redis=False, ipv6_prefix_length=64)

    with caplog.at_level(logging.WARNING, logger="wp303"):
        await enforce_prefix_length_contract(
            redis_handler, config, logging.getLogger("wp303")
        )

    assert "The recorded ipv6_prefix_length could not be checked: down" in caplog.text


V6 = "2001:db8:1:2::9"
_SHARED_REDIS = "redis://user:hunter2@one.invalid:6379/0"


async def _app_on_the_shared_redis(prefix: str) -> SecurityConfig:
    config = SecurityConfig(
        enable_redis=True,
        redis_url=_SHARED_REDIS,
        redis_prefix=prefix,
        enable_agent=False,
        ipv6_prefix_length=64,
    )
    redis = MagicMock()
    redis.initialize = AsyncMock()
    redis.get_key = AsyncMock(return_value=None)
    initializer = HandlerInitializer(config, redis_handler=redis)
    await initializer.initialize_redis_handlers()
    return config


async def test_an_unban_through_two_apps_of_one_identity_unbans_it_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first = await _app_on_the_shared_redis("wp303-same-identity:")
    second = await _app_on_the_shared_redis("wp303-same-identity:")
    ban = ip_ban_manager_for(first)
    identity = ban._grouped_identity_of(V6, first)
    assert identity == ban._grouped_identity_of(V6, second)
    ban.banned_ips[identity] = 10**12
    forgotten = AsyncMock()
    monkeypatch.setattr(ban, "_write_with_version_bump", AsyncMock())
    monkeypatch.setattr(ban, "_forget_strikes", forgotten)

    await ban.unban_ip(V6)

    assert identity not in ban.banned_ips
    assert forgotten.call_args_list == [call(V6), call(identity)]


async def test_a_geo_copy_for_a_handler_without_a_key_prefix_is_set_if_absent(
    tmp_path: Path,
) -> None:
    IPInfoManager._instance = None
    manager = IPInfoManager(token="tok", db_path=tmp_path / "geo.mmdb")
    manager._max_age = 3600
    manager.db_path.write_bytes(b"\x00\xff mmdb")
    handler = MagicMock()
    handler.config = SimpleNamespace(enable_redis=False, redis_prefix="wp303:")
    handler.set_key_if_absent = AsyncMock()
    handler.set_key = AsyncMock()

    await manager._cache_database_in_redis([handler], only_if_absent=True)

    handler.set_key_if_absent.assert_awaited_once_with(
        "ipinfo", "database", "\x00\xff mmdb", 3600
    )
    handler.set_key.assert_not_awaited()
    IPInfoManager._instance = None


async def test_a_ban_strike_script_with_redis_off_returns_no_result() -> None:
    manager = RedisManager(SecurityConfig(enable_redis=False))

    with pytest.raises(TypeError, match=redis_types.NO_OPERATION_RESULT):
        await manager.get_bans_and_record_strike(
            [("banned_ips", "198.51.100.5")],
            ("ban_version", "counter"),
            None,
            1.0,
            "198.51.100.5",
            ("ip_list",),
            1.0,
            0.0,
            60,
            10,
        )


def test_a_default_security_header_that_is_not_text_is_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setitem(_DEFAULT_SECURITY_HEADERS_CONFIG, "xss_protection", None)
    config = SecurityConfig(enable_redis=False, security_headers={"enabled": True})

    with pytest.raises(TypeError, match="default xss_protection setting"):
        apply_security_headers_settings(SecurityHeadersManager(), config)
