import warnings
from collections.abc import Generator
from typing import Any
from unittest.mock import patch

import pytest

from guard_core import _staged_defaults
from guard_core.core.checks.factory import build_default_pipeline
from guard_core.decorators import SecurityDecorator
from guard_core.handlers.ipban_handler import ip_ban_manager
from guard_core.models import SecurityConfig
from tests.conftest import MockGuardRequest
from tests.test_core.conftest import build_middleware

CLIENT = "203.0.113.20"
OTHER = "203.0.113.21"
XSS = {"q": "<script>alert(1)</script>"}


@pytest.fixture(autouse=True)
def _fresh_ban_store() -> Generator[None, None, None]:
    ip_ban_manager.banned_ips.clear()
    ip_ban_manager.banned_networks.clear()
    ip_ban_manager.redis_handler = None
    yield
    ip_ban_manager.banned_ips.clear()
    ip_ban_manager.banned_networks.clear()


def _config(access_only: bool, **settings: Any) -> SecurityConfig:
    defaults: dict[str, Any] = {
        "enable_redis": False,
        "enable_penetration_detection": False,
        "enable_rate_limiting": False,
        "whitelist": [CLIENT],
        "whitelist_access_only": access_only,
    }
    return SecurityConfig(**{**defaults, **settings})


async def _run(
    config: SecurityConfig,
    *,
    ip: str = CLIENT,
    headers: dict[str, str] | None = None,
    query: dict[str, str] | None = None,
    count: int = 1,
) -> list[int | None]:
    middleware = build_middleware(config, SecurityDecorator(config))
    pipeline = build_default_pipeline(middleware)
    statuses: list[int | None] = []
    for _ in range(count):
        request = MockGuardRequest(
            path="/x",
            client_host=ip,
            headers=headers or {},
            query_params=query or {},
        )
        response = await pipeline.execute(request)
        statuses.append(None if response is None else response.status_code)
    return statuses


@pytest.mark.parametrize("access_only", [True, False])
async def test_the_whitelist_still_admits_and_still_refuses_both_ways(
    access_only: bool,
) -> None:
    config = _config(access_only)

    assert await _run(config) == [None]
    assert await _run(config, ip=OTHER) == [403]


async def test_the_field_defaults_to_false() -> None:
    assert SecurityConfig(enable_redis=False).whitelist_access_only is False


BAD_AGENT = {"User-Agent": "badbot/1.0"}


async def test_flag_on_a_whitelisted_ip_is_blocked_for_a_bad_user_agent() -> None:
    config = _config(True, blocked_user_agents=["badbot"])

    assert await _run(config, headers=BAD_AGENT) == [403]


async def test_flag_off_a_whitelisted_ip_skips_the_user_agent_check() -> None:
    config = _config(False, blocked_user_agents=["badbot"])

    assert await _run(config, headers=BAD_AGENT) == [None]


async def test_an_exempt_ip_with_a_bad_user_agent_passes_with_the_flag_on() -> None:
    config = _config(
        True, whitelist=None, exempt_ips=[CLIENT], blocked_user_agents=["badbot"]
    )

    assert await _run(config, headers=BAD_AGENT) == [None]


async def test_flag_on_a_whitelisted_ip_is_blocked_for_a_blocked_cloud() -> None:
    config = _config(True, block_cloud_providers={"AWS"})
    with patch(
        "guard_core.handlers.cloud_handler.cloud_handler.is_cloud_ip",
        return_value=True,
    ):
        assert await _run(config) == [403]


async def test_flag_off_a_whitelisted_ip_skips_the_cloud_check() -> None:
    config = _config(False, block_cloud_providers={"AWS"})
    with patch(
        "guard_core.handlers.cloud_handler.cloud_handler.is_cloud_ip",
        return_value=True,
    ):
        assert await _run(config) == [None]


async def test_flag_on_a_whitelisted_ip_is_stopped_by_detection() -> None:
    config = _config(True, enable_penetration_detection=True)

    assert await _run(config, query=XSS) == [400]


async def test_flag_off_a_whitelisted_ip_skips_detection() -> None:
    config = _config(False, enable_penetration_detection=True)

    assert await _run(config, query=XSS) == [None]


async def test_flag_on_a_whitelisted_ip_is_rate_limited() -> None:
    config = _config(
        True, enable_rate_limiting=True, rate_limit=1, rate_limit_window=60
    )

    assert await _run(config, count=3) == [None, 429, 429]


async def test_flag_off_a_whitelisted_ip_is_not_rate_limited() -> None:
    config = _config(
        False, enable_rate_limiting=True, rate_limit=1, rate_limit_window=60
    )

    assert await _run(config, count=3) == [None, None, None]


async def test_flag_on_a_whitelisted_ip_is_banned_at_the_threshold() -> None:
    config = _config(
        True,
        enable_rate_limiting=True,
        rate_limit=1,
        rate_limit_window=60,
        enable_rate_limit_auto_ban=True,
        auto_ban_threshold=2,
    )

    statuses = await _run(config, count=5)

    assert 403 in statuses
    assert await ip_ban_manager.is_ip_banned(CLIENT) is True


async def test_flag_on_hostile_signal_strikes_ban_a_whitelisted_ip() -> None:
    config = _config(
        True,
        blocked_user_agents=["badbot"],
        ban_on_hostile_signals=True,
        auto_ban_threshold=2,
    )

    statuses = await _run(config, headers=BAD_AGENT, count=4)

    assert statuses == [403, 403, 403, 403]
    assert await ip_ban_manager.is_ip_banned(CLIENT) is True


async def test_flag_off_a_whitelisted_ip_collects_no_strikes() -> None:
    config = _config(
        False,
        blocked_user_agents=["badbot"],
        ban_on_hostile_signals=True,
        auto_ban_threshold=2,
    )

    assert await _run(config, headers=BAD_AGENT, count=4) == [None] * 4
    assert await ip_ban_manager.is_ip_banned(CLIENT) is False


@pytest.mark.parametrize("access_only", [True, False])
async def test_emergency_mode_keeps_its_own_whitelist(access_only: bool) -> None:
    config = _config(access_only, emergency_mode=True)
    admitting = _config(
        access_only, emergency_mode=True, emergency_whitelist_only=False
    )

    assert await _run(config) == [503]
    assert await _run(admitting) == [None]


async def test_a_whitelisted_ip_inside_a_banned_ban_is_still_denied() -> None:
    config = _config(True)
    await ip_ban_manager.ban_ip(CLIENT + "/32", 600, "operator")

    assert await _run(config) == [403]


async def test_the_matched_entry_is_exposed_on_the_request_when_the_flag_is_on() -> (
    None
):
    config = _config(True, whitelist=["203.0.113.0/24", CLIENT])
    middleware = build_middleware(config, SecurityDecorator(config))
    pipeline = build_default_pipeline(middleware)
    request = MockGuardRequest(path="/x", client_host=CLIENT)

    await pipeline.execute(request)

    assert request.state.is_whitelisted is False
    assert request.state.whitelist_entry == f"{CLIENT}/32"


async def test_the_flag_off_marks_the_request_as_whitelisted_as_before() -> None:
    config = _config(False)
    middleware = build_middleware(config, SecurityDecorator(config))
    pipeline = build_default_pipeline(middleware)
    request = MockGuardRequest(path="/x", client_host=CLIENT)

    await pipeline.execute(request)

    assert request.state.is_whitelisted is True


async def test_a_neighbours_429s_do_not_consume_the_whitelisted_hosts_budget() -> None:
    host = "2001:db8:0:1::5"
    neighbour = "2001:db8:0:1::6"
    config = _config(
        True,
        whitelist=[host, "2001:db8:0:1::/64"],
        enable_rate_limiting=True,
        rate_limit=2,
        rate_limit_window=60,
    )
    middleware = build_middleware(config, SecurityDecorator(config))
    pipeline = build_default_pipeline(middleware)

    async def status(ip: str) -> int | None:
        response = await pipeline.execute(MockGuardRequest(path="/x", client_host=ip))
        return None if response is None else response.status_code

    neighbour_statuses = [await status(neighbour) for _ in range(5)]
    host_statuses = [await status(host) for _ in range(3)]

    assert neighbour_statuses == [None, None, 429, 429, 429]
    assert host_statuses == [None, None, 429]


async def test_a_whitelisted_host_that_attacks_is_banned_at_its_own_identity() -> None:
    host = "2001:db8:0:1::5"
    neighbour = "2001:db8:0:1::6"
    config = _config(
        True,
        whitelist=[host, "2001:db8:0:1::/64"],
        enable_rate_limiting=True,
        rate_limit=1,
        rate_limit_window=60,
        enable_rate_limit_auto_ban=True,
        auto_ban_threshold=2,
    )

    await _run(config, ip=host, count=5)

    assert await ip_ban_manager.is_ip_banned(host) is True
    assert await ip_ban_manager.is_ip_banned(neighbour) is False


def test_unset_flag_warns_once_when_a_whitelist_is_configured() -> None:
    _staged_defaults._whitelist_access_only_warned = False

    with pytest.warns(DeprecationWarning, match="whitelist_access_only") as caught:
        SecurityConfig(enable_redis=False, whitelist=[CLIENT])

    message = str(caught[0].message)
    assert "5.0.0" in message
    assert "exempt_ips" in message
    assert "whitelist_access_only=True" in message
    assert "whitelist_access_only=False" in message
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        SecurityConfig(enable_redis=False, whitelist=[CLIENT])


def test_an_explicit_flag_or_no_whitelist_does_not_warn() -> None:
    _staged_defaults._whitelist_access_only_warned = False

    with warnings.catch_warnings():
        warnings.simplefilter("error", DeprecationWarning)
        SecurityConfig(
            enable_redis=False, whitelist=[CLIENT], whitelist_access_only=False
        )
        SecurityConfig(enable_redis=False)
