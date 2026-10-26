from collections.abc import Iterator
from datetime import datetime, timezone
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from guard_core.core.checks.implementations.emergency_mode import EmergencyModeCheck
from guard_core.handlers.dynamic_rule_handler import DynamicRuleManager
from guard_core.models import DynamicRules, SecurityConfig
from tests.conftest import MockGuardRequest, MockGuardResponse

EMERGENCY_IP = "10.0.0.1"
WHITELISTED_IP = "203.0.113.5"
EXEMPT_IP = "198.51.100.9"
UNKNOWN_IP = "192.0.2.77"


@pytest.fixture(autouse=True)
def reset_singleton() -> Iterator[None]:
    DynamicRuleManager._instance = None
    yield
    DynamicRuleManager._instance = None


def _rules(**overrides: Any) -> DynamicRules:
    fields: dict[str, Any] = {
        "rule_id": "R",
        "version": 1,
        "timestamp": datetime.now(timezone.utc),
    }
    fields.update(overrides)
    return DynamicRules(**fields)


def _check(**config: Any) -> EmergencyModeCheck:
    return _check_for(_config(**config))


def _config(**config: Any) -> SecurityConfig:
    return SecurityConfig(
        enable_redis=False,
        emergency_mode=True,
        emergency_whitelist=[EMERGENCY_IP],
        whitelist=[EMERGENCY_IP, "203.0.113.0/24"],
        exempt_ips=[EXEMPT_IP],
        **config,
    )


def _check_for(config: SecurityConfig) -> EmergencyModeCheck:
    middleware = MagicMock()
    middleware.config = config
    middleware.logger = MagicMock()
    middleware.event_bus.send_middleware_event = AsyncMock()
    middleware.create_error_response = AsyncMock(
        return_value=MockGuardResponse("unavailable", 503)
    )
    return EmergencyModeCheck(middleware)


async def _status(check: EmergencyModeCheck, ip: str) -> int | None:
    request = MockGuardRequest(client_host=ip)
    request.state.client_ip = ip
    with patch(
        "guard_core.core.checks.implementations.emergency_mode.log_activity",
        new=AsyncMock(),
    ):
        response = await check.check(request)
    return None if response is None else response.status_code


def test_emergency_whitelist_only_defaults_to_on() -> None:
    assert SecurityConfig().emergency_whitelist_only is True
    assert _rules().emergency_whitelist_only is True


@pytest.mark.parametrize(
    ("ip", "expected"),
    [(EMERGENCY_IP, None), (WHITELISTED_IP, 503), (EXEMPT_IP, 503), (UNKNOWN_IP, 503)],
)
async def test_on_admits_only_the_emergency_whitelist(
    ip: str, expected: int | None
) -> None:
    assert await _status(_check(), ip) == expected


@pytest.mark.parametrize(
    ("ip", "expected"),
    [
        (EMERGENCY_IP, None),
        (WHITELISTED_IP, None),
        (EXEMPT_IP, None),
        (UNKNOWN_IP, 503),
    ],
)
async def test_off_also_admits_the_whitelist_and_exempt_ips(
    ip: str, expected: int | None
) -> None:
    assert await _status(_check(emergency_whitelist_only=False), ip) == expected


async def test_an_emergency_rule_sets_the_flag_and_a_revocation_restores_it() -> None:
    config = SecurityConfig(enable_redis=False)
    manager = DynamicRuleManager(config)

    await manager._apply_rules(
        _rules(emergency_mode=True, emergency_whitelist_only=False)
    )
    assert (config.emergency_mode, config.emergency_whitelist_only) == (True, False)

    await manager._apply_rules(_rules(version=2))
    assert (config.emergency_mode, config.emergency_whitelist_only) == (False, True)


async def test_an_emergency_rule_without_the_field_admits_only_the_list() -> None:
    config = SecurityConfig(enable_redis=False, emergency_whitelist_only=False)
    manager = DynamicRuleManager(config)

    await manager._apply_rules(_rules(emergency_mode=True))
    assert config.emergency_whitelist_only is True


DYNAMIC_IP = "198.18.0.7"
DYNAMIC_CIDR_IP = "198.19.4.20"


async def _apply_dynamic_whitelist(
    config: SecurityConfig, entries: list[str], version: int = 1
) -> None:
    await DynamicRuleManager(config)._apply_rules(
        _rules(version=version, ip_whitelist=entries)
    )


@pytest.mark.parametrize(
    ("ip", "expected"),
    [(DYNAMIC_IP, None), (DYNAMIC_CIDR_IP, None), (UNKNOWN_IP, 503)],
)
async def test_off_admits_the_dynamic_rule_ip_whitelist(
    ip: str, expected: int | None
) -> None:
    config = _config(emergency_whitelist_only=False)
    await _apply_dynamic_whitelist(config, [DYNAMIC_IP, "198.19.4.0/24"])
    assert await _status(_check_for(config), ip) == expected


@pytest.mark.parametrize("ip", [DYNAMIC_IP, DYNAMIC_CIDR_IP])
async def test_on_still_blocks_the_dynamic_rule_ip_whitelist(ip: str) -> None:
    config = _config()
    await _apply_dynamic_whitelist(config, [DYNAMIC_IP, "198.19.4.0/24"])
    assert await _status(_check_for(config), ip) == 503


async def test_off_blocks_again_once_the_rule_drops_the_ip() -> None:
    config = _config(emergency_whitelist_only=False)
    await _apply_dynamic_whitelist(config, [DYNAMIC_IP])
    assert await _status(_check_for(config), DYNAMIC_IP) is None
    await _apply_dynamic_whitelist(config, [EXEMPT_IP], version=2)
    assert await _status(_check_for(config), DYNAMIC_IP) == 503


async def test_passive_mode_logs_only_for_a_dynamic_rule_ip_when_off() -> None:
    config = _config(emergency_whitelist_only=False, passive_mode=True)
    await _apply_dynamic_whitelist(config, [DYNAMIC_IP])
    assert await _status(_check_for(config), DYNAMIC_IP) is None
    assert await _status(_check_for(config), UNKNOWN_IP) is None
