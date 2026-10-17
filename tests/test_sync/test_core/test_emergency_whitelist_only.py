from collections.abc import Iterator
from datetime import datetime, timezone
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from guard_core.models import DynamicRules, SecurityConfig
from guard_core.sync.core.checks.implementations.emergency_mode import (
    EmergencyModeCheck,
)
from guard_core.sync.handlers.dynamic_rule_handler import DynamicRuleManager
from tests.test_sync.conftest import MockGuardResponse, SyncMockGuardRequest

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
    middleware = MagicMock()
    middleware.config = SecurityConfig(
        enable_redis=False,
        emergency_mode=True,
        emergency_whitelist=[EMERGENCY_IP],
        whitelist=[EMERGENCY_IP, "203.0.113.0/24"],
        exempt_ips=[EXEMPT_IP],
        **config,
    )
    middleware.logger = MagicMock()
    middleware.event_bus.send_middleware_event = MagicMock()
    middleware.create_error_response = MagicMock(
        return_value=MockGuardResponse("unavailable", 503)
    )
    return EmergencyModeCheck(middleware)


def _status(check: EmergencyModeCheck, ip: str) -> int | None:
    request = SyncMockGuardRequest(client_host=ip)
    request.state.client_ip = ip
    with patch(
        "guard_core.sync.core.checks.implementations.emergency_mode.log_activity",
        new=MagicMock(),
    ):
        response = check.check(request)
    return None if response is None else response.status_code


def test_emergency_whitelist_only_defaults_to_on() -> None:
    assert SecurityConfig().emergency_whitelist_only is True
    assert _rules().emergency_whitelist_only is True


@pytest.mark.parametrize(
    ("ip", "expected"),
    [(EMERGENCY_IP, None), (WHITELISTED_IP, 503), (EXEMPT_IP, 503), (UNKNOWN_IP, 503)],
)
def test_on_admits_only_the_emergency_whitelist(ip: str, expected: int | None) -> None:
    assert _status(_check(), ip) == expected


@pytest.mark.parametrize(
    ("ip", "expected"),
    [
        (EMERGENCY_IP, None),
        (WHITELISTED_IP, None),
        (EXEMPT_IP, None),
        (UNKNOWN_IP, 503),
    ],
)
def test_off_also_admits_the_whitelist_and_exempt_ips(
    ip: str, expected: int | None
) -> None:
    assert _status(_check(emergency_whitelist_only=False), ip) == expected


def test_an_emergency_rule_sets_the_flag_and_a_revocation_restores_it() -> None:
    config = SecurityConfig(enable_redis=False)
    manager = DynamicRuleManager(config)

    manager._apply_rules(_rules(emergency_mode=True, emergency_whitelist_only=False))
    assert (config.emergency_mode, config.emergency_whitelist_only) == (True, False)

    manager._apply_rules(_rules(version=2))
    assert (config.emergency_mode, config.emergency_whitelist_only) == (False, True)


def test_an_emergency_rule_without_the_field_admits_only_the_list() -> None:
    config = SecurityConfig(enable_redis=False, emergency_whitelist_only=False)
    manager = DynamicRuleManager(config)

    manager._apply_rules(_rules(emergency_mode=True))
    assert config.emergency_whitelist_only is True
