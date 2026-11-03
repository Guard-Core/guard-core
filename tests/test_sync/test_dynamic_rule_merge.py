from collections.abc import Iterator
from datetime import datetime, timedelta, timezone
from typing import Any
from unittest.mock import MagicMock

import pytest

from guard_core.models import DynamicRules, SyncSecurityConfig
from guard_core.sync._utils.access_control import _is_loopback
from guard_core.sync.handlers._dynamic_rule_validation import MalformedDynamicRules
from guard_core.sync.handlers.dynamic_rule_handler import DynamicRuleManager
from guard_core.sync.protocols.geo_ip_protocol import SyncGeoIPHandler


@pytest.fixture(autouse=True)
def reset_singleton() -> Iterator[None]:
    DynamicRuleManager._instance = None
    yield
    DynamicRuleManager._instance = None


def _rules(**overrides: object) -> DynamicRules:
    base: dict[str, Any] = {
        "rule_id": "R",
        "version": 1,
        "timestamp": datetime.now(timezone.utc),
    }
    base.update(overrides)
    return DynamicRules(**base)


def _manager(**config_kwargs: object) -> tuple[DynamicRuleManager, SyncSecurityConfig]:
    settings: dict[str, Any] = {
        "enable_redis": False,
        "geo_ip_handler": MagicMock(spec=SyncGeoIPHandler),
        "blocked_countries": ["CN"],
        "block_cloud_providers": {"GCP"},
        "blocked_user_agents": ["staticbot"],
    }
    settings.update(config_kwargs)
    config = SyncSecurityConfig(**settings)
    return DynamicRuleManager(config), config


def test_dynamic_blocks_are_added_to_the_static_lists() -> None:
    manager, config = _manager()
    manager._apply_rules(
        _rules(
            blocked_countries=["ru", "CN", "ru"],
            blocked_cloud_providers={"AWS", "aws"},
            blocked_user_agents=["dynbot", "staticbot"],
        )
    )
    assert config.blocked_countries == frozenset({"CN", "RU"})
    assert config.block_cloud_providers == frozenset({"GCP", "AWS"})
    assert config.blocked_user_agents == ["staticbot", "dynbot"]


def test_dynamic_rule_with_nothing_usable_leaves_the_static_lists_intact() -> None:
    manager, config = _manager()
    with pytest.raises(MalformedDynamicRules):
        manager._apply_rules(_rules(blocked_cloud_providers={"NotACloud"}))
    manager._apply_rules(_rules(version=2, blocked_user_agents=[r"(a|aa)+$"]))

    assert config.block_cloud_providers == frozenset({"GCP"})
    assert config.blocked_user_agents == ["staticbot"]
    assert config.blocked_countries == frozenset({"CN"})


def test_revoking_the_rule_restores_exactly_the_static_lists() -> None:
    manager, config = _manager()
    rules = _rules(
        blocked_countries=["RU"],
        blocked_cloud_providers={"AWS"},
        blocked_user_agents=["dynbot"],
        expires_at=datetime.now(timezone.utc) - timedelta(seconds=1),
    )
    manager._apply_rules(rules)
    manager.current_rules = rules
    assert "RU" in config.blocked_countries

    manager._check_rule_expiry()

    assert config.blocked_countries == frozenset({"CN"})
    assert config.block_cloud_providers == frozenset({"GCP"})
    assert config.blocked_user_agents == ["staticbot"]


def test_dynamic_allow_list_replaces_only_when_non_empty_and_valid() -> None:
    manager, config = _manager(whitelist_countries=["US"], blocked_countries=[])
    manager._apply_rules(_rules(whitelist_countries=[]))
    assert config.whitelist_countries == frozenset({"US"})

    manager._apply_rules(_rules(version=2, whitelist_countries=["de", "fr"]))
    assert config.whitelist_countries == frozenset({"DE", "FR"})

    with pytest.raises(MalformedDynamicRules):
        manager._apply_rules(_rules(version=3, whitelist_countries=["de", "USA!"]))
    assert config.whitelist_countries == frozenset({"DE", "FR"})


def test_dynamic_allow_list_keeps_the_check_time_loopback_exemption() -> None:
    from guard_core.sync.utils import check_ip_access

    manager, config = _manager(blocked_countries=[])
    geo = MagicMock(spec=SyncGeoIPHandler)
    geo.get_country.return_value = "XX"
    config.geo_ip_handler = geo
    manager._apply_rules(_rules(whitelist_countries=["DE"]))

    assert config.whitelist_countries == frozenset({"DE"})
    assert _is_loopback("127.0.0.1")
    loopback = check_ip_access("127.0.0.1", config, geo)
    assert loopback.allowed is True
    stranger = check_ip_access("203.0.113.9", config, geo)
    assert stranger.allowed is False
