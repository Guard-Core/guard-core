from collections.abc import Iterator
from datetime import datetime, timezone
from typing import Any
from unittest.mock import MagicMock

import pytest

from guard_core.models import DynamicRules, SecurityConfig
from guard_core.sync.handlers.dynamic_rule_handler import DynamicRuleManager
from guard_core.sync.handlers.ipban_handler import ip_ban_manager


@pytest.fixture(autouse=True)
def reset_singleton() -> Iterator[None]:
    DynamicRuleManager._instance = None
    yield
    DynamicRuleManager._instance = None


def _rules(**overrides: Any) -> DynamicRules:
    base: dict[str, Any] = {
        "rule_id": "R",
        "version": 1,
        "timestamp": datetime.now(timezone.utc),
    }
    base.update(overrides)
    return DynamicRules(**base)


def _manager(**config_kwargs: Any) -> tuple[DynamicRuleManager, SecurityConfig, Any]:
    settings: dict[str, Any] = {
        "enable_redis": False,
        "enable_agent": True,
        "agent_api_key": "test-api-key",
        "enable_dynamic_rules": True,
        "rate_limit": 600,
        "rate_limit_window": 60,
        "enable_rate_limiting": False,
    }
    settings.update(config_kwargs)
    config = SecurityConfig(**settings)
    ip_ban_manager.config = config
    manager = DynamicRuleManager(config)
    agent = MagicMock()
    agent.send_event = MagicMock()
    agent.get_dynamic_rules = MagicMock()
    manager.agent_handler = agent
    return manager, config, agent.send_event


def _poll(manager: DynamicRuleManager, rules: DynamicRules) -> None:
    manager.agent_handler.get_dynamic_rules.return_value = rules
    manager.update_rules()


def _event_types(send_event: Any) -> list[tuple[str, str]]:
    return [
        (call.args[0].event_type, call.args[0].action_taken)
        for call in send_event.call_args_list
    ]


MALFORMED = [
    pytest.param({"global_rate_limit": -5, "global_rate_window": 60}, id="negative"),
    pytest.param({"global_rate_limit": 0, "global_rate_window": 60}, id="zero-limit"),
    pytest.param({"global_rate_limit": 5, "global_rate_window": 0}, id="zero-window"),
    pytest.param({"global_rate_limit": 5, "global_rate_window": -1}, id="neg-window"),
    pytest.param({"endpoint_rate_limits": {"/x": (0, 0)}}, id="endpoint-zero"),
    pytest.param({"endpoint_rate_limits": {"/x": (5, 0)}}, id="endpoint-window"),
    pytest.param({"endpoint_rate_limits": {"/a/../b": (5, 60)}}, id="key-dot-dot"),
    pytest.param({"endpoint_rate_limits": {"/a//b": (5, 60)}}, id="key-double-slash"),
    pytest.param({"endpoint_rate_limits": {"/a%2Fb": (5, 60)}}, id="key-encoded-slash"),
    pytest.param(
        {"endpoint_rate_limits": {"/a%5cb": (5, 60)}}, id="key-encoded-bslash"
    ),
    pytest.param({"endpoint_rate_limits": {"/a\\b": (5, 60)}}, id="key-backslash"),
    pytest.param({"blocked_countries": ["USA!"]}, id="country-punct"),
    pytest.param({"blocked_countries": ["not a country"]}, id="country-words"),
    pytest.param({"blocked_countries": ["12"]}, id="country-digits"),
    pytest.param({"whitelist_countries": ["USA"]}, id="allow-three-letters"),
    pytest.param({"blocked_cloud_providers": {"NotACloud"}}, id="provider"),
    pytest.param({"ip_blacklist": ["not-an-ip"]}, id="ban-not-an-ip"),
    pytest.param({"ip_blacklist": ["10.0.0.0/33"]}, id="ban-bad-cidr"),
    pytest.param({"ip_whitelist": ["not-an-ip"]}, id="allow-not-an-ip"),
    pytest.param({"emergency_whitelist": ["10.0.0.0/33"]}, id="emergency-bad-cidr"),
    pytest.param({"emergency_whitelist": ["not-an-ip"]}, id="emergency-not-an-ip"),
]


@pytest.mark.parametrize("malformed", MALFORMED)
def test_malformed_rule_is_rejected_whole_once(malformed: dict[str, Any]) -> None:
    manager, config, send_event = _manager()
    fields = {
        "ip_blacklist": ["198.51.100.40"],
        "suspicious_patterns": [r"wp11validationpattern\d+"],
        "blocked_user_agents": ["wp11validationbot"],
        **malformed,
    }
    for _ in range(3):
        _poll(manager, _rules(**fields))

    assert config.rate_limit == 600
    assert not config.blocked_user_agents
    assert manager.current_rules is None
    assert not ip_ban_manager.is_ip_banned("198.51.100.40")
    assert _event_types(send_event) == [("dynamic_rule_updated", "rules_rejected")]
    metadata = send_event.call_args_list[0].args[0].metadata
    assert metadata["rejected"]


def test_rejected_rule_keeps_the_last_known_rule() -> None:
    manager, config, send_event = _manager()
    _poll(manager, _rules(global_rate_limit=50, global_rate_window=60))
    assert config.rate_limit == 50

    _poll(manager, _rules(version=2, global_rate_limit=-5, global_rate_window=60))

    assert config.rate_limit == 50
    assert manager.current_rules is not None
    assert manager.current_rules.version == 1
    assert ("dynamic_rule_updated", "rules_rejected") in _event_types(send_event)


def test_a_rule_fixed_after_rejection_is_applied() -> None:
    manager, config, _ = _manager()
    _poll(manager, _rules(global_rate_limit=-5, global_rate_window=60))
    _poll(manager, _rules(version=2, global_rate_limit=70, global_rate_window=60))
    assert config.rate_limit == 70


def test_apply_rules_rejects_a_malformed_rule_before_any_side_effect() -> None:
    from guard_core.sync.handlers._dynamic_rule_validation import MalformedDynamicRules

    manager, config, _ = _manager()
    with pytest.raises(MalformedDynamicRules) as caught:
        manager._apply_rules(
            _rules(ip_blacklist=["198.51.100.41"], global_rate_limit=-1)
        )
    assert caught.value.problems
    assert not ip_ban_manager.is_ip_banned("198.51.100.41")
    assert config.rate_limit == 600


def test_country_rules_without_geo_are_skipped_and_the_rest_applies() -> None:
    manager, config, send_event = _manager()
    _poll(
        manager,
        _rules(
            blocked_countries=["RU"],
            whitelist_countries=["US"],
            global_rate_limit=50,
            global_rate_window=60,
        ),
    )

    assert config.rate_limit == 50
    assert not config.blocked_countries
    applied = [
        call.args[0]
        for call in send_event.call_args_list
        if call.args[0].event_type == "dynamic_rule_applied"
    ]
    assert len(applied) == 1
    assert any("blocked_countries" in item for item in applied[0].metadata["skipped"])


def test_unsafe_patterns_are_skipped_and_listed_in_the_applied_event() -> None:
    manager, config, send_event = _manager()
    _poll(
        manager,
        _rules(blocked_user_agents=["goodbot", r"(a|aa)+$"], global_rate_limit=50),
    )

    assert config.blocked_user_agents == ["goodbot"]
    applied = [
        call.args[0]
        for call in send_event.call_args_list
        if call.args[0].event_type == "dynamic_rule_applied"
    ]
    skipped = applied[0].metadata["skipped"]
    assert any(item.startswith("blocked_user_agents:") for item in skipped)


def test_a_refused_self_ban_is_skipped_and_reported() -> None:
    manager, _, send_event = _manager()
    _poll(manager, _rules(ip_blacklist=["127.0.0.1", "198.51.100.50"]))

    assert ip_ban_manager.is_ip_banned("198.51.100.50")
    applied = [
        call.args[0]
        for call in send_event.call_args_list
        if call.args[0].event_type == "dynamic_rule_applied"
    ]
    assert (
        "ip_blacklist: 127.0.0.1 (ban refused: loopback)"
        in (applied[0].metadata["skipped"])
    )


def test_a_valid_emergency_whitelist_is_still_applied() -> None:
    manager, config, _ = _manager()
    _poll(
        manager,
        _rules(emergency_mode=True, emergency_whitelist=["198.51.100.0/24", "::1"]),
    )
    assert config.emergency_mode is True
