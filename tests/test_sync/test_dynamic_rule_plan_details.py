from collections.abc import Iterator
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from guard_core.models import DynamicRules, SecurityConfig
from guard_core.sync.detection_engine.compiler import PatternCompiler
from guard_core.sync.handlers._dynamic_rule_plan import DynamicRulePlan
from guard_core.sync.handlers.dynamic_rule_handler import DynamicRuleManager
from guard_core.sync.protocols.geo_ip_protocol import SyncGeoIPHandler


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


def _manager(geo: bool = True, **config_kwargs: Any) -> DynamicRuleManager:
    settings: dict[str, Any] = {"enable_redis": False}
    if geo:
        settings["geo_ip_handler"] = MagicMock(spec=SyncGeoIPHandler)
    settings.update(config_kwargs)
    return DynamicRuleManager(SecurityConfig(**settings))


def _plan(manager: DynamicRuleManager, rules: DynamicRules) -> DynamicRulePlan:
    return manager._build_plan(rules, manager._snapshot_config())


def test_a_fresh_plan_has_empty_defaults() -> None:
    plan = DynamicRulePlan(state={})
    assert plan.exempt_ips == []
    assert plan.emergency_whitelist is None
    assert plan.skipped == []
    assert plan.messages == []
    assert plan.validated == set()


def test_plan_messages_describe_every_applied_part() -> None:
    manager = _manager()
    with pytest.warns(UserWarning, match="blocked_countries is ignored"):
        plan = _plan(
            manager,
            _rules(
                blocked_countries=["ru", "RU"],
                whitelist_countries=["us"],
                blocked_cloud_providers={"azure"},
                blocked_user_agents=["goodbot"],
                global_rate_limit=50,
                global_rate_window=60,
                endpoint_rate_limits={"/a": (5, 60)},
                enable_penetration_detection=True,
                enable_ip_banning=False,
                enable_rate_limiting=True,
                enable_rate_limit_auto_ban=True,
                auto_ban_threshold=10,
                auto_ban_duration=600,
                ip_whitelist=["198.51.100.0/24"],
                emergency_mode=True,
                emergency_whitelist=["10.0.0.0/8"],
            ),
        )
    texts = [message for _, message in plan.messages]
    assert texts == [
        "Dynamic rule: Blocked countries ['RU']",
        "Dynamic rule: Whitelisted countries ['US']",
        "Dynamic rule: Blocked cloud providers frozenset({'Azure'})",
        "Dynamic rule: Blocked user agents ['goodbot']",
        "Dynamic rule: Exempt IPs ['198.51.100.0/24']",
        "Dynamic rule: Global rate limit 50 per 60s",
        "Dynamic rule: Applied endpoint-specific rate limits for 1 endpoints: ['/a']",
        "Dynamic rule: Penetration detection True",
        "Dynamic rule: IP banning False",
        "Dynamic rule: Rate limiting True",
        "Dynamic rule: Rate-limit auto-ban True",
        "Dynamic rule: Auto-ban threshold 10",
        "Dynamic rule: Auto-ban duration 600",
        "[EMERGENCY MODE] Reduced auto-ban threshold from 10 to 5",
    ]
    assert plan.emergency_whitelist == ["10.0.0.0/8"]
    assert "exempt_ips" not in plan.validated
    assert "blocked_user_agents" not in plan.validated
    assert {"blocked_countries", "rate_limit", "emergency_mode"} <= plan.validated


def test_static_countries_are_merged_not_replaced() -> None:
    manager = _manager(blocked_countries=["KP"])
    plan = _plan(manager, _rules(blocked_countries=["ru"]))
    assert plan.state["blocked_countries"] == frozenset({"KP", "RU"})


def test_emergency_threshold_never_drops_below_one_and_halves_otherwise() -> None:
    manager = _manager(auto_ban_threshold=1)
    plan = _plan(manager, _rules(emergency_mode=True))
    assert plan.state["auto_ban_threshold"] == 1

    DynamicRuleManager._instance = None
    plan = _plan(_manager(auto_ban_threshold=7), _rules(emergency_mode=True))
    assert plan.state["auto_ban_threshold"] == 3


def test_skips_are_listed_with_their_reasons() -> None:
    manager = _manager(geo=False)
    plan = _plan(
        manager,
        _rules(
            blocked_countries=["RU"],
            blocked_user_agents=[r"(a|aa)+$"],
            ip_blacklist=["198.51.100.9", "2001:db8::9"],
            ip_whitelist=["127.0.0.1", "198.51.100.0/24"],
        ),
    )
    assert sorted(plan.skipped) == sorted(
        [
            "blocked_countries and whitelist_countries: no geo_ip_handler or "
            "ipinfo_token to resolve IPs to countries",
            "ip_whitelist: 127.0.0.1 (loopback)",
            "ip_blacklist: 198.51.100.9 (overridden by ip_whitelist)",
            "blocked_user_agents: pattern '(a|aa)+$' failed the ReDoS validator",
        ]
    )
    texts = [message for _, message in plan.messages]
    assert (
        "Dynamic rule: country rules cannot take effect (blocked=['RU'], "
        "allowed=[]); no geo_ip_handler or ipinfo_token is configured to "
        "resolve IPs to countries"
    ) in texts
    assert "Dynamic rule: skipped ip_whitelist entry '127.0.0.1' (loopback)" in texts
    assert (
        "Dynamic rule: ip_blacklist entry 198.51.100.9 is also in ip_whitelist; "
        "the whitelist wins"
    ) in texts
    assert any(
        message.startswith(
            "Dynamic rule: rejected blocked_user_agents patterns failing the "
            "ReDoS validator: "
        )
        for message in texts
    )


def test_host_bits_in_ip_entries_are_accepted_and_mixed_families_coexist() -> None:
    manager = _manager()
    plan = _plan(
        manager,
        _rules(
            ip_blacklist=["198.51.100.77/24", "2001:db8::1"],
            ip_whitelist=["198.51.100.0/24"],
        ),
    )
    assert plan.skipped == [
        "ip_blacklist: 198.51.100.77/24 (overridden by ip_whitelist)"
    ]
    assert plan.exempt_ips == ["198.51.100.0/24"]


def test_exempt_entry_with_host_bits_is_canonicalized() -> None:
    manager = _manager()
    plan = _plan(manager, _rules(ip_whitelist=["198.51.100.77/24"]))
    assert plan.exempt_ips == ["198.51.100.0/24"]


def test_user_agent_validation_uses_the_configured_validation_cache(
    tmp_path: Path,
) -> None:
    cache_path = tmp_path / "validation-cache.json"
    manager = _manager(detection_pattern_validation_cache_path=str(cache_path))
    _plan(manager, _rules(blocked_user_agents=["cachedbot"]))
    assert cache_path.exists()


def test_each_user_agent_pattern_is_validated_exactly_once() -> None:
    manager = _manager()
    calls: list[str] = []
    original = PatternCompiler.validate_pattern_safety

    def spy(
        self: PatternCompiler,
        pattern: str,
        test_strings: list[str] | None = None,
        max_content_length: int | None = None,
    ) -> tuple[bool, str]:
        calls.append(pattern)
        return original(self, pattern, test_strings, max_content_length)

    with patch.object(PatternCompiler, "validate_pattern_safety", spy):
        manager._apply_rules(_rules(blocked_user_agents=["onebot", "twobot"]))
    assert calls == ["onebot", "twobot"]


def test_a_value_the_validators_reject_fails_the_plan_before_any_change() -> None:
    manager = _manager()
    rules = _rules(global_rate_limit=50, global_rate_window=60, auto_ban_threshold=7)
    rules.auto_ban_threshold = 0
    before = manager.config.auto_ban_threshold

    with pytest.raises(ValueError, match="auto_ban_threshold must be >= 1"):
        _plan(manager, rules)

    assert manager.config.auto_ban_threshold == before
    assert manager.config.rate_limit == 10


def test_the_swap_writes_one_prepared_batch_and_bumps_the_revision_once() -> None:
    manager = _manager(blocked_countries=["KP"])
    plan = _plan(manager, _rules(global_rate_limit=50, blocked_countries=["ru"]))
    revision = manager.config.revision
    manager._swap_config(plan)
    assert manager.config.revision == revision + 1
    assert manager.config.rate_limit == 50
    assert manager.config.blocked_countries == frozenset({"KP", "RU"})
    assert "rate_limit" in manager.config.model_fields_set


def test_geo_state_is_resolved_while_planning_not_while_swapping() -> None:
    manager = _manager(geo=False, ipinfo_token="token-for-test")
    plan = _plan(manager, _rules(blocked_countries=["ru"]))
    assert "geo_ip_handler" in plan.prepared
    assert manager.config.geo_ip_handler is None
    manager._swap_config(plan)
    assert manager.config.geo_ip_handler is plan.prepared["geo_ip_handler"]
