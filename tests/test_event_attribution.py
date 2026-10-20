from collections.abc import Iterator
from datetime import datetime, timedelta, timezone
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from guard_core.core.checks.factory import build_default_pipeline
from guard_core.core.checks.pipeline import SecurityCheckPipeline
from guard_core.decorators import SecurityDecorator
from guard_core.handlers.cloud_handler import cloud_handler
from guard_core.handlers.dynamic_rule_handler import DynamicRuleManager
from guard_core.handlers.ipban_handler import ip_ban_manager
from guard_core.handlers.suspatterns_handler import sus_patterns_handler
from guard_core.models import DynamicRules, SecurityConfig
from guard_core.utils import detect_penetration_attempt
from tests.conftest import MockGuardRequest
from tests.test_core.conftest import build_middleware, fixed_country_geo_ip

RULE_ID = "rule-wp23"
RULE_IP = "198.51.100.21"
OTHER_IP = "198.51.100.22"
DYNAMIC = {"matched_rule_type": "dynamic", "matched_rule_id": RULE_ID}
DYNAMIC_OVERLAP = {**DYNAMIC, "matched_rule_overlaps_static": True}
SCRIPT_ATTACK = "<script>alert(1)</script>"


class _Agent:
    def __init__(self) -> None:
        self.events: list[Any] = []

    async def send_event(self, event: Any) -> None:
        self.events.append(event)


@pytest.fixture(autouse=True)
def reset_singleton() -> Iterator[None]:
    DynamicRuleManager._instance = None
    yield
    DynamicRuleManager._instance = None


def _config(**overrides: Any) -> SecurityConfig:
    fields: dict[str, Any] = {
        "enable_redis": False,
        "enable_agent": True,
        "agent_api_key": "test-api-key",
        "enable_dynamic_rules": True,
        "enable_penetration_detection": False,
        "enable_rate_limiting": False,
    }
    fields.update(overrides)
    return SecurityConfig(**fields)


def _rules(**overrides: Any) -> DynamicRules:
    fields: dict[str, Any] = {
        "rule_id": RULE_ID,
        "version": 1,
        "timestamp": datetime.now(timezone.utc),
    }
    fields.update(overrides)
    return DynamicRules(**fields)


async def _apply(config: SecurityConfig, rules: DynamicRules) -> DynamicRuleManager:
    ip_ban_manager.config = config
    manager = DynamicRuleManager(config)
    agent = MagicMock()
    agent.send_event = AsyncMock()
    agent.get_dynamic_rules = AsyncMock(return_value=rules)
    manager.agent_handler = agent
    await manager.update_rules()
    return manager


def _pipeline(
    config: SecurityConfig, geo: Any = None
) -> tuple[SecurityCheckPipeline, Any]:
    middleware = build_middleware(config, SecurityDecorator(config), geo)
    return build_default_pipeline(middleware), middleware


async def _run(
    config: SecurityConfig, request: MockGuardRequest, geo: Any = None
) -> Any:
    pipeline, middleware = _pipeline(config, geo)
    await pipeline.execute(request)
    return middleware


def _bus_events(middleware: Any, event_type: str) -> list[dict[str, Any]]:
    calls = middleware.event_bus.send_middleware_event.call_args_list
    return [call.kwargs for call in calls if call.kwargs["event_type"] == event_type]


def _attr(fields: Any) -> dict[str, Any]:
    return {key: value for key, value in fields.items() if key.startswith("matched_")}


def _request(ip: str = RULE_IP, path: str = "/x", **kwargs: Any) -> MockGuardRequest:
    return MockGuardRequest(path=path, client_host=ip, **kwargs)


async def _one(middleware: Any, event_type: str) -> dict[str, Any]:
    [event] = _bus_events(middleware, event_type)
    return event


async def test_a_rule_ban_hit_carries_the_dynamic_attribution() -> None:
    config = _config()
    manager = await _apply(config, _rules(ip_blacklist=[RULE_IP]))
    assert manager._owned_bans == [RULE_IP]

    middleware = await _run(config, _request())

    event = await _one(middleware, "ip_blocked")
    assert event["filter_type"] == "banned"
    assert _attr(event) == DYNAMIC


async def test_a_ban_held_by_a_rule_cidr_carries_the_attribution() -> None:
    config = _config()
    await _apply(config, _rules(ip_blacklist=["198.51.100.0/24"]))

    middleware = await _run(config, _request(OTHER_IP))

    assert _attr(await _one(middleware, "ip_blocked")) == DYNAMIC


async def test_a_ban_also_in_the_static_blacklist_flags_the_overlap() -> None:
    config = _config(blacklist=(RULE_IP,))
    await _apply(config, _rules(ip_blacklist=[RULE_IP]))

    middleware = await _run(config, _request())

    assert _attr(await _one(middleware, "ip_blocked")) == DYNAMIC_OVERLAP


async def test_an_auto_ban_is_not_the_rules() -> None:
    config = _config()
    await _apply(config, _rules(ip_blacklist=[RULE_IP]))
    assert await ip_ban_manager.ban_ip(OTHER_IP, 3600, "penetration_attempt")

    middleware = await _run(config, _request(OTHER_IP))

    event = await _one(middleware, "ip_blocked")
    assert event["filter_type"] == "banned"
    assert _attr(event) == {}


async def test_a_longer_foreign_ban_the_rule_did_not_take_over_is_not_the_rules() -> (
    None
):
    config = _config()
    ip_ban_manager.config = config
    assert await ip_ban_manager.ban_ip(RULE_IP, 100_000, "operator")
    manager = await _apply(config, _rules(ip_blacklist=[RULE_IP], ip_ban_duration=60))
    assert manager._owned_bans == []

    middleware = await _run(config, _request())

    event = await _one(middleware, "ip_blocked")
    assert event["filter_type"] == "banned"
    assert _attr(event) == {}


async def test_a_blocked_country_carries_the_attribution_on_both_events() -> None:
    geo = fixed_country_geo_ip("CN")
    config = _config(geo_ip_handler=geo)
    await _apply(config, _rules(blocked_countries=["CN"]))

    middleware = await _run(config, _request(), geo)

    assert _attr(await _one(middleware, "country_blocked")) == DYNAMIC
    assert _attr(await _one(middleware, "ip_blocked")) == DYNAMIC


async def test_a_country_also_blocked_statically_flags_the_overlap() -> None:
    geo = fixed_country_geo_ip("CN")
    config = _config(geo_ip_handler=geo, blocked_countries=["CN"])
    await _apply(config, _rules(blocked_countries=["CN"]))

    middleware = await _run(config, _request(), geo)

    assert _attr(await _one(middleware, "country_blocked")) == DYNAMIC_OVERLAP


async def test_a_country_blocked_by_the_static_list_alone_carries_nothing() -> None:
    geo = fixed_country_geo_ip("CN")
    config = _config(geo_ip_handler=geo, blocked_countries=["CN"])
    await _apply(config, _rules(blocked_countries=["JP"]))

    middleware = await _run(config, _request(), geo)

    assert _attr(await _one(middleware, "country_blocked")) == {}
    assert _attr(await _one(middleware, "ip_blocked")) == {}


async def test_a_deny_under_the_rules_country_allow_list_carries_the_attribution() -> (
    None
):
    geo = fixed_country_geo_ip("CN")
    config = _config(geo_ip_handler=geo)
    await _apply(config, _rules(whitelist_countries=["US"]))

    middleware = await _run(config, _request(), geo)

    event = await _one(middleware, "country_blocked")
    assert event["rule_type"] == "country_whitelist"
    assert _attr(event) == DYNAMIC


async def test_a_deny_under_a_static_allow_list_is_not_the_rules() -> None:
    geo = fixed_country_geo_ip("CN")
    config = _config(geo_ip_handler=geo, whitelist_countries=["US"])
    await _apply(config, _rules(blocked_countries=["JP"]))

    middleware = await _run(config, _request(), geo)

    event = await _one(middleware, "country_blocked")
    assert event["rule_type"] == "country_whitelist"
    assert _attr(event) == {}


def _aws_cloud() -> Any:
    return patch.multiple(
        cloud_handler,
        is_cloud_ip=MagicMock(return_value=True),
        get_cloud_provider_details=MagicMock(return_value=("AWS", "198.51.100.0/24")),
    )


async def test_a_blocked_cloud_provider_carries_the_attribution() -> None:
    config = _config()
    await _apply(config, _rules(blocked_cloud_providers={"AWS"}))

    with _aws_cloud():
        middleware = await _run(config, _request())

    assert _attr(await _one(middleware, "ip_blocked")) == DYNAMIC
    [call] = middleware.event_bus.send_cloud_detection_events.call_args_list
    assert _attr(call.kwargs["attribution"]) == DYNAMIC


async def test_a_cloud_provider_also_blocked_statically_flags_the_overlap() -> None:
    config = _config(block_cloud_providers={"AWS"})
    await _apply(config, _rules(blocked_cloud_providers={"AWS"}))

    with _aws_cloud():
        middleware = await _run(config, _request())

    assert _attr(await _one(middleware, "ip_blocked")) == DYNAMIC_OVERLAP


async def test_a_cloud_provider_blocked_by_the_static_list_alone_carries_nothing() -> (
    None
):
    config = _config(block_cloud_providers={"AWS"})
    await _apply(config, _rules(ip_ban_duration=30))

    with _aws_cloud():
        middleware = await _run(config, _request())

    assert _attr(await _one(middleware, "ip_blocked")) == {}


async def test_a_blocked_user_agent_pattern_carries_the_attribution() -> None:
    config = _config()
    await _apply(config, _rules(blocked_user_agents=["wp23bot"]))

    middleware = await _run(config, _request(headers={"User-Agent": "wp23bot/1.0"}))

    assert _attr(await _one(middleware, "user_agent_blocked")) == DYNAMIC


async def test_a_user_agent_pattern_also_in_the_static_list_flags_the_overlap() -> None:
    config = _config(blocked_user_agents=["wp23bot"])
    await _apply(config, _rules(blocked_user_agents=["wp23bot"]))

    middleware = await _run(config, _request(headers={"User-Agent": "wp23bot/1.0"}))

    assert _attr(await _one(middleware, "user_agent_blocked")) == DYNAMIC_OVERLAP


async def test_a_static_user_agent_pattern_alone_carries_nothing() -> None:
    config = _config(blocked_user_agents=["wp23bot"])
    await _apply(config, _rules(blocked_user_agents=["otherbot"]))

    middleware = await _run(config, _request(headers={"User-Agent": "wp23bot/1.0"}))

    assert _attr(await _one(middleware, "user_agent_blocked")) == {}


async def _rate_limited_events(
    config: SecurityConfig, path: str = "/api"
) -> tuple[Any, list[Any]]:
    pipeline, middleware = _pipeline(config)
    agent = _Agent()
    middleware.rate_limit_handler.agent_handler = agent
    for _ in range(3):
        await pipeline.execute(_request(path=path))
    return middleware, [e for e in agent.events if e.event_type == "rate_limited"]


async def test_the_rules_global_rate_limit_carries_the_attribution() -> None:
    config = _config(enable_rate_limiting=True, rate_limit=100, rate_limit_window=60)
    await _apply(config, _rules(global_rate_limit=1, global_rate_window=60))

    _, events = await _rate_limited_events(config)

    assert events
    assert all(_attr(e.metadata) == DYNAMIC for e in events)


async def test_a_global_rate_limit_equal_to_the_static_one_flags_the_overlap() -> None:
    config = _config(enable_rate_limiting=True, rate_limit=1, rate_limit_window=60)
    await _apply(config, _rules(global_rate_limit=1, global_rate_window=60))

    _, events = await _rate_limited_events(config)

    assert events
    assert all(_attr(e.metadata) == DYNAMIC_OVERLAP for e in events)


async def test_a_static_global_rate_limit_alone_carries_nothing() -> None:
    config = _config(enable_rate_limiting=True, rate_limit=1, rate_limit_window=60)
    await _apply(config, _rules(enable_ip_banning=False))

    _, events = await _rate_limited_events(config)

    assert events
    assert all(_attr(e.metadata) == {} for e in events)


async def test_a_rule_endpoint_limit_carries_the_attribution_on_both_events() -> None:
    config = _config()
    await _apply(config, _rules(endpoint_rate_limits={"/api": (1, 60)}))

    middleware, events = await _rate_limited_events(config)

    assert events
    assert all(_attr(e.metadata) == DYNAMIC for e in events)
    violations = _bus_events(middleware, "dynamic_rule_violation")
    assert violations
    assert all(_attr(v) == DYNAMIC for v in violations)


async def test_an_endpoint_limit_also_in_the_static_config_flags_the_overlap() -> None:
    config = _config(endpoint_rate_limits={"/api": (1, 60)})
    await _apply(config, _rules(endpoint_rate_limits={"/api": (1, 60)}))

    middleware, events = await _rate_limited_events(config)

    assert events
    assert all(_attr(e.metadata) == DYNAMIC_OVERLAP for e in events)
    assert all(
        _attr(v) == DYNAMIC_OVERLAP
        for v in _bus_events(middleware, "dynamic_rule_violation")
    )


async def test_an_endpoint_limit_of_the_static_config_alone_carries_nothing() -> None:
    config = _config(endpoint_rate_limits={"/api": (1, 60)})
    await _apply(config, _rules(blocked_user_agents=["otherbot"]))

    middleware, events = await _rate_limited_events(config)

    assert events
    assert all(_attr(e.metadata) == {} for e in events)
    assert all(
        _attr(v) == {} for v in _bus_events(middleware, "dynamic_rule_violation")
    )


async def test_emergency_mode_set_by_the_rule_carries_the_attribution() -> None:
    config = _config()
    await _apply(
        config,
        _rules(emergency_mode=True, emergency_whitelist=["198.51.100.99"]),
    )

    middleware = await _run(config, _request())

    assert _attr(await _one(middleware, "emergency_mode_block")) == DYNAMIC


async def test_emergency_mode_already_static_flags_the_overlap() -> None:
    config = _config(emergency_mode=True, emergency_whitelist=["198.51.100.99"])
    await _apply(
        config,
        _rules(emergency_mode=True, emergency_whitelist=["198.51.100.99"]),
    )

    middleware = await _run(config, _request())

    assert _attr(await _one(middleware, "emergency_mode_block")) == DYNAMIC_OVERLAP


async def test_static_emergency_mode_alone_carries_nothing() -> None:
    config = _config(emergency_mode=True, emergency_whitelist=["198.51.100.99"])
    await _apply(config, _rules(enable_ip_banning=False))

    middleware = await _run(config, _request())

    assert _attr(await _one(middleware, "emergency_mode_block")) == {}


async def test_an_allow_decision_carries_nothing() -> None:
    config = _config()
    await _apply(
        config,
        _rules(
            emergency_mode=True,
            emergency_whitelist=[RULE_IP],
            ip_whitelist=[OTHER_IP],
            emergency_whitelist_only=False,
        ),
    )

    allowed = await _run(config, _request(OTHER_IP))
    admitted = await _run(config, _request(RULE_IP))

    for middleware in (allowed, admitted):
        calls = middleware.event_bus.send_middleware_event.call_args_list
        assert [c for c in calls if _attr(c.kwargs)] == []
        assert _bus_events(middleware, "emergency_mode_block") == []


async def test_a_toggle_or_threshold_never_attributes() -> None:
    config = _config(blacklist=(OTHER_IP,))
    await _apply(
        config,
        _rules(enable_ip_banning=False, auto_ban_threshold=3, auto_ban_duration=60),
    )

    middleware = await _run(config, _request(OTHER_IP))

    assert _attr(await _one(middleware, "ip_blocked")) == {}


async def test_a_set_that_expired_on_receipt_never_attributes() -> None:
    geo = fixed_country_geo_ip("CN")
    config = _config(geo_ip_handler=geo, blocked_countries=["CN"])
    manager = await _apply(
        config,
        _rules(
            blocked_countries=["CN"],
            expires_at=datetime.now(timezone.utc) - timedelta(seconds=5),
        ),
    )
    assert manager.current_rules is None

    middleware = await _run(config, _request(), geo)

    assert _attr(await _one(middleware, "country_blocked")) == {}


async def test_a_set_that_expired_after_it_was_applied_stops_attributing() -> None:
    geo = fixed_country_geo_ip("CN")
    config = _config(geo_ip_handler=geo, blocked_countries=["CN"])
    manager = await _apply(
        config,
        _rules(
            blocked_countries=["CN"],
            expires_at=datetime.now(timezone.utc) + timedelta(seconds=30),
        ),
    )
    before = await _run(config, _request(), geo)
    assert _attr(await _one(before, "country_blocked")) == DYNAMIC_OVERLAP
    assert manager.current_rules is not None
    manager.current_rules.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
    await manager._check_rule_expiry()

    after = await _run(config, _request(), geo)

    assert _attr(await _one(after, "country_blocked")) == {}


async def test_the_view_follows_the_set_that_is_applied() -> None:
    geo = fixed_country_geo_ip("CN")
    config = _config(geo_ip_handler=geo)
    manager = await _apply(config, _rules(blocked_countries=["CN"]))
    first = await _run(config, _request(), geo)
    assert _attr(await _one(first, "country_blocked")) == DYNAMIC

    manager.agent_handler.get_dynamic_rules.return_value = _rules(
        rule_id="rule-two", version=2, blocked_countries=["CN"]
    )
    await manager.update_rules()
    second = await _run(config, _request(), geo)

    assert _attr(await _one(second, "country_blocked")) == {
        "matched_rule_type": "dynamic",
        "matched_rule_id": "rule-two",
    }


async def test_an_allowed_request_never_builds_the_view() -> None:
    config = _config()
    manager = await _apply(config, _rules(ip_blacklist=[RULE_IP]))

    with patch.object(manager, "rule_attribution") as view:
        middleware = await _run(config, _request(OTHER_IP))

    assert _bus_events(middleware, "ip_blocked") == []
    view.assert_not_called()


def _detection_config(**overrides: Any) -> SecurityConfig:
    return _config(enable_penetration_detection=True, **overrides)


async def _detect(
    config: SecurityConfig, request: MockGuardRequest
) -> tuple[Any, list[Any]]:
    pipeline, middleware = _pipeline(config)
    agent = _Agent()
    sus_patterns_handler.agent_handler = agent
    await pipeline.execute(request)
    return middleware, [e for e in agent.events if e.event_type == "pattern_detected"]


async def test_a_rule_pattern_detection_carries_the_attribution_on_both_events() -> (
    None
):
    pattern = r"wp23dyn[a-z]{3,6}"
    config = _detection_config()
    await _apply(config, _rules(suspicious_patterns=[pattern]))

    middleware, detected = await _detect(config, _request(path="/search?q=wp23dynabc"))

    penetration = await _one(middleware, "penetration_attempt")
    [pattern_event] = detected
    assert _attr(penetration) == DYNAMIC
    assert _attr(pattern_event.metadata) == DYNAMIC


async def test_a_known_pattern_a_rule_also_lists_flags_the_overlap() -> None:
    config = _detection_config()
    request = _request(path="/search", query_params={"q": SCRIPT_ATTACK})
    result = await detect_penetration_attempt(request, config)
    assert result.matched_pattern_source is not None
    await _apply(config, _rules(suspicious_patterns=[result.matched_pattern_source]))

    middleware, detected = await _detect(
        config, _request(path="/search", query_params={"q": SCRIPT_ATTACK})
    )

    assert _attr(await _one(middleware, "penetration_attempt")) == DYNAMIC_OVERLAP
    assert [_attr(e.metadata) for e in detected] == [DYNAMIC_OVERLAP]


async def test_a_detection_by_a_pattern_the_rule_does_not_list_carries_nothing() -> (
    None
):
    config = _detection_config()
    await _apply(config, _rules(suspicious_patterns=[r"wp23dyn[a-z]{3,6}"]))

    middleware, detected = await _detect(
        config, _request(path="/search", query_params={"q": SCRIPT_ATTACK})
    )

    assert _attr(await _one(middleware, "penetration_attempt")) == {}
    assert [_attr(e.metadata) for e in detected] == [{}]


async def test_both_split_events_carry_one_id_the_category_and_the_endpoint() -> None:
    config = _detection_config()

    middleware, detected = await _detect(
        config, _request(path="/search", query_params={"q": SCRIPT_ATTACK})
    )

    penetration = await _one(middleware, "penetration_attempt")
    [pattern_event] = detected
    assert penetration["correlation_id"]
    assert penetration["correlation_id"] == pattern_event.metadata["correlation_id"]
    assert (
        penetration["threat_categories"] == pattern_event.metadata["threat_categories"]
    )
    assert penetration["category"] == pattern_event.metadata["category"] == "xss"
    assert pattern_event.endpoint == "/search"


async def test_the_category_and_the_id_are_carried_in_passive_mode() -> None:
    config = _detection_config(passive_mode=True)

    middleware, detected = await _detect(
        config, _request(path="/search", query_params={"q": SCRIPT_ATTACK})
    )

    penetration = await _one(middleware, "penetration_attempt")
    [pattern_event] = detected
    assert penetration["action_taken"] == "logged_only"
    assert penetration["category"] == "xss"
    assert penetration["correlation_id"] == pattern_event.metadata["correlation_id"]


async def test_the_pattern_event_endpoint_is_redacted_like_every_other_event() -> None:
    config = _detection_config()

    _, detected = await _detect(
        config,
        _request(
            path="/search?token=hunter2&q=%3Cscript%3Ealert(1)%3C/script%3E",
        ),
    )

    [pattern_event] = detected
    assert pattern_event.endpoint is not None
    assert pattern_event.endpoint.startswith("/search")
    assert "hunter2" not in pattern_event.endpoint


async def test_two_requests_from_one_ip_carry_two_ids() -> None:
    config = _detection_config(enable_ip_banning=False)
    pipeline, middleware = _pipeline(config)
    agent = _Agent()
    sus_patterns_handler.agent_handler = agent

    for path in ("/a", "/b"):
        await pipeline.execute(_request(path=path, query_params={"q": SCRIPT_ATTACK}))

    penetrations = _bus_events(middleware, "penetration_attempt")
    detected = [e for e in agent.events if e.event_type == "pattern_detected"]
    ids = {event["correlation_id"] for event in penetrations}
    assert len(penetrations) == len(detected) == 2
    assert len(ids) == 2
    assert {e.metadata["correlation_id"] for e in detected} == ids


async def test_a_direct_detect_call_has_no_endpoint() -> None:
    agent = _Agent()
    sus_patterns_handler.agent_handler = agent
    config = _detection_config()
    sus_patterns_handler.configure(config)

    await sus_patterns_handler.detect(SCRIPT_ATTACK, RULE_IP, "request_body")

    [event] = [e for e in agent.events if e.event_type == "pattern_detected"]
    assert event.endpoint is None
