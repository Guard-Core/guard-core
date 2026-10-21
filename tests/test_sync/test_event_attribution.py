import ipaddress
import time
from collections.abc import Callable, Iterator
from datetime import datetime, timedelta, timezone
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from guard_core.models import DynamicRules, SecurityConfig
from guard_core.sync._utils import rule_attribution as rule_attribution_module
from guard_core.sync.core.checks.factory import build_default_pipeline
from guard_core.sync.core.checks.pipeline import SecurityCheckPipeline
from guard_core.sync.decorators import SecurityDecorator
from guard_core.sync.handlers.cloud_handler import cloud_handler
from guard_core.sync.handlers.dynamic_rule_handler import DynamicRuleManager
from guard_core.sync.handlers.ipban_handler import ip_ban_manager
from guard_core.sync.handlers.suspatterns_handler import sus_patterns_handler
from guard_core.sync.utils import detect_penetration_attempt
from tests.test_sync.conftest import SyncMockGuardRequest
from tests.test_sync.test_core.conftest import (
    build_middleware,
    build_route_pipeline,
    fixed_country_geo_ip,
    send_request,
)

RULE_ID = "rule-wp23"
RULE_IP = "198.51.100.21"
OTHER_IP = "198.51.100.22"
DYNAMIC = {"matched_rule_type": "dynamic", "matched_rule_id": RULE_ID}
DYNAMIC_OVERLAP = {**DYNAMIC, "matched_rule_overlaps_static": True}
SCRIPT_ATTACK = "<script>alert(1)</script>"


class _Agent:
    def __init__(self) -> None:
        self.events: list[Any] = []

    def send_event(self, event: Any) -> None:
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


def _apply(
    config: SecurityConfig, rules: DynamicRules, applied: bool = True
) -> DynamicRuleManager:
    ip_ban_manager.config = config
    manager = DynamicRuleManager(config)
    agent = MagicMock()
    agent.send_event = MagicMock()
    agent.get_dynamic_rules = MagicMock(return_value=rules)
    manager.agent_handler = agent
    manager.update_rules()
    assert (manager.current_rules is not None) is applied
    return manager


def _pipeline(
    config: SecurityConfig, geo: Any = None
) -> tuple[SecurityCheckPipeline, Any]:
    middleware = build_middleware(config, SecurityDecorator(config), geo)
    return build_default_pipeline(middleware), middleware


def _run(config: SecurityConfig, request: SyncMockGuardRequest, geo: Any = None) -> Any:
    pipeline, middleware = _pipeline(config, geo)
    pipeline.execute(request)
    return middleware


def _bus_events(middleware: Any, event_type: str) -> list[dict[str, Any]]:
    calls = middleware.event_bus.send_middleware_event.call_args_list
    return [call.kwargs for call in calls if call.kwargs["event_type"] == event_type]


def _attr(fields: Any) -> dict[str, Any]:
    return {key: value for key, value in fields.items() if key.startswith("matched_")}


def _request(
    ip: str = RULE_IP, path: str = "/x", **kwargs: Any
) -> SyncMockGuardRequest:
    return SyncMockGuardRequest(path=path, client_host=ip, **kwargs)


def _one(middleware: Any, event_type: str) -> dict[str, Any]:
    [event] = _bus_events(middleware, event_type)
    return event


def test_a_rule_ban_hit_carries_the_dynamic_attribution() -> None:
    config = _config()
    manager = _apply(config, _rules(ip_blacklist=[RULE_IP]))
    assert manager._owned_bans == [RULE_IP]

    middleware = _run(config, _request())

    event = _one(middleware, "ip_blocked")
    assert event["filter_type"] == "banned"
    assert _attr(event) == DYNAMIC


def test_a_ban_held_by_a_rule_cidr_carries_the_attribution() -> None:
    config = _config()
    _apply(config, _rules(ip_blacklist=["198.51.100.0/24"]))

    middleware = _run(config, _request(OTHER_IP))

    assert _attr(_one(middleware, "ip_blocked")) == DYNAMIC


def test_a_ban_also_in_the_static_blacklist_flags_the_overlap() -> None:
    config = _config(blacklist=(RULE_IP,))
    _apply(config, _rules(ip_blacklist=[RULE_IP]))

    middleware = _run(config, _request())

    assert _attr(_one(middleware, "ip_blocked")) == DYNAMIC_OVERLAP


def test_an_auto_ban_is_not_the_rules() -> None:
    config = _config()
    _apply(config, _rules(ip_blacklist=[RULE_IP]))
    assert ip_ban_manager.ban_ip(OTHER_IP, 3600, "penetration_attempt")

    middleware = _run(config, _request(OTHER_IP))

    event = _one(middleware, "ip_blocked")
    assert event["filter_type"] == "banned"
    assert _attr(event) == {}


def test_a_longer_foreign_ban_the_rule_did_not_take_over_is_not_the_rules() -> None:
    config = _config()
    ip_ban_manager.config = config
    assert ip_ban_manager.ban_ip(RULE_IP, 100_000, "operator")
    manager = _apply(config, _rules(ip_blacklist=[RULE_IP], ip_ban_duration=60))
    assert manager._owned_bans == []

    middleware = _run(config, _request())

    event = _one(middleware, "ip_blocked")
    assert event["filter_type"] == "banned"
    assert _attr(event) == {}


def test_a_blocked_country_carries_the_attribution_on_both_events() -> None:
    geo = fixed_country_geo_ip("CN")
    config = _config(geo_ip_handler=geo)
    _apply(config, _rules(blocked_countries=["CN"]))

    middleware = _run(config, _request(), geo)

    assert _attr(_one(middleware, "country_blocked")) == DYNAMIC
    assert _attr(_one(middleware, "ip_blocked")) == DYNAMIC


def test_a_country_also_blocked_statically_flags_the_overlap() -> None:
    geo = fixed_country_geo_ip("CN")
    config = _config(geo_ip_handler=geo, blocked_countries=["CN"])
    _apply(config, _rules(blocked_countries=["CN"]))

    middleware = _run(config, _request(), geo)

    assert _attr(_one(middleware, "country_blocked")) == DYNAMIC_OVERLAP


def test_a_country_blocked_by_the_static_list_alone_carries_nothing() -> None:
    geo = fixed_country_geo_ip("CN")
    config = _config(geo_ip_handler=geo, blocked_countries=["CN"])
    _apply(config, _rules(blocked_countries=["JP"]))

    middleware = _run(config, _request(), geo)

    assert _attr(_one(middleware, "country_blocked")) == {}
    assert _attr(_one(middleware, "ip_blocked")) == {}


def test_a_deny_under_the_rules_country_allow_list_carries_the_attribution() -> None:
    geo = fixed_country_geo_ip("CN")
    config = _config(geo_ip_handler=geo)
    _apply(config, _rules(whitelist_countries=["US"]))

    middleware = _run(config, _request(), geo)

    event = _one(middleware, "country_blocked")
    assert event["rule_type"] == "country_whitelist"
    assert _attr(event) == DYNAMIC


def test_a_deny_under_a_static_allow_list_is_not_the_rules() -> None:
    geo = fixed_country_geo_ip("CN")
    config = _config(geo_ip_handler=geo, whitelist_countries=["US"])
    _apply(config, _rules(blocked_user_agents=["otherbot"]))

    middleware = _run(config, _request(), geo)

    event = _one(middleware, "country_blocked")
    assert event["rule_type"] == "country_whitelist"
    assert _attr(event) == {}


def _aws_cloud() -> Any:
    return patch.multiple(
        cloud_handler,
        is_cloud_ip=MagicMock(return_value=True),
        get_cloud_provider_details=MagicMock(return_value=("AWS", "198.51.100.0/24")),
    )


def test_a_blocked_cloud_provider_carries_the_attribution() -> None:
    config = _config()
    _apply(config, _rules(blocked_cloud_providers={"AWS"}))

    with _aws_cloud():
        middleware = _run(config, _request())

    assert _attr(_one(middleware, "ip_blocked")) == DYNAMIC
    [call] = middleware.event_bus.send_cloud_detection_events.call_args_list
    assert _attr(call.kwargs["attribution"]) == DYNAMIC


def test_a_cloud_provider_also_blocked_statically_flags_the_overlap() -> None:
    config = _config(block_cloud_providers={"AWS"})
    _apply(config, _rules(blocked_cloud_providers={"AWS"}))

    with _aws_cloud():
        middleware = _run(config, _request())

    assert _attr(_one(middleware, "ip_blocked")) == DYNAMIC_OVERLAP


def test_a_cloud_provider_blocked_by_the_static_list_alone_carries_nothing() -> None:
    config = _config(block_cloud_providers={"AWS"})
    _apply(config, _rules(ip_ban_duration=30))

    with _aws_cloud():
        middleware = _run(config, _request())

    assert _attr(_one(middleware, "ip_blocked")) == {}


def test_a_blocked_user_agent_pattern_carries_the_attribution() -> None:
    config = _config()
    _apply(config, _rules(blocked_user_agents=["wp23bot"]))

    middleware = _run(config, _request(headers={"User-Agent": "wp23bot/1.0"}))

    assert _attr(_one(middleware, "user_agent_blocked")) == DYNAMIC


def test_a_user_agent_pattern_also_in_the_static_list_flags_the_overlap() -> None:
    config = _config(blocked_user_agents=["wp23bot"])
    _apply(config, _rules(blocked_user_agents=["wp23bot"]))

    middleware = _run(config, _request(headers={"User-Agent": "wp23bot/1.0"}))

    assert _attr(_one(middleware, "user_agent_blocked")) == DYNAMIC_OVERLAP


def test_a_static_user_agent_pattern_alone_carries_nothing() -> None:
    config = _config(blocked_user_agents=["wp23bot"])
    _apply(config, _rules(blocked_user_agents=["otherbot"]))

    middleware = _run(config, _request(headers={"User-Agent": "wp23bot/1.0"}))

    assert _attr(_one(middleware, "user_agent_blocked")) == {}


def _rate_limited_events(
    config: SecurityConfig, path: str = "/api"
) -> tuple[Any, list[Any]]:
    pipeline, middleware = _pipeline(config)
    agent = _Agent()
    middleware.rate_limit_handler.agent_handler = agent
    for _ in range(3):
        pipeline.execute(_request(path=path))
    return middleware, [e for e in agent.events if e.event_type == "rate_limited"]


def test_the_rules_global_rate_limit_carries_the_attribution() -> None:
    config = _config(enable_rate_limiting=True, rate_limit=100, rate_limit_window=60)
    _apply(config, _rules(global_rate_limit=1, global_rate_window=60))

    _, events = _rate_limited_events(config)

    assert events
    assert all(_attr(e.metadata) == DYNAMIC for e in events)


def test_a_global_rate_limit_equal_to_the_static_one_flags_the_overlap() -> None:
    config = _config(enable_rate_limiting=True, rate_limit=1, rate_limit_window=60)
    _apply(config, _rules(global_rate_limit=1, global_rate_window=60))

    _, events = _rate_limited_events(config)

    assert events
    assert all(_attr(e.metadata) == DYNAMIC_OVERLAP for e in events)


def test_a_static_global_rate_limit_alone_carries_nothing() -> None:
    config = _config(enable_rate_limiting=True, rate_limit=1, rate_limit_window=60)
    _apply(config, _rules(enable_ip_banning=False))

    _, events = _rate_limited_events(config)

    assert events
    assert all(_attr(e.metadata) == {} for e in events)


def test_a_rule_endpoint_limit_carries_the_attribution_on_both_events() -> None:
    config = _config()
    _apply(config, _rules(endpoint_rate_limits={"/api": (1, 60)}))

    middleware, events = _rate_limited_events(config)

    assert events
    assert all(_attr(e.metadata) == DYNAMIC for e in events)
    violations = _bus_events(middleware, "dynamic_rule_violation")
    assert violations
    assert all(_attr(v) == DYNAMIC for v in violations)


def test_an_endpoint_limit_also_in_the_static_config_flags_the_overlap() -> None:
    config = _config(endpoint_rate_limits={"/api": (1, 60)})
    _apply(config, _rules(endpoint_rate_limits={"/api": (1, 60)}))

    middleware, events = _rate_limited_events(config)

    assert events
    assert all(_attr(e.metadata) == DYNAMIC_OVERLAP for e in events)
    assert all(
        _attr(v) == DYNAMIC_OVERLAP
        for v in _bus_events(middleware, "dynamic_rule_violation")
    )


def test_an_endpoint_limit_of_the_static_config_alone_carries_nothing() -> None:
    config = _config(endpoint_rate_limits={"/api": (1, 60)})
    _apply(config, _rules(blocked_user_agents=["otherbot"]))

    middleware, events = _rate_limited_events(config)

    assert events
    assert all(_attr(e.metadata) == {} for e in events)
    assert all(
        _attr(v) == {} for v in _bus_events(middleware, "dynamic_rule_violation")
    )


def test_emergency_mode_set_by_the_rule_carries_the_attribution() -> None:
    config = _config()
    _apply(
        config,
        _rules(emergency_mode=True, emergency_whitelist=["198.51.100.99"]),
    )

    middleware = _run(config, _request())

    assert _attr(_one(middleware, "emergency_mode_block")) == DYNAMIC


def test_emergency_mode_already_static_flags_the_overlap() -> None:
    config = _config(emergency_mode=True, emergency_whitelist=["198.51.100.99"])
    _apply(
        config,
        _rules(emergency_mode=True, emergency_whitelist=["198.51.100.99"]),
    )

    middleware = _run(config, _request())

    assert _attr(_one(middleware, "emergency_mode_block")) == DYNAMIC_OVERLAP


def test_static_emergency_mode_alone_carries_nothing() -> None:
    config = _config(emergency_mode=True, emergency_whitelist=["198.51.100.99"])
    _apply(config, _rules(enable_ip_banning=False))

    middleware = _run(config, _request())

    assert _attr(_one(middleware, "emergency_mode_block")) == {}


def test_an_allow_decision_carries_nothing() -> None:
    config = _config()
    _apply(
        config,
        _rules(
            emergency_mode=True,
            emergency_whitelist=[RULE_IP],
            ip_whitelist=[OTHER_IP],
            emergency_whitelist_only=False,
        ),
    )

    allowed = _run(config, _request(OTHER_IP))
    admitted = _run(config, _request(RULE_IP))

    for middleware in (allowed, admitted):
        calls = middleware.event_bus.send_middleware_event.call_args_list
        assert [c for c in calls if _attr(c.kwargs)] == []
        assert _bus_events(middleware, "emergency_mode_block") == []


def test_a_toggle_or_threshold_never_attributes() -> None:
    config = _config(blacklist=(OTHER_IP,))
    _apply(
        config,
        _rules(enable_ip_banning=False, auto_ban_threshold=3, auto_ban_duration=60),
    )

    middleware = _run(config, _request(OTHER_IP))

    assert _attr(_one(middleware, "ip_blocked")) == {}


def test_a_set_that_expired_on_receipt_never_attributes() -> None:
    geo = fixed_country_geo_ip("CN")
    config = _config(geo_ip_handler=geo, blocked_countries=["CN"])
    manager = _apply(
        config,
        _rules(
            blocked_countries=["CN"],
            expires_at=datetime.now(timezone.utc) - timedelta(seconds=5),
        ),
        applied=False,
    )
    assert manager.current_rules is None

    middleware = _run(config, _request(), geo)

    assert _attr(_one(middleware, "country_blocked")) == {}


def test_a_set_that_expired_after_it_was_applied_stops_attributing() -> None:
    geo = fixed_country_geo_ip("CN")
    config = _config(geo_ip_handler=geo, blocked_countries=["CN"])
    manager = _apply(
        config,
        _rules(
            blocked_countries=["CN"],
            expires_at=datetime.now(timezone.utc) + timedelta(seconds=30),
        ),
    )
    before = _run(config, _request(), geo)
    assert _attr(_one(before, "country_blocked")) == DYNAMIC_OVERLAP
    assert manager.current_rules is not None
    manager.current_rules.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
    manager._check_rule_expiry()

    after = _run(config, _request(), geo)

    assert _attr(_one(after, "country_blocked")) == {}


def test_the_view_follows_the_set_that_is_applied() -> None:
    geo = fixed_country_geo_ip("CN")
    config = _config(geo_ip_handler=geo)
    manager = _apply(config, _rules(blocked_countries=["CN"]))
    first = _run(config, _request(), geo)
    assert _attr(_one(first, "country_blocked")) == DYNAMIC

    manager.agent_handler.get_dynamic_rules.return_value = _rules(
        rule_id="rule-two", version=2, blocked_countries=["CN"]
    )
    manager.update_rules()
    second = _run(config, _request(), geo)

    assert _attr(_one(second, "country_blocked")) == {
        "matched_rule_type": "dynamic",
        "matched_rule_id": "rule-two",
    }


def test_an_allowed_request_never_builds_the_view() -> None:
    config = _config()
    manager = _apply(config, _rules(ip_blacklist=[RULE_IP]))

    with patch.object(manager, "rule_attribution") as view:
        middleware = _run(config, _request(OTHER_IP))

    assert _bus_events(middleware, "ip_blocked") == []
    view.assert_not_called()


def _detection_config(**overrides: Any) -> SecurityConfig:
    return _config(enable_penetration_detection=True, **overrides)


def _detect(
    config: SecurityConfig, request: SyncMockGuardRequest
) -> tuple[Any, list[Any]]:
    pipeline, middleware = _pipeline(config)
    agent = _Agent()
    sus_patterns_handler.agent_handler = agent
    pipeline.execute(request)
    return middleware, [e for e in agent.events if e.event_type == "pattern_detected"]


def test_a_rule_pattern_detection_carries_the_attribution_on_both_events() -> None:
    pattern = r"wp23dyn[a-z]{3,6}"
    config = _detection_config()
    _apply(config, _rules(suspicious_patterns=[pattern]))

    middleware, detected = _detect(config, _request(path="/search?q=wp23dynabc"))

    penetration = _one(middleware, "penetration_attempt")
    [pattern_event] = detected
    assert _attr(penetration) == DYNAMIC
    assert _attr(pattern_event.metadata) == DYNAMIC


def test_a_known_pattern_a_rule_also_lists_flags_the_overlap() -> None:
    config = _detection_config()
    request = _request(path="/search", query_params={"q": SCRIPT_ATTACK})
    result = detect_penetration_attempt(request, config)
    assert result.matched_pattern_source is not None
    _apply(config, _rules(suspicious_patterns=[result.matched_pattern_source]))

    middleware, detected = _detect(
        config, _request(path="/search", query_params={"q": SCRIPT_ATTACK})
    )

    assert _attr(_one(middleware, "penetration_attempt")) == DYNAMIC_OVERLAP
    assert [_attr(e.metadata) for e in detected] == [DYNAMIC_OVERLAP]


def test_a_detection_by_a_pattern_the_rule_does_not_list_carries_nothing() -> None:
    config = _detection_config()
    _apply(config, _rules(suspicious_patterns=[r"wp23dyn[a-z]{3,6}"]))

    middleware, detected = _detect(
        config, _request(path="/search", query_params={"q": SCRIPT_ATTACK})
    )

    assert _attr(_one(middleware, "penetration_attempt")) == {}
    assert [_attr(e.metadata) for e in detected] == [{}]


def test_both_split_events_carry_one_id_the_category_and_the_endpoint() -> None:
    config = _detection_config()

    middleware, detected = _detect(
        config, _request(path="/search", query_params={"q": SCRIPT_ATTACK})
    )

    penetration = _one(middleware, "penetration_attempt")
    [pattern_event] = detected
    assert penetration["correlation_id"]
    assert penetration["correlation_id"] == pattern_event.metadata["correlation_id"]
    assert (
        penetration["threat_categories"] == pattern_event.metadata["threat_categories"]
    )
    assert penetration["category"] == pattern_event.metadata["category"] == "xss"
    assert pattern_event.endpoint == "/search"


def test_the_category_and_the_id_are_carried_in_passive_mode() -> None:
    config = _detection_config(passive_mode=True)

    middleware, detected = _detect(
        config, _request(path="/search", query_params={"q": SCRIPT_ATTACK})
    )

    penetration = _one(middleware, "penetration_attempt")
    [pattern_event] = detected
    assert penetration["action_taken"] == "logged_only"
    assert penetration["category"] == "xss"
    assert penetration["correlation_id"] == pattern_event.metadata["correlation_id"]


def test_the_pattern_event_endpoint_is_redacted_like_every_other_event() -> None:
    config = _detection_config()

    _, detected = _detect(
        config,
        _request(
            path="/search?token=hunter2&q=%3Cscript%3Ealert(1)%3C/script%3E",
        ),
    )

    [pattern_event] = detected
    assert pattern_event.endpoint is not None
    assert pattern_event.endpoint.startswith("/search")
    assert "hunter2" not in pattern_event.endpoint


def test_two_requests_from_one_ip_carry_two_ids() -> None:
    config = _detection_config(enable_ip_banning=False)
    pipeline, middleware = _pipeline(config)
    agent = _Agent()
    sus_patterns_handler.agent_handler = agent

    for path in ("/a", "/b"):
        pipeline.execute(_request(path=path, query_params={"q": SCRIPT_ATTACK}))

    penetrations = _bus_events(middleware, "penetration_attempt")
    detected = [e for e in agent.events if e.event_type == "pattern_detected"]
    ids = {event["correlation_id"] for event in penetrations}
    assert len(penetrations) == len(detected) == 2
    assert len(ids) == 2
    assert {e.metadata["correlation_id"] for e in detected} == ids


def test_a_direct_detect_call_has_no_endpoint() -> None:
    agent = _Agent()
    sus_patterns_handler.agent_handler = agent
    config = _detection_config()
    sus_patterns_handler.configure(config)

    sus_patterns_handler.detect(SCRIPT_ATTACK, RULE_IP, "request_body")

    [event] = [e for e in agent.events if e.event_type == "pattern_detected"]
    assert event.endpoint is None


def test_a_static_user_agent_block_without_any_rule_carries_nothing() -> None:
    config = _config(blocked_user_agents=["wp23bot"])

    middleware = _run(config, _request(headers={"User-Agent": "wp23bot/1.0"}))

    assert _attr(_one(middleware, "user_agent_blocked")) == {}


def _gcp_ranges() -> Any:
    central = ipaddress.ip_network("34.100.0.0/24")
    europe = ipaddress.ip_network("35.200.0.0/24")
    return patch.multiple(
        cloud_handler,
        ip_ranges={"GCP": {central, europe}},
        network_regions={
            "GCP": {str(central): "us-central1", str(europe): "europe-west1"}
        },
    )


CENTRAL_IP = "34.100.0.5"
EUROPE_IP = "35.200.0.5"


def _gcp_events(static: set[str], rule: set[str], ip: str) -> Any:
    config = _config(block_cloud_providers=static or None)
    _apply(config, _rules(blocked_cloud_providers=rule))
    with _gcp_ranges():
        middleware = _run(config, _request(ip))
    return _bus_events(middleware, "ip_blocked")


def test_a_rule_carve_out_still_stamps_the_regions_it_blocks() -> None:
    [event] = _gcp_events(set(), {"GCP:!us-central1"}, EUROPE_IP)

    assert _attr(event) == DYNAMIC


def test_a_rule_carve_out_region_is_not_blocked_and_not_stamped() -> None:
    assert _gcp_events(set(), {"GCP:!us-central1"}, CENTRAL_IP) == []


def test_a_rule_block_with_a_static_carve_out_stamps_the_overlap_elsewhere() -> None:
    [event] = _gcp_events({"GCP:!us-central1"}, {"GCP"}, EUROPE_IP)

    assert _attr(event) == DYNAMIC_OVERLAP


def test_a_rule_block_wins_over_a_static_carve_out_of_the_same_region() -> None:
    [event] = _gcp_events({"GCP:!us-central1"}, {"GCP"}, CENTRAL_IP)

    assert _attr(event) == DYNAMIC


def test_a_static_block_wins_over_a_rule_carve_out_of_the_same_region() -> None:
    [event] = _gcp_events({"GCP"}, {"GCP:!us-central1"}, CENTRAL_IP)

    assert _attr(event) == {}


def test_a_region_both_sources_carve_out_stays_free() -> None:
    assert _gcp_events({"GCP:!us-central1"}, {"GCP:!us-central1"}, CENTRAL_IP) == []


def _route_blocks(selector: str) -> Callable[[SecurityDecorator], Any]:
    def apply(decorator: SecurityDecorator) -> Any:
        return decorator.block_clouds([selector])

    return apply


def test_a_route_block_wins_over_a_global_carve_out_and_back() -> None:
    for global_selector, route_selector in (
        ("GCP:!us-central1", "GCP"),
        ("GCP", "GCP:!us-central1"),
    ):
        config = _config(enable_dynamic_rules=False, enable_agent=False)
        config.block_cloud_providers = frozenset({global_selector})
        pipeline, _, route_id = build_route_pipeline(
            config, _route_blocks(route_selector)
        )
        with _gcp_ranges():
            response = send_request(pipeline, route_id, ip=CENTRAL_IP)

        assert response is not None and response.status_code == 403


def test_a_provider_only_the_static_list_blocks_is_not_the_rules() -> None:
    [event] = _gcp_events({"GCP"}, {"AWS"}, CENTRAL_IP)

    assert _attr(event) == {}


def test_an_auto_ban_after_the_rules_own_ban_expired_is_not_the_rules() -> None:
    config = _config()
    _apply(config, _rules(ip_blacklist=[RULE_IP], ip_ban_duration=1))
    first = _run(config, _request())
    assert _attr(_one(first, "ip_blocked")) == DYNAMIC
    time.sleep(1.3)
    assert ip_ban_manager.ban_ip(RULE_IP, 3600, "penetration_attempt")

    middleware = _run(config, _request())

    event = _one(middleware, "ip_blocked")
    assert event["filter_type"] == "banned"
    assert _attr(event) == {}


def test_an_operator_ban_inside_a_rule_cidr_is_the_deciding_entry() -> None:
    config = _config()
    _apply(config, _rules(ip_blacklist=["198.51.100.0/24"]))
    assert ip_ban_manager.ban_ip(OTHER_IP, 3600, "operator")

    operator = _run(config, _request(OTHER_IP))
    neighbour = _run(config, _request("198.51.100.30"))

    assert _attr(_one(operator, "ip_blocked")) == {}
    assert _attr(_one(neighbour, "ip_blocked")) == DYNAMIC


def test_a_longer_foreign_ban_written_over_the_rules_is_not_the_rules() -> None:
    config = _config()
    _apply(config, _rules(ip_blacklist=[RULE_IP], ip_ban_duration=60))
    assert ip_ban_manager.ban_ip(RULE_IP, 100_000, "operator")

    middleware = _run(config, _request())

    assert _attr(_one(middleware, "ip_blocked")) == {}


def test_the_view_is_built_when_the_set_changes_not_on_the_first_block() -> None:
    config = _config()
    manager = _apply(config, _rules(ip_blacklist=[RULE_IP]))

    cached = manager._attribution_cache
    assert cached is not None
    assert cached[0][0] is manager.current_rules
    assert manager.rule_attribution() is cached[1]

    manager.agent_handler.get_dynamic_rules.return_value = _rules(
        rule_id="rule-two", version=2, ip_blacklist=[OTHER_IP]
    )
    manager.update_rules()
    rebuilt = manager._attribution_cache
    assert rebuilt is not None and rebuilt[1] is not cached[1]
    assert rebuilt[1].rule_id == "rule-two"
    assert rebuilt[1].owned_ban_members == frozenset({f"banned_ips:{OTHER_IP}"})

    assert manager.current_rules is not None
    manager.current_rules.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
    manager._check_rule_expiry()
    assert manager._attribution_cache is None


class _MustNotBeRead:
    """A view that fails the test when anything reads it."""

    def __getattr__(self, name: str) -> Any:
        raise AssertionError(f"the attribution view was read ({name}) with no consumer")


def _real_bus(config: SecurityConfig, middleware: Any, agent: Any) -> None:
    from guard_core.sync.core.events.middleware_events import SecurityEventBus

    middleware.event_bus = SecurityEventBus(agent, config)


def _blocked_without_a_consumer(
    config: SecurityConfig, request: SyncMockGuardRequest, geo: Any = None
) -> Any:
    pipeline, middleware = _pipeline(config, geo)
    _real_bus(config, middleware, None)
    return pipeline.execute(request)


def test_a_blocked_request_with_no_event_consumer_never_reads_the_view(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    geo = fixed_country_geo_ip("CN")
    config = _config(
        geo_ip_handler=geo,
        blocked_user_agents=["wp23bot"],
        blocked_countries=["CN"],
        agent_enable_events=True,
    )
    _apply(
        config,
        _rules(
            ip_blacklist=[RULE_IP],
            blocked_user_agents=["rulebot"],
            blocked_countries=["CN"],
            suspicious_patterns=["wp23dyn[a-z]{3,6}"],
        ),
    )
    monkeypatch.setattr(rule_attribution_module, "_applied", _MustNotBeRead())
    config.agent_enable_events = True

    banned = _blocked_without_a_consumer(config, _request(RULE_IP), geo)
    other = _blocked_without_a_consumer(
        config, _request(OTHER_IP, headers={"User-Agent": "wp23bot/1.0"}), geo
    )

    assert banned is not None and banned.status_code == 403
    assert other is not None and other.status_code == 403


def test_a_blocked_request_with_a_consumer_still_reads_the_view() -> None:
    config = _config()
    _apply(config, _rules(ip_blacklist=[RULE_IP]))
    agent = _Agent()
    pipeline, middleware = _pipeline(config)
    _real_bus(config, middleware, agent)

    pipeline.execute(_request(RULE_IP))

    [event] = [e for e in agent.events if e.event_type == "ip_blocked"]
    assert _attr(event.metadata) == DYNAMIC
