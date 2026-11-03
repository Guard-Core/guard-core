from typing import Any

from guard_core.models import SyncSecurityConfig
from guard_core.sync.core.checks.factory import build_default_pipeline
from guard_core.sync.decorators import SecurityDecorator
from tests.test_sync.conftest import SyncMockGuardRequest
from tests.test_sync.test_core.conftest import build_middleware, fixed_country_geo_ip


def _events(**rules: object) -> list[dict[str, Any]]:
    geo = fixed_country_geo_ip("CN")
    config = SyncSecurityConfig(
        enable_redis=False,
        enable_penetration_detection=False,
        enable_rate_limiting=False,
        geo_ip_handler=geo,
        **rules,
    )
    middleware = build_middleware(config, SecurityDecorator(config), geo)
    request = SyncMockGuardRequest(path="/x", client_host="203.0.113.5")
    response = build_default_pipeline(middleware).execute(request)
    assert response is not None and response.status_code == 403
    calls = middleware.event_bus.send_middleware_event.call_args_list
    return [{"event_type": call.kwargs["event_type"], **call.kwargs} for call in calls]


def _of_type(events: list[dict[str, Any]], event_type: str) -> list[dict[str, Any]]:
    return [event for event in events if event["event_type"] == event_type]


def test_a_blocked_country_emits_country_blocked_with_country_and_rule() -> None:
    events = _events(blocked_countries=["CN"])

    [event] = _of_type(events, "country_blocked")
    assert event["country"] == "CN"
    assert event["rule_type"] == "country_blacklist"
    assert event["action_taken"] == "request_blocked"
    assert event["ip_address"] == "203.0.113.5"


def test_a_country_outside_the_allow_list_names_the_allow_list_rule() -> None:
    events = _events(whitelist_countries=["US"])

    [event] = _of_type(events, "country_blocked")
    assert event["country"] == "CN"
    assert event["rule_type"] == "country_whitelist"


def test_ip_blocked_stays_and_now_carries_the_country() -> None:
    events = _events(blocked_countries=["CN"])

    [event] = _of_type(events, "ip_blocked")
    assert event["filter_type"] == "global"
    assert event["country"] == "CN"


def test_a_list_denial_emits_no_country_blocked() -> None:
    events = _events(blacklist=["203.0.113.5"])

    assert _of_type(events, "country_blocked") == []
