from datetime import datetime, timedelta, timezone
from typing import Any
from unittest.mock import Mock
from zoneinfo import ZoneInfo

import pytest

from guard_core.core.checks.implementations import (
    time_window as time_window_check_module,
)
from guard_core.core.checks.implementations.time_window import TimeWindowCheck
from guard_core.core.validation import validator as validator_module
from guard_core.core.validation.context import ValidationContext
from guard_core.core.validation.validator import RequestValidator
from guard_core.decorators import SecurityDecorator
from guard_core.models import SecurityConfig
from guard_core.utils import is_user_agent_allowed
from tests.test_core.conftest import (
    build_middleware,
    build_route_pipeline,
    send_request,
)


def _config(**settings: Any) -> SecurityConfig:
    return SecurityConfig(
        enable_redis=False,
        enable_penetration_detection=False,
        enable_rate_limiting=False,
        **settings,
    )


async def test_global_https_applies_to_a_route_with_only_a_rate_limit() -> None:
    config = _config(enforce_https=True)
    pipeline, _, route_id = build_route_pipeline(config, lambda d: d.rate_limit(50, 60))

    decorated = await send_request(pipeline, route_id, ip="203.0.113.5", scheme="http")
    plain = await send_request(pipeline, "", ip="203.0.113.5", scheme="http")

    assert plain is not None and plain.status_code == 301
    assert decorated is not None
    assert decorated.status_code == plain.status_code


async def test_route_require_https_still_forces_https_with_the_global_setting_off() -> (
    None
):
    config = _config(enforce_https=False)
    pipeline, _, route_id = build_route_pipeline(config, lambda d: d.require_https())

    over_http = await send_request(pipeline, route_id, ip="203.0.113.5", scheme="http")
    over_https = await send_request(
        pipeline, route_id, ip="203.0.113.5", scheme="https"
    )

    assert over_http is not None and over_http.status_code == 301
    assert over_https is None


async def test_neither_setting_leaves_plain_http_alone() -> None:
    config = _config(enforce_https=False)
    pipeline, _, route_id = build_route_pipeline(config, lambda d: d.rate_limit(50, 60))

    assert (
        await send_request(pipeline, route_id, ip="203.0.113.5", scheme="http") is None
    )


def _both_methods() -> tuple[RequestValidator, TimeWindowCheck]:
    config = _config()
    validator = RequestValidator(
        ValidationContext(config=config, logger=Mock(), event_bus=Mock())
    )
    check = TimeWindowCheck(build_middleware(config, SecurityDecorator(config)))
    return validator, check


def _at(monkeypatch: pytest.MonkeyPatch, instant: datetime) -> None:
    clock = Mock()
    clock.now = lambda tz: instant.astimezone(tz)
    for module in (time_window_check_module, validator_module):
        monkeypatch.setattr(module, "datetime", clock)


def _grid(zone: str, day: datetime) -> list[datetime]:
    local = day.replace(tzinfo=ZoneInfo(zone))
    edges = [local.replace(hour=9), local.replace(hour=17)]
    return [
        (edge + timedelta(minutes=delta)).astimezone(timezone.utc)
        for edge in edges
        for delta in (-61, -1, 0, 1, 61)
    ]


ZONES_AND_DAYS = [
    ("UTC", datetime(2026, 7, 1)),
    ("Europe/Berlin", datetime(2026, 7, 1)),
    ("Europe/Berlin", datetime(2026, 1, 15)),
    ("Europe/Berlin", datetime(2026, 3, 29)),
    ("Europe/Berlin", datetime(2026, 10, 25)),
]


@pytest.mark.parametrize(("zone", "day"), ZONES_AND_DAYS)
async def test_the_legacy_method_gives_the_check_verdict_around_both_edges(
    monkeypatch: pytest.MonkeyPatch, zone: str, day: datetime
) -> None:
    validator, check = _both_methods()
    restrictions = {"start": "09:00", "end": "17:00", "timezone": zone}

    for instant in _grid(zone, day):
        _at(monkeypatch, instant)
        local = instant.astimezone(ZoneInfo(zone)).strftime("%H:%M")
        expected = "09:00" <= local <= "17:00"
        assert await check._check_time_window(restrictions) is expected
        assert await validator.check_time_window(restrictions) is expected, instant


async def test_the_legacy_method_honors_the_timezone_where_utc_would_differ(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    validator, _ = _both_methods()
    restrictions = {"start": "09:00", "end": "17:00", "timezone": "Europe/Berlin"}
    _at(monkeypatch, datetime(2026, 7, 1, 6, 30, tzinfo=timezone.utc))

    assert await validator.check_time_window(restrictions) is False
    _at(monkeypatch, datetime(2026, 7, 1, 7, 0, tzinfo=timezone.utc))
    assert await validator.check_time_window(restrictions) is True


async def test_the_legacy_window_end_is_minute_inclusive_like_the_check(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    validator, check = _both_methods()
    restrictions = {"start": "09:00", "end": "17:00"}

    _at(monkeypatch, datetime(2026, 7, 1, 17, 0, 59, tzinfo=timezone.utc))
    assert await validator.check_time_window(restrictions) is True
    assert await check._check_time_window(restrictions) is True
    _at(monkeypatch, datetime(2026, 7, 1, 17, 1, tzinfo=timezone.utc))
    assert await validator.check_time_window(restrictions) is False
    assert await check._check_time_window(restrictions) is False


def test_a_bad_timezone_fails_at_startup_when_misconfiguration_is_fatal() -> None:
    decorator = SecurityDecorator(
        SecurityConfig(enable_redis=False, fail_on_misconfiguration=True)
    )

    with pytest.raises(ValueError, match="not a known IANA time zone"):
        decorator.time_window("09:00", "17:00", "Mars/Olympus")(lambda: None)


async def test_a_blocked_name_at_character_600_of_an_8000_character_agent() -> None:
    marker = "zzq_badbot_zzq"
    user_agent = "a" * 599 + marker + "a" * (8000 - 599 - len(marker))
    config = SecurityConfig(blocked_user_agents=[marker])

    assert len(user_agent) == 8000
    assert await is_user_agent_allowed(user_agent, config) is False
