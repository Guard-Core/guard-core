import logging
from collections.abc import Callable
from typing import Any

import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.sync.core.checks.pipeline import SecurityCheckPipeline
from guard_core.sync.core.initialization.handler_initializer import HandlerInitializer
from guard_core.sync.decorators import SecurityDecorator
from tests.test_sync.test_core.conftest import (
    build_route_pipeline,
    fixed_country_geo_ip,
    send_request,
)

IP = "198.51.100.30"


def _config(**settings: Any) -> SyncSecurityConfig:
    defaults: dict[str, Any] = {
        "enable_redis": False,
        "enable_penetration_detection": False,
        "enable_rate_limiting": False,
        "rate_limit": 1,
    }
    return SyncSecurityConfig(**{**defaults, **settings})


def _statuses(
    pipeline: SecurityCheckPipeline, route_id: str, count: int
) -> list[int | None]:
    statuses = []
    for _ in range(count):
        response = send_request(pipeline, route_id, ip=IP)
        statuses.append(None if response is None else response.status_code)
    return statuses


def test_a_rate_limit_decorator_applies_with_the_global_switch_off() -> None:
    pipeline, _, route_id = build_route_pipeline(
        _config(), lambda d: d.rate_limit(2, 60)
    )

    assert _statuses(pipeline, route_id, 4) == [None, None, 429, 429]


def test_a_geo_rate_limit_decorator_applies_with_the_global_switch_off() -> None:
    config = _config()
    geo = fixed_country_geo_ip("US")
    config.geo_ip_handler = geo
    pipeline, _, route_id = build_route_pipeline(
        config, lambda d: d.geo_rate_limit({"US": (2, 60)}), geo_ip_handler=geo
    )

    assert _statuses(pipeline, route_id, 4) == [None, None, 429, 429]


def test_the_switch_still_turns_off_the_global_tier() -> None:
    pipeline, _, route_id = build_route_pipeline(
        _config(), lambda d: d.rate_limit(1000, 60)
    )

    assert _statuses(pipeline, route_id, 5) == [None] * 5


def test_the_switch_on_keeps_both_tiers() -> None:
    pipeline, _, route_id = build_route_pipeline(
        _config(enable_rate_limiting=True, rate_limit=3),
        lambda d: d.rate_limit(1000, 60),
    )

    assert _statuses(pipeline, route_id, 5) == [None, None, None, 429, 429]


def _decorated(
    make: Callable[[SecurityDecorator], Any], config: SyncSecurityConfig
) -> tuple[SecurityDecorator, str]:
    decorator = SecurityDecorator(config)

    def limited_route() -> None:
        pass

    return decorator, make(decorator)(limited_route)._guard_route_id


def test_startup_names_the_routes_whose_limits_stay_on(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = _config()
    decorator, route_id = _decorated(lambda d: d.rate_limit(5, 60), config)
    initializer = HandlerInitializer(config, guard_decorator=decorator)

    with caplog.at_level(logging.INFO):
        initializer.initialize_redis_handlers()

    lines = [
        record
        for record in caplog.records
        if "enable_rate_limiting is False" in record.getMessage()
    ]
    assert len(lines) == 1
    assert lines[0].levelno == logging.INFO
    assert route_id in lines[0].getMessage()


def test_startup_is_silent_when_the_switch_is_on(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = _config(enable_rate_limiting=True)
    decorator, _ = _decorated(lambda d: d.rate_limit(5, 60), config)
    initializer = HandlerInitializer(config, guard_decorator=decorator)

    with caplog.at_level(logging.INFO):
        initializer.initialize_redis_handlers()

    assert not [
        record
        for record in caplog.records
        if "enable_rate_limiting is False" in record.getMessage()
    ]


def test_startup_is_silent_when_no_route_has_a_limit(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = _config()
    decorator, _ = _decorated(lambda d: d.require_https(), config)
    initializer = HandlerInitializer(config, guard_decorator=decorator)

    with caplog.at_level(logging.INFO):
        initializer.initialize_redis_handlers()

    assert not [
        record
        for record in caplog.records
        if "enable_rate_limiting is False" in record.getMessage()
    ]
