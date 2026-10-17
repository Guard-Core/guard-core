from typing import Any

import pytest

from guard_core.decorators import SecurityDecorator
from guard_core.decorators.route_config import RouteConfig
from guard_core.models import SecurityConfig
from tests.test_core.conftest import build_route_pipeline, send_request

SQLI_PATH = "/x?q=1%27%20UNION%20SELECT%20password%20FROM%20users--"


def _config(detection: bool) -> SecurityConfig:
    return SecurityConfig(
        enable_redis=False,
        enable_penetration_detection=detection,
        enable_rate_limiting=False,
        enable_ip_banning=False,
    )


async def _status(pipeline: Any, route_id: str) -> int | None:
    response = await send_request(pipeline, route_id, ip="203.0.113.80", path=SQLI_PATH)
    return None if response is None else response.status_code


def test_a_route_config_keeps_the_v440_default() -> None:
    assert RouteConfig().enable_suspicious_detection is True


@pytest.mark.parametrize("detection", [True, False])
def test_a_decorated_route_reports_the_global_setting_it_was_created_with(
    detection: bool,
) -> None:
    decorator = SecurityDecorator(_config(detection))

    def route() -> None:
        pass

    decorated = decorator.rate_limit(50, 60)(route)
    route_config = decorator.get_route_config(decorated._guard_route_id)

    assert route_config is not None
    assert route_config.enable_suspicious_detection is detection


async def test_enabling_global_detection_after_decoration_protects_the_route() -> None:
    config = _config(detection=False)
    pipeline, _, route_id = build_route_pipeline(config, lambda d: d.rate_limit(50, 60))

    config.enable_penetration_detection = True

    assert await _status(pipeline, route_id) == 400


async def test_disabling_global_detection_after_decoration_unprotects_the_route() -> (
    None
):
    config = _config(detection=True)
    pipeline, _, route_id = build_route_pipeline(config, lambda d: d.rate_limit(50, 60))

    config.enable_penetration_detection = False

    assert await _status(pipeline, route_id) is None


async def test_an_explicit_off_stays_off_when_global_detection_is_on() -> None:
    pipeline, _, route_id = build_route_pipeline(
        _config(detection=True), lambda d: d.suspicious_detection(False)
    )

    assert await _status(pipeline, route_id) is None


async def test_an_explicit_on_scans_the_route_when_global_detection_is_off() -> None:
    pipeline, _, route_id = build_route_pipeline(
        _config(detection=False), lambda d: d.suspicious_detection(True)
    )

    assert await _status(pipeline, route_id) == 400


async def test_a_direct_assignment_pins_the_route_like_the_decorator() -> None:
    config = _config(detection=True)
    pipeline, middleware, route_id = build_route_pipeline(
        config, lambda d: d.rate_limit(50, 60)
    )
    route_config = middleware.guard_decorator.get_route_config(route_id)
    assert route_config is not None

    route_config.enable_suspicious_detection = False

    assert await _status(pipeline, route_id) is None
