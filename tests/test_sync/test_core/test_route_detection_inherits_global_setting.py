from typing import Any

from guard_core.models import SecurityConfig
from guard_core.sync.decorators.route_config import RouteConfig
from tests.test_sync.test_core.conftest import build_route_pipeline, send_request

SQLI_PATH = "/x?q=1%27%20UNION%20SELECT%20password%20FROM%20users--"


def _config(detection: bool) -> SecurityConfig:
    return SecurityConfig(
        enable_redis=False,
        enable_penetration_detection=detection,
        enable_rate_limiting=False,
        enable_ip_banning=False,
    )


def _status(pipeline: Any, route_id: str) -> int | None:
    response = send_request(pipeline, route_id, ip="203.0.113.80", path=SQLI_PATH)
    return None if response is None else response.status_code


def test_a_route_config_inherits_the_global_setting_by_default() -> None:
    assert RouteConfig().enable_suspicious_detection is None


def test_enabling_global_detection_after_decoration_protects_the_route() -> None:
    config = _config(detection=False)
    pipeline, _, route_id = build_route_pipeline(config, lambda d: d.rate_limit(50, 60))

    config.enable_penetration_detection = True

    assert _status(pipeline, route_id) == 400


def test_disabling_global_detection_after_decoration_unprotects_the_route() -> None:
    config = _config(detection=True)
    pipeline, _, route_id = build_route_pipeline(config, lambda d: d.rate_limit(50, 60))

    config.enable_penetration_detection = False

    assert _status(pipeline, route_id) is None


def test_an_explicit_off_stays_off_when_global_detection_is_on() -> None:
    pipeline, _, route_id = build_route_pipeline(
        _config(detection=True), lambda d: d.suspicious_detection(False)
    )

    assert _status(pipeline, route_id) is None


def test_an_explicit_on_scans_the_route_when_global_detection_is_off() -> None:
    pipeline, _, route_id = build_route_pipeline(
        _config(detection=False), lambda d: d.suspicious_detection(True)
    )

    assert _status(pipeline, route_id) == 400
