from typing import Any

from guard_core.handlers.cors_handler import CorsHandler
from guard_core.models import SecurityConfig

ORIGIN = "https://app.example.com"
PREFLIGHT = {
    "origin": ORIGIN,
    "access-control-request-method": "POST",
}


def _handler(**overrides: Any) -> CorsHandler:
    fields: dict[str, Any] = {
        "enable_redis": False,
        "enable_cors": True,
        "cors_allow_origins": [ORIGIN],
    }
    fields.update(overrides)
    return CorsHandler(SecurityConfig(**fields))


def test_an_allowed_preflight_carries_the_security_headers() -> None:
    response = _handler().build_preflight_response(PREFLIGHT)

    assert response.status_code == 200
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "SAMEORIGIN"
    assert "Strict-Transport-Security" in response.headers
    assert response.headers["Access-Control-Allow-Origin"] == ORIGIN


def test_a_refused_preflight_carries_the_security_headers_too() -> None:
    response = _handler().build_preflight_response(
        {**PREFLIGHT, "origin": "https://evil.example"}
    )

    assert response.status_code == 400
    assert response.headers["X-Content-Type-Options"] == "nosniff"


def test_the_preflight_follows_the_configured_security_headers() -> None:
    response = _handler(
        security_headers={"enabled": True, "frame_options": "DENY"}
    ).build_preflight_response(PREFLIGHT)

    assert response.headers["X-Frame-Options"] == "DENY"


def test_security_headers_off_adds_none_to_the_preflight() -> None:
    for value in (None, {}, {"enabled": False}):
        response = _handler(security_headers=value).build_preflight_response(PREFLIGHT)

        assert "X-Content-Type-Options" not in response.headers
        assert response.headers["Access-Control-Max-Age"] == "600"


def test_a_cors_header_is_never_replaced_by_a_security_header() -> None:
    response = _handler(
        security_headers={"enabled": True, "custom": {"Vary": "Accept"}}
    ).build_preflight_response(PREFLIGHT)

    assert response.headers["Vary"] == "Origin"


def test_a_config_changed_after_construction_is_followed() -> None:
    config = SecurityConfig(
        enable_redis=False, enable_cors=True, cors_allow_origins=[ORIGIN]
    )
    handler = CorsHandler(config)
    assert handler.build_preflight_response(PREFLIGHT).headers["X-Frame-Options"] == (
        "SAMEORIGIN"
    )

    config.security_headers = {"enabled": True, "frame_options": "DENY"}

    assert handler.build_preflight_response(PREFLIGHT).headers["X-Frame-Options"] == (
        "DENY"
    )
