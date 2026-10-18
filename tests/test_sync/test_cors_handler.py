import pytest

from guard_core.models import SecurityConfig
from guard_core.sync.handlers.cors_handler import (
    CorsHandler,
    is_preflight,
)


@pytest.fixture
def cfg() -> SecurityConfig:
    return SecurityConfig(
        enable_cors=True,
        cors_allow_origins=["https://app.example.com"],
        cors_allow_methods=["GET", "POST"],
        cors_allow_headers=["X-Custom"],
        cors_allow_credentials=True,
        cors_max_age=600,
        cors_expose_headers=["X-Trace"],
    )


def test_is_preflight_true_for_options_with_acrm() -> None:
    headers = {
        "origin": "https://app.example.com",
        "access-control-request-method": "POST",
    }
    assert is_preflight("OPTIONS", headers) is True


def test_is_preflight_lowercase_options_works() -> None:
    headers = {
        "origin": "https://app.example.com",
        "access-control-request-method": "POST",
    }
    assert is_preflight("options", headers) is True


def test_is_preflight_false_for_options_without_acrm() -> None:
    assert is_preflight("OPTIONS", {"origin": "x"}) is False


def test_is_preflight_false_for_get() -> None:
    assert is_preflight("GET", {"origin": "x"}) is False


def test_is_preflight_handles_mixed_case_headers() -> None:
    headers = {
        "Origin": "https://app.example.com",
        "Access-Control-Request-Method": "POST",
    }
    assert is_preflight("OPTIONS", headers) is True


def test_preflight_response_allowed_origin(cfg: SecurityConfig) -> None:
    handler = CorsHandler(cfg)
    response = handler.build_preflight_response(
        request_headers={
            "origin": "https://app.example.com",
            "access-control-request-method": "POST",
            "access-control-request-headers": "X-Custom",
        }
    )
    assert response.status_code == 200
    assert response.headers["Access-Control-Allow-Origin"] == "https://app.example.com"
    assert response.headers["Access-Control-Allow-Credentials"] == "true"
    assert "POST" in response.headers["Access-Control-Allow-Methods"]
    assert response.headers["Access-Control-Max-Age"] == "600"
    assert response.headers["Vary"] == "Origin"


def test_preflight_response_disallowed_origin(cfg: SecurityConfig) -> None:
    handler = CorsHandler(cfg)
    response = handler.build_preflight_response(
        request_headers={
            "origin": "https://attacker.example.com",
            "access-control-request-method": "POST",
        }
    )
    assert response.status_code == 400
    assert "origin" in response.body.lower()


def test_preflight_response_disallowed_method(cfg: SecurityConfig) -> None:
    handler = CorsHandler(cfg)
    response = handler.build_preflight_response(
        request_headers={
            "origin": "https://app.example.com",
            "access-control-request-method": "DELETE",
        }
    )
    assert response.status_code == 400
    assert "method" in response.body.lower()


def test_preflight_response_disallowed_headers(cfg: SecurityConfig) -> None:
    handler = CorsHandler(cfg)
    response = handler.build_preflight_response(
        request_headers={
            "origin": "https://app.example.com",
            "access-control-request-method": "POST",
            "access-control-request-headers": "X-Forbidden",
        }
    )
    assert response.status_code == 400
    assert "headers" in response.body.lower()


def test_response_headers_for_simple_request(cfg: SecurityConfig) -> None:
    handler = CorsHandler(cfg)
    headers = handler.build_response_headers(
        request_headers={"origin": "https://app.example.com"}
    )
    assert headers["Access-Control-Allow-Origin"] == "https://app.example.com"
    assert headers["Access-Control-Allow-Credentials"] == "true"
    assert headers["Access-Control-Expose-Headers"] == "X-Trace"
    assert headers["Vary"] == "Origin"


def test_response_headers_for_disallowed_origin(cfg: SecurityConfig) -> None:
    handler = CorsHandler(cfg)
    headers = handler.build_response_headers(
        request_headers={"origin": "https://attacker.example.com"}
    )
    assert headers == {"Vary": "Origin"}


def test_response_headers_with_no_origin_return_only_vary(cfg: SecurityConfig) -> None:
    handler = CorsHandler(cfg)
    headers = handler.build_response_headers(request_headers={})
    assert headers == {"Vary": "Origin"}


def test_wildcard_origin_with_credentials_raises_at_init() -> None:
    bad = SecurityConfig(
        enable_cors=True,
        cors_allow_origins=["*"],
        cors_allow_credentials=True,
    )
    with pytest.raises(ValueError, match="wildcard origin"):
        CorsHandler(bad)


def test_wildcard_origin_without_credentials() -> None:
    cfg = SecurityConfig(
        enable_cors=True,
        cors_allow_origins=["*"],
        cors_allow_credentials=False,
        cors_allow_methods=["GET"],
    )
    handler = CorsHandler(cfg)
    headers = handler.build_response_headers(
        request_headers={"origin": "https://random.example.com"}
    )
    assert headers["Access-Control-Allow-Origin"] == "*"


def test_allow_all_headers_mirrors_requested(cfg: SecurityConfig) -> None:
    cfg2 = SecurityConfig(
        enable_cors=True,
        cors_allow_origins=["https://app.example.com"],
        cors_allow_methods=["GET", "POST"],
        cors_allow_headers=["*"],
        cors_allow_credentials=True,
    )
    handler = CorsHandler(cfg2)
    response = handler.build_preflight_response(
        request_headers={
            "origin": "https://app.example.com",
            "access-control-request-method": "POST",
            "access-control-request-headers": "X-Anything, Y-Other",
        }
    )
    assert response.status_code == 200
    assert response.headers["Access-Control-Allow-Headers"] == "X-Anything, Y-Other"


def test_disabled_cors_handler_skips_logic() -> None:
    cfg = SecurityConfig(enable_cors=False)
    handler = CorsHandler(cfg)
    headers = handler.build_response_headers(request_headers={"origin": "https://x"})
    assert headers == {}


def test_is_origin_allowed_false_when_disabled() -> None:
    cfg = SecurityConfig(enable_cors=False)
    handler = CorsHandler(cfg)
    assert handler.is_origin_allowed("https://example.com") is False


def test_is_origin_allowed_true_for_wildcard() -> None:
    cfg = SecurityConfig(
        enable_cors=True,
        cors_allow_origins=["*"],
        cors_allow_credentials=False,
        cors_allow_methods=["GET"],
    )
    handler = CorsHandler(cfg)
    assert handler.is_origin_allowed("https://any.example.com") is True


def test_preflight_allow_all_headers_empty_requested_headers_raw() -> None:
    cfg2 = SecurityConfig(
        enable_cors=True,
        cors_allow_origins=["https://app.example.com"],
        cors_allow_methods=["GET", "POST"],
        cors_allow_headers=["*"],
        cors_allow_credentials=True,
    )
    handler = CorsHandler(cfg2)
    response = handler.build_preflight_response(
        request_headers={
            "origin": "https://app.example.com",
            "access-control-request-method": "POST",
        }
    )
    assert response.status_code == 200
    assert "Access-Control-Allow-Headers" not in response.headers


def test_preflight_no_credentials_flag() -> None:
    cfg2 = SecurityConfig(
        enable_cors=True,
        cors_allow_origins=["https://app.example.com"],
        cors_allow_methods=["GET", "POST"],
        cors_allow_credentials=False,
    )
    handler = CorsHandler(cfg2)
    response = handler.build_preflight_response(
        request_headers={
            "origin": "https://app.example.com",
            "access-control-request-method": "GET",
        }
    )
    assert response.status_code == 200
    assert "Access-Control-Allow-Credentials" not in response.headers
