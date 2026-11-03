from typing import Any

import pytest

from guard_core.handlers.cors_handler import CorsHandler, CorsPreflightResponse
from guard_core.handlers.security_headers_handler import security_headers_manager
from guard_core.models import SecurityConfig

ORIGIN = "https://app.example.com"


def _config(**overrides: object) -> SecurityConfig:
    fields: dict[str, Any] = {
        "enable_redis": False,
        "enable_cors": True,
        "cors_allow_origins": [ORIGIN],
        "cors_allow_methods": ["GET", "POST"],
        "cors_allow_headers": ["X-Custom"],
    }
    fields.update(overrides)
    return SecurityConfig(**fields)


def _preflight(
    handler: CorsHandler, requested: str = "X-Custom"
) -> CorsPreflightResponse:
    return handler.build_preflight_response(
        {
            "origin": ORIGIN,
            "access-control-request-method": "POST",
            "access-control-request-headers": requested,
        }
    )


async def test_empty_allow_headers_means_the_same_in_both_implementations() -> None:
    config = _config(cors_allow_headers=[])

    preflight = _preflight(CorsHandler(config))
    manager = await security_headers_manager.get_cors_headers(ORIGIN, config=config)

    assert preflight.status_code == 400
    assert "Disallowed CORS: headers" in preflight.body
    assert "Access-Control-Allow-Headers" not in manager


async def test_empty_allow_headers_still_answers_a_header_less_preflight() -> None:
    config = _config(cors_allow_headers=[])

    preflight = _preflight(CorsHandler(config), requested="")

    assert preflight.status_code == 200


async def test_a_wildcard_allow_headers_still_works_in_both() -> None:
    config = _config(cors_allow_headers=["*"])

    preflight = _preflight(CorsHandler(config))
    manager = await security_headers_manager.get_cors_headers(ORIGIN, config=config)

    assert preflight.status_code == 200
    assert manager["Access-Control-Allow-Headers"] == "*"


async def test_cors_max_age_is_honored_by_both_implementations() -> None:
    config = _config(cors_max_age=600)

    preflight = _preflight(CorsHandler(config))
    manager = await security_headers_manager.get_cors_headers(ORIGIN, config=config)

    assert preflight.headers["Access-Control-Max-Age"] == "600"
    assert manager["Access-Control-Max-Age"] == "600"


async def test_a_max_age_of_zero_is_honored() -> None:
    config = _config(cors_max_age=0)

    preflight = _preflight(CorsHandler(config))
    manager = await security_headers_manager.get_cors_headers(ORIGIN, config=config)

    assert preflight.headers["Access-Control-Max-Age"] == "0"
    assert manager["Access-Control-Max-Age"] == "0"


async def test_a_configured_origin_with_a_trailing_slash_matches() -> None:
    config = _config(cors_allow_origins=[f"{ORIGIN}/"])
    handler = CorsHandler(config)

    assert handler.is_origin_allowed(ORIGIN)
    assert _preflight(handler).status_code == 200
    assert (
        handler.build_response_headers({"origin": ORIGIN})[
            "Access-Control-Allow-Origin"
        ]
        == ORIGIN
    )
    manager = await security_headers_manager.get_cors_headers(ORIGIN, config=config)
    assert manager["Access-Control-Allow-Origin"] == ORIGIN


def test_a_wildcard_origin_is_untouched_by_the_normalisation() -> None:
    handler = CorsHandler(_config(cors_allow_origins=["*"]))

    assert (
        handler.build_response_headers({"origin": ORIGIN})[
            "Access-Control-Allow-Origin"
        ]
        == "*"
    )


@pytest.mark.parametrize(
    "request_headers",
    [{"origin": ORIGIN}, {"origin": "https://evil.example"}, {}],
    ids=["allowed", "disallowed", "no-origin"],
)
def test_vary_origin_is_on_every_response_when_cors_is_on(
    request_headers: dict[str, str],
) -> None:
    headers = CorsHandler(_config()).build_response_headers(request_headers)

    assert headers["Vary"] == "Origin"


def test_a_disallowed_or_origin_less_response_carries_no_allow_origin() -> None:
    handler = CorsHandler(_config())

    assert "Access-Control-Allow-Origin" not in handler.build_response_headers(
        {"origin": "https://evil.example"}
    )
    assert "Access-Control-Allow-Origin" not in handler.build_response_headers({})


def test_a_wildcard_deployment_varies_on_origin_too() -> None:
    handler = CorsHandler(_config(cors_allow_origins=["*"]))

    assert handler.build_response_headers({})["Vary"] == "Origin"


def test_cors_off_adds_nothing() -> None:
    handler = CorsHandler(_config(enable_cors=False))

    assert handler.build_response_headers({"origin": ORIGIN}) == {}


@pytest.mark.parametrize(
    ("existing", "merged"),
    [
        (None, "Origin"),
        ("", "Origin"),
        ("Accept-Encoding", "Accept-Encoding, Origin"),
        ("Accept-Encoding, origin", "Accept-Encoding, origin"),
        ("*", "*"),
    ],
)
def test_vary_merges_with_the_apps_own_vary(existing: str | None, merged: str) -> None:
    headers = CorsHandler(_config()).build_response_headers(
        {"origin": ORIGIN}, existing_vary=existing
    )

    assert headers["Vary"] == merged
