from typing import Any

import pytest

from guard_core.models import SecurityConfig
from tests.test_core.conftest import build_route_pipeline, send_request


def _config(**overrides: Any) -> SecurityConfig:
    return SecurityConfig(
        enable_redis=False,
        enable_penetration_detection=False,
        enable_rate_limiting=False,
        **overrides,
    )


def _deny(request: Any, credential: str) -> bool:
    return False


@pytest.mark.parametrize(
    ("make", "headers", "challenge"),
    [
        (lambda d: d.require_auth("bearer", verifier=_deny), {}, "Bearer"),
        (
            lambda d: d.require_auth("bearer", verifier=_deny),
            {"authorization": "Bearer nope"},
            "Bearer",
        ),
        (
            lambda d: d.require_auth("basic", verifier=_deny),
            {},
            'Basic realm="Restricted"',
        ),
        (lambda d: d.api_key_auth("X-Key", verifier=_deny), {}, "ApiKey"),
        (lambda d: d.require_authorization_header("bearer"), {}, "Bearer"),
    ],
)
async def test_a_401_carries_a_challenge_for_the_scheme_in_use(
    make: Any, headers: dict[str, str], challenge: str
) -> None:
    pipeline, _, route_id = build_route_pipeline(_config(), make)

    response = await send_request(
        pipeline, route_id, ip="203.0.113.40", headers=headers
    )

    assert response is not None
    assert response.status_code == 401
    assert response.headers["WWW-Authenticate"] == challenge


async def test_a_passed_request_gets_no_challenge() -> None:
    pipeline, _, route_id = build_route_pipeline(
        _config(), lambda d: d.require_auth("bearer", verifier=lambda r, k: True)
    )

    response = await send_request(
        pipeline,
        route_id,
        ip="203.0.113.41",
        headers={"authorization": "Bearer ok"},
    )

    assert response is None
