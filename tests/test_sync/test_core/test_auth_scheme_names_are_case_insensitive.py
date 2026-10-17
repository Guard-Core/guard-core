import base64
import logging
from typing import Any

import pytest

from guard_core.models import SecurityConfig
from guard_core.sync.core.checks.helpers import _SCHEME_FAILURES
from guard_core.sync.decorators import SecurityDecorator
from guard_core.sync.decorators._route_arguments import BUILT_IN_AUTH_SCHEMES
from tests.test_sync.test_core.conftest import build_route_pipeline, send_request

PASSWORD = "Sup3r-Secret-Pw"
BASIC_BLOB = base64.b64encode(f"alice:{PASSWORD}".encode()).decode()


def _config() -> SecurityConfig:
    return SecurityConfig(
        enable_redis=False,
        enable_penetration_detection=False,
        enable_rate_limiting=False,
    )


def _decoding(request: Any, credential: str) -> bool:
    blob = credential.rsplit(" ", 1)[-1]
    user, _, password = base64.b64decode(blob).decode().partition(":")
    raise ValueError(f"backend rejected {user} with password {password}")


def _deny(request: Any, credential: str) -> bool:
    return False


def _route_config(make: Any) -> Any:
    decorator = SecurityDecorator(_config())

    def route() -> None:
        pass

    decorated = make(decorator)(route)
    return decorator.get_route_config(decorated._guard_route_id)


def test_a_capitalized_basic_type_never_logs_the_decoded_password(
    caplog: pytest.LogCaptureFixture,
) -> None:
    pipeline, _, route_id = build_route_pipeline(
        _config(), lambda d: d.require_auth("Basic", verifier=_decoding)
    )

    with caplog.at_level(logging.DEBUG):
        response = send_request(
            pipeline,
            route_id,
            ip="203.0.113.160",
            headers={"authorization": f"Basic {BASIC_BLOB}"},
        )

    assert response is not None
    assert response.status_code == 503
    logged = "\n".join(r.getMessage() for r in caplog.records)
    assert PASSWORD not in logged
    assert "ValueError: backend rejected alice with password [REDACTED]" in logged


@pytest.mark.parametrize(
    ("scheme", "challenge"),
    [("Basic", 'Basic realm="Restricted"'), ("BASIC", 'Basic realm="Restricted"')],
)
def test_a_capitalized_basic_type_answers_the_basic_challenge(
    scheme: str, challenge: str
) -> None:
    pipeline, _, route_id = build_route_pipeline(
        _config(), lambda d: d.require_auth(scheme, verifier=_deny)
    )

    response = send_request(pipeline, route_id, ip="203.0.113.161")

    assert response is not None
    assert response.status_code == 401
    assert response.headers["WWW-Authenticate"] == challenge


def test_an_uppercase_bearer_type_hands_the_verifier_the_token_only() -> None:
    received: list[str] = []

    def verifier(request: Any, credential: str) -> bool:
        received.append(credential)
        return True

    pipeline, _, route_id = build_route_pipeline(
        _config(), lambda d: d.require_auth("BEARER", verifier=verifier)
    )

    response = send_request(
        pipeline,
        route_id,
        ip="203.0.113.162",
        headers={"authorization": "Bearer tok-1"},
    )

    assert response is None
    assert received == ["tok-1"]


@pytest.mark.parametrize(
    ("headers", "expected_status"),
    [({"authorization": "Token abc"}, 401), ({"authorization": "Bearer abc"}, None)],
)
def test_a_capitalized_presence_scheme_enforces_the_bearer_prefix(
    headers: dict[str, str], expected_status: int | None
) -> None:
    pipeline, _, route_id = build_route_pipeline(
        _config(), lambda d: d.require_authorization_header("Bearer")
    )

    response = send_request(pipeline, route_id, ip="203.0.113.163", headers=headers)

    assert (response and response.status_code) == expected_status


@pytest.mark.parametrize(
    ("given", "stored"),
    [
        ("bearer", "bearer"),
        ("basic", "basic"),
        ("Bearer", "bearer"),
        ("BASIC", "basic"),
        ("Token", "Token"),
        ("digest", "digest"),
    ],
)
def test_only_the_built_in_scheme_names_are_folded(given: str, stored: str) -> None:
    auth = _route_config(lambda d: d.require_auth(given))
    presence = _route_config(lambda d: d.require_authorization_header(given))

    assert auth.auth_required == stored
    assert presence.authorization_header_required == stored


def test_the_built_in_scheme_names_match_the_credential_extraction() -> None:
    assert set(BUILT_IN_AUTH_SCHEMES) == set(_SCHEME_FAILURES)
