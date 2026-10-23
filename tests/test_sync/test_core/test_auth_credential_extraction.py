from typing import Any

import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.sync.core.checks.helpers import extract_credential
from tests.test_sync.test_core.conftest import build_route_pipeline, send_request


@pytest.mark.parametrize(
    ("header", "scheme", "credential"),
    [
        ("Bearer abc", "bearer", "abc"),
        ("bearer abc", "bearer", "abc"),
        ("BEARER abc", "bearer", "abc"),
        ("Basic dXNlcjpwdw==", "basic", "dXNlcjpwdw=="),
        ("basic dXNlcjpwdw==", "basic", "dXNlcjpwdw=="),
    ],
)
def test_the_scheme_name_is_case_insensitive(
    header: str, scheme: str, credential: str
) -> None:
    assert extract_credential(header, scheme) == (credential, "")


@pytest.mark.parametrize(
    ("header", "scheme"),
    [
        ("Bearer ", "bearer"),
        ("Bearer    ", "bearer"),
        ("bearer ", "bearer"),
        ("Basic ", "basic"),
        ("", "bearer"),
        ("Token abc", "bearer"),
    ],
)
def test_an_empty_or_foreign_credential_is_missing(header: str, scheme: str) -> None:
    credential, reason = extract_credential(header, scheme)

    assert credential is None
    assert reason


def _config() -> SyncSecurityConfig:
    return SyncSecurityConfig(
        enable_redis=False,
        enable_penetration_detection=False,
        enable_rate_limiting=False,
    )


@pytest.mark.parametrize("header", ["Bearer ", "bearer "])
def test_require_auth_never_runs_the_verifier_for_an_empty_token(
    header: str,
) -> None:
    calls: list[Any] = []

    def verifier(request: Any, credential: str) -> bool:
        calls.append(credential)
        return True

    pipeline, _, route_id = build_route_pipeline(
        _config(), lambda d: d.require_auth("bearer", verifier=verifier)
    )

    response = send_request(
        pipeline, route_id, ip="203.0.113.30", headers={"authorization": header}
    )

    assert response is not None
    assert response.status_code == 401
    assert calls == []


def test_presence_only_route_rejects_an_empty_bearer_token() -> None:
    pipeline, _, route_id = build_route_pipeline(
        _config(), lambda d: d.require_authorization_header("bearer")
    )

    response = send_request(
        pipeline, route_id, ip="203.0.113.31", headers={"authorization": "Bearer "}
    )

    assert response is not None
    assert response.status_code == 401


def test_lowercase_bearer_scheme_reaches_the_verifier() -> None:
    seen: list[str] = []

    def verifier(request: Any, credential: str) -> bool:
        seen.append(credential)
        return True

    pipeline, _, route_id = build_route_pipeline(
        _config(), lambda d: d.require_auth("bearer", verifier=verifier)
    )

    response = send_request(
        pipeline,
        route_id,
        ip="203.0.113.32",
        headers={"authorization": "bearer abc"},
    )

    assert response is None
    assert seen == ["abc"]
