import logging
from typing import Any

import pytest

from guard_core.models import SecurityConfig
from tests.test_sync.test_core.conftest import build_route_pipeline, send_request


def _config() -> SecurityConfig:
    return SecurityConfig(
        enable_redis=False,
        enable_penetration_detection=False,
        enable_rate_limiting=False,
    )


def _raising(request: Any, credential: str) -> bool:
    raise RuntimeError("auth backend down")


@pytest.mark.parametrize(
    ("make", "headers"),
    [
        (
            lambda d: d.require_auth("bearer", verifier=_raising),
            {"authorization": "Bearer token-value"},
        ),
        (lambda d: d.api_key_auth("X-Key", verifier=_raising), {"X-Key": "key-value"}),
    ],
)
def test_a_raising_verifier_is_logged_with_its_cause_and_answers_503(
    make: Any, headers: dict[str, str], caplog: pytest.LogCaptureFixture
) -> None:
    pipeline, _, route_id = build_route_pipeline(_config(), make)

    with caplog.at_level(logging.ERROR):
        response = send_request(pipeline, route_id, ip="203.0.113.50", headers=headers)

    assert response is not None
    assert response.status_code == 503
    assert "WWW-Authenticate" not in response.headers
    errors = [r for r in caplog.records if r.levelno == logging.ERROR]
    assert len(errors) == 1
    message = errors[0].getMessage()
    assert message.splitlines()[0] == "Authentication verifier raised RuntimeError"
    assert "Traceback (most recent call last)" in message
    assert "RuntimeError: auth backend down" in message
    assert errors[0].exc_info is None


def test_a_verifier_that_returns_false_logs_no_error(
    caplog: pytest.LogCaptureFixture,
) -> None:
    pipeline, _, route_id = build_route_pipeline(
        _config(), lambda d: d.require_auth("bearer", verifier=lambda r, k: False)
    )

    with caplog.at_level(logging.ERROR):
        send_request(
            pipeline,
            route_id,
            ip="203.0.113.51",
            headers={"authorization": "Bearer token-value"},
        )

    assert [r for r in caplog.records if r.levelno >= logging.ERROR] == []


def _status(pipeline: Any, route_id: str, ip: str) -> int:
    response = send_request(
        pipeline, route_id, ip=ip, headers={"authorization": "Bearer token-value"}
    )
    assert response is not None
    return response.status_code


def _ban_config(**overrides: Any) -> SecurityConfig:
    return SecurityConfig(
        enable_redis=False,
        enable_penetration_detection=False,
        enable_rate_limiting=False,
        enable_ip_banning=True,
        ban_on_hostile_signals=True,
        auto_ban_threshold=2,
        **overrides,
    )


def test_verifier_errors_never_count_toward_a_ban() -> None:
    pipeline, middleware, route_id = build_route_pipeline(
        _ban_config(), lambda d: d.require_auth("bearer", verifier=_raising)
    )

    statuses = [_status(pipeline, route_id, "203.0.113.52") for _ in range(6)]

    assert statuses == [503] * 6
    assert middleware.suspicious_request_counts == {}


def test_a_falsy_verifier_result_stays_401_and_keeps_counting() -> None:
    pipeline, _, route_id = build_route_pipeline(
        _ban_config(), lambda d: d.require_auth("bearer", verifier=lambda r, k: False)
    )

    statuses = [_status(pipeline, route_id, "203.0.113.53") for _ in range(3)]

    assert statuses == [401, 401, 403]


def test_passive_mode_lets_a_verifier_error_through_and_logs_it(
    caplog: pytest.LogCaptureFixture,
) -> None:
    pipeline, _, route_id = build_route_pipeline(
        SecurityConfig(
            enable_redis=False,
            enable_penetration_detection=False,
            enable_rate_limiting=False,
            passive_mode=True,
        ),
        lambda d: d.require_auth("bearer", verifier=_raising),
    )

    with caplog.at_level(logging.ERROR):
        response = send_request(
            pipeline,
            route_id,
            ip="203.0.113.54",
            headers={"authorization": "Bearer token-value"},
        )

    assert response is None
    assert any("RuntimeError" in r.getMessage() for r in caplog.records)


def _leaking(request: Any, credential: str) -> bool:
    raise ValueError(f"bad token {credential}")


@pytest.mark.parametrize(
    ("make", "headers", "secret"),
    [
        (
            lambda d: d.require_auth("bearer", verifier=_leaking),
            {"authorization": "Bearer s3cr3t-bearer-value"},
            "s3cr3t-bearer-value",
        ),
        (
            lambda d: d.api_key_auth("X-Key", verifier=_leaking),
            {"X-Key": "s3cr3t-api-key-value"},
            "s3cr3t-api-key-value",
        ),
    ],
)
def test_the_credential_never_reaches_the_log_through_the_exception(
    make: Any,
    headers: dict[str, str],
    secret: str,
    caplog: pytest.LogCaptureFixture,
) -> None:
    pipeline, _, route_id = build_route_pipeline(_config(), make)

    with caplog.at_level(logging.DEBUG):
        response = send_request(pipeline, route_id, ip="203.0.113.55", headers=headers)

    assert response is not None
    assert response.status_code == 503
    errors = [r for r in caplog.records if r.levelno == logging.ERROR]
    assert len(errors) == 1
    message = errors[0].getMessage()
    assert message.splitlines()[0] == "Authentication verifier raised ValueError"
    assert "Traceback (most recent call last)" in message
    assert secret not in message
    assert "ValueError: bad token [REDACTED]" in message
    assert errors[0].exc_info is None


def test_an_empty_credential_redacts_nothing() -> None:
    from guard_core.sync.core.checks.implementations.authentication import (
        _describe_verifier_error,
    )

    description = _describe_verifier_error(ValueError("kept intact"), "")

    assert description.splitlines()[0] == "Authentication verifier raised ValueError"
    assert "ValueError: kept intact" in description
    assert "[REDACTED]" not in description
