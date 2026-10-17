from typing import Any

import pytest

from guard_core.models import SecurityConfig
from guard_core.sync.core.checks.implementations.authentication import (
    AuthenticationCheck,
)
from guard_core.sync.decorators.route_config import RouteConfig
from tests.test_sync.conftest import SyncMockGuardRequest
from tests.test_sync.test_core.conftest import (
    build_middleware,
    build_route_pipeline,
    send_request,
)


class _RecordingAgent:
    def __init__(self) -> None:
        self.events: list[Any] = []

    def send_event(self, event: Any) -> None:
        self.events.append(event)


def _config() -> SecurityConfig:
    return SecurityConfig(
        enable_redis=False,
        enable_penetration_detection=False,
        enable_rate_limiting=False,
    )


def _raising(request: Any, credential: str) -> bool:
    raise RuntimeError("down")


SCENARIOS = [
    (
        lambda d: d.require_auth("bearer", verifier=lambda r, k: True),
        {},
        ("Missing or invalid Bearer token", "bearer", "require_auth"),
    ),
    (
        lambda d: d.require_auth("bearer", verifier=lambda r, k: False),
        {"authorization": "Bearer t"},
        ("Authentication failed", "bearer", "require_auth"),
    ),
    (
        lambda d: d.require_auth("bearer", verifier=_raising),
        {"authorization": "Bearer t"},
        ("Authentication error", "bearer", "require_auth"),
    ),
    (
        lambda d: d.require_auth("bearer"),
        {"authorization": "Bearer t"},
        ("No auth verifier configured", "bearer", "require_auth"),
    ),
    (
        lambda d: d.api_key_auth("X-Key", verifier=lambda r, k: True),
        {},
        ("Missing API key", "api_key", "api_key_required"),
    ),
    (
        lambda d: d.api_key_auth("X-Key", verifier=lambda r, k: False),
        {"X-Key": "k"},
        ("Authentication failed", "api_key", "api_key_required"),
    ),
    (
        lambda d: d.require_authorization_header("bearer"),
        {},
        ("Missing or invalid Bearer token", "bearer", "authorization_header"),
    ),
]


@pytest.mark.parametrize(("make", "headers", "expected"), SCENARIOS)
def test_the_failure_event_names_the_reason_the_type_and_the_violation(
    make: Any, headers: dict[str, str], expected: tuple[str, str, str]
) -> None:
    reason, auth_type, violation_type = expected
    pipeline, middleware, route_id = build_route_pipeline(_config(), make)
    agent = _RecordingAgent()
    middleware.guard_decorator.initialize_agent(agent)

    send_request(pipeline, route_id, ip="203.0.113.140", headers=headers)

    assert len(agent.events) == 1
    event = agent.events[0]
    assert event.reason == reason
    assert event.metadata["auth_type"] == auth_type
    assert event.metadata["violation_type"] == violation_type


def test_a_verifier_error_answers_the_service_unavailable_body() -> None:
    pipeline, _, route_id = build_route_pipeline(
        _config(), lambda d: d.require_auth("bearer", verifier=_raising)
    )

    response = send_request(
        pipeline,
        route_id,
        ip="203.0.113.141",
        headers={"authorization": "Bearer t"},
    )

    assert response is not None
    assert response.body == b"Authentication service unavailable"


def test_a_route_without_credentials_to_verify_sets_no_principal() -> None:
    config = _config()
    pipeline, middleware, _ = build_route_pipeline(
        config, lambda d: d.rate_limit(5, 60)
    )
    check = AuthenticationCheck(build_middleware(config, middleware.guard_decorator))
    request = SyncMockGuardRequest(path="/x", client_host="203.0.113.142")
    request.state.route_config = RouteConfig()

    assert check.check(request) is None
    assert request.state.auth_principal is None


def test_a_stacked_route_reports_each_failure_with_its_own_auth_type() -> None:
    pipeline, middleware, route_id = build_route_pipeline(
        _config(),
        lambda d: d.require_auth("bearer", verifier=lambda r, k: True),
        lambda d: d.api_key_auth("X-Key", verifier=lambda r, k: False),
    )
    agent = _RecordingAgent()
    middleware.guard_decorator.initialize_agent(agent)

    send_request(
        pipeline,
        route_id,
        ip="203.0.113.143",
        headers={"authorization": "Bearer t", "X-Key": "wrong"},
    )

    assert [e.metadata["auth_type"] for e in agent.events] == ["api_key"]
