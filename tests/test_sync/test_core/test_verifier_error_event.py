import logging
from typing import Any

import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.sync.core.events.event_types import EventFilter
from guard_core.sync.core.events.middleware_events import SecurityEventBus
from tests.test_sync.test_core.conftest import build_route_pipeline, send_request

_REQUESTS = 5


class _RecordingAgent:
    def __init__(self) -> None:
        self.events: list[Any] = []

    def send_event(self, event: Any) -> None:
        self.events.append(event)

    def initialize_redis(self, redis_handler: Any) -> None:
        return None


def _config(**overrides: Any) -> SyncSecurityConfig:
    return SyncSecurityConfig(
        enable_redis=False,
        enable_penetration_detection=False,
        enable_rate_limiting=False,
        enable_ip_banning=True,
        ban_on_hostile_signals=True,
        auto_ban_threshold=2,
        **overrides,
    )


def _raising(request: Any, credential: str) -> bool:
    raise RuntimeError(f"auth backend down for {credential}")


def _wired(config: SyncSecurityConfig, make: Any) -> tuple[Any, Any, str, Any]:
    pipeline, middleware, route_id = build_route_pipeline(config, make)
    agent = _RecordingAgent()
    middleware.guard_decorator.initialize_agent(agent)
    middleware.agent_handler = agent
    middleware.event_bus = SecurityEventBus(
        agent_handler=agent, config=config, event_filter=EventFilter()
    )
    return pipeline, middleware, route_id, agent


@pytest.mark.parametrize(
    ("make", "headers", "secret", "auth_type", "violation_type"),
    [
        (
            lambda d: d.require_auth("bearer", verifier=_raising),
            {"authorization": "Bearer s3cr3t-bearer"},
            "s3cr3t-bearer",
            "bearer",
            "require_auth",
        ),
        (
            lambda d: d.api_key_auth("X-Key", verifier=_raising),
            {"X-Key": "s3cr3t-key"},
            "s3cr3t-key",
            "api_key",
            "api_key_required",
        ),
    ],
)
def test_a_verifier_outage_is_reported_as_a_verifier_error_not_an_attack(
    make: Any,
    headers: dict[str, str],
    secret: str,
    auth_type: str,
    violation_type: str,
    caplog: pytest.LogCaptureFixture,
) -> None:
    pipeline, middleware, route_id, agent = _wired(_config(), make)

    with caplog.at_level(logging.DEBUG):
        statuses = []
        for _ in range(_REQUESTS):
            response = send_request(
                pipeline, route_id, ip="203.0.113.70", headers=headers
            )
            assert response is not None
            statuses.append(response.status_code)

    assert statuses == [503] * _REQUESTS
    errors = [r for r in caplog.records if r.levelno == logging.ERROR]
    assert len(errors) == _REQUESTS
    assert all(secret not in r.getMessage() for r in caplog.records)
    assert [
        r for r in caplog.records if "Authentication failure" in r.getMessage()
    ] == []
    assert middleware.suspicious_request_counts == {}
    kinds = [event.event_type for event in agent.events]
    assert kinds == ["auth_verifier_error"] * _REQUESTS
    event = agent.events[0]
    assert event.action_taken == "request_blocked"
    assert event.reason == "Authentication error"
    assert event.metadata["auth_type"] == auth_type
    assert event.metadata["violation_type"] == violation_type
    assert secret not in repr(event)


def test_a_verifier_error_in_passive_mode_is_logged_only() -> None:
    pipeline, _, route_id, agent = _wired(
        _config(passive_mode=True),
        lambda d: d.require_auth("bearer", verifier=_raising),
    )

    response = send_request(
        pipeline,
        route_id,
        ip="203.0.113.71",
        headers={"authorization": "Bearer token-value"},
    )

    assert response is None
    assert [e.event_type for e in agent.events] == ["auth_verifier_error"]
    assert agent.events[0].action_taken == "logged_only"


def test_a_falsy_verifier_result_still_reports_an_authentication_failure(
    caplog: pytest.LogCaptureFixture,
) -> None:
    pipeline, _, route_id, agent = _wired(
        _config(), lambda d: d.require_auth("bearer", verifier=lambda r, k: False)
    )

    with caplog.at_level(logging.WARNING):
        response = send_request(
            pipeline,
            route_id,
            ip="203.0.113.72",
            headers={"authorization": "Bearer token-value"},
        )

    assert response is not None
    assert response.status_code == 401
    assert [e.event_type for e in agent.events] == ["authentication_failed"]
    assert any("Authentication failure" in r.getMessage() for r in caplog.records)
