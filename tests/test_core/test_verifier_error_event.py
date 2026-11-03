import logging
from collections.abc import Callable
from typing import Any

import pytest

from guard_core.core.events.event_types import EventFilter
from guard_core.core.events.middleware_events import SecurityEventBus
from guard_core.decorators import SecurityDecorator
from guard_core.models import SecurityConfig
from guard_core.protocols.agent_protocol import JsonValue
from tests.test_core.conftest import build_route_pipeline, send_request

_REQUESTS = 5


class _RecordingAgent:
    def __init__(self) -> None:
        self.events: list[Any] = []

    async def send_event(self, event: object) -> None:
        self.events.append(event)

    async def initialize_redis(self, redis_handler: object) -> None:
        return None

    async def send_metric(self, metric: object) -> None:
        return None

    async def start(self) -> None:
        return None

    async def stop(self) -> None:
        return None

    async def flush_buffer(self) -> None:
        return None

    async def get_dynamic_rules(self) -> None:
        return None

    def get_stats(self) -> dict[str, JsonValue]:
        return {}

    async def health_check(self) -> bool:
        return True


def _config(**overrides: object) -> SecurityConfig:
    return SecurityConfig(
        enable_redis=False,
        enable_penetration_detection=False,
        enable_rate_limiting=False,
        enable_ip_banning=True,
        ban_on_hostile_signals=True,
        auto_ban_threshold=2,
        **overrides,
    )


def _raising(request: object, credential: str) -> bool:
    raise RuntimeError(f"auth backend down for {credential}")


async def _wired(
    config: SecurityConfig, make: Callable[[SecurityDecorator], object]
) -> tuple[Any, Any, str, Any]:
    pipeline, middleware, route_id = build_route_pipeline(config, make)
    agent = _RecordingAgent()
    await middleware.guard_decorator.initialize_agent(agent)
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
async def test_a_verifier_outage_is_reported_as_a_verifier_error_not_an_attack(
    make: Callable[[SecurityDecorator], object],
    headers: dict[str, str],
    secret: str,
    auth_type: str,
    violation_type: str,
    caplog: pytest.LogCaptureFixture,
) -> None:
    pipeline, middleware, route_id, agent = await _wired(_config(), make)

    with caplog.at_level(logging.DEBUG):
        statuses = []
        for _ in range(_REQUESTS):
            response = await send_request(
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


async def test_a_verifier_error_in_passive_mode_is_logged_only() -> None:
    pipeline, _, route_id, agent = await _wired(
        _config(passive_mode=True),
        lambda d: d.require_auth("bearer", verifier=_raising),
    )

    response = await send_request(
        pipeline,
        route_id,
        ip="203.0.113.71",
        headers={"authorization": "Bearer token-value"},
    )

    assert response is None
    assert [e.event_type for e in agent.events] == ["auth_verifier_error"]
    assert agent.events[0].action_taken == "logged_only"


async def test_a_falsy_verifier_result_still_reports_an_authentication_failure(
    caplog: pytest.LogCaptureFixture,
) -> None:
    pipeline, _, route_id, agent = await _wired(
        _config(), lambda d: d.require_auth("bearer", verifier=lambda r, k: False)
    )

    with caplog.at_level(logging.WARNING):
        response = await send_request(
            pipeline,
            route_id,
            ip="203.0.113.72",
            headers={"authorization": "Bearer token-value"},
        )

    assert response is not None
    assert response.status_code == 401
    assert [e.event_type for e in agent.events] == ["authentication_failed"]
    assert any("Authentication failure" in r.getMessage() for r in caplog.records)
