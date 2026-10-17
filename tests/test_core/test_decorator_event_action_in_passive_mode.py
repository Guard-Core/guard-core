from typing import Any

import pytest

from guard_core.models import SecurityConfig
from tests.test_core.conftest import build_route_pipeline, send_request


class _RecordingAgent:
    def __init__(self) -> None:
        self.events: list[Any] = []

    async def send_event(self, event: Any) -> None:
        self.events.append(event)


def _config(**overrides: Any) -> SecurityConfig:
    settings: dict[str, Any] = {
        "enable_redis": False,
        "enable_penetration_detection": False,
        "enable_rate_limiting": False,
        "enable_ip_banning": False,
    }
    settings.update(overrides)
    return SecurityConfig(**settings)


CASES: list[tuple[str, Any, dict[str, str], int]] = [
    (
        "access_denied",
        lambda d: d.require_ip(whitelist=["198.51.100.1"]),
        {},
        1,
    ),
    (
        "authentication_failed",
        lambda d: d.require_auth("bearer", verifier=lambda r, k: False),
        {},
        1,
    ),
    (
        "rate_limited",
        lambda d: d.rate_limit(1, 60),
        {},
        2,
    ),
]


@pytest.mark.parametrize(("event_type", "make", "headers", "requests"), CASES)
@pytest.mark.parametrize(
    ("passive", "action"), [(True, "logged_only"), (False, "blocked")]
)
async def test_the_decorator_event_reports_whether_the_request_was_blocked(
    event_type: str,
    make: Any,
    headers: dict[str, str],
    requests: int,
    passive: bool,
    action: str,
) -> None:
    pipeline, middleware, route_id = build_route_pipeline(
        _config(passive_mode=passive, enable_rate_limiting=True), make
    )
    agent = _RecordingAgent()
    await middleware.guard_decorator.initialize_agent(agent)

    for _ in range(requests):
        await send_request(pipeline, route_id, ip="203.0.113.70", headers=headers)

    matching = [e for e in agent.events if e.event_type == event_type]
    assert [e.action_taken for e in matching] == [action]
