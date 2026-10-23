import logging
from typing import Any

import pytest

from guard_core.models import SyncSecurityConfig
from tests.test_sync.test_core.conftest import build_route_pipeline, send_request


class _RecordingAgent:
    def __init__(self) -> None:
        self.events: list[Any] = []

    def send_event(self, event: Any) -> None:
        self.events.append(event)


def _config() -> SyncSecurityConfig:
    return SyncSecurityConfig(
        enable_redis=False,
        enable_penetration_detection=False,
        enable_rate_limiting=False,
    )


@pytest.mark.parametrize(
    ("header", "decorator_type", "violation_type"),
    [
        ("X-API-Key", "authentication", "api_key_required"),
        ("Authorization", "authentication", "required_header"),
        ("X-Tenant", "advanced", "required_header"),
    ],
)
@pytest.mark.parametrize(
    ("sent", "field", "reason"),
    [
        (None, "missing_header", "Missing required header: {header}"),
        (
            "wrong",
            "mismatched_header",
            "Header '{header}' does not match the required value",
        ),
    ],
)
def test_a_header_violation_is_logged_and_reported_with_its_classification(
    header: str,
    decorator_type: str,
    violation_type: str,
    sent: str | None,
    field: str,
    reason: str,
    caplog: pytest.LogCaptureFixture,
) -> None:
    pipeline, middleware, route_id = build_route_pipeline(
        _config(), lambda d: d.require_headers({header: "expected"})
    )
    agent = _RecordingAgent()
    middleware.guard_decorator.initialize_agent(agent)
    headers = {} if sent is None else {header: sent}
    expected_reason = reason.format(header=header)

    with caplog.at_level(logging.WARNING):
        response = send_request(pipeline, route_id, ip="203.0.113.150", headers=headers)

    assert response is not None
    assert response.status_code == 400
    logged = [
        r.getMessage()
        for r in caplog.records
        if r.getMessage().startswith("Suspicious activity detected from 203.0.113.150")
    ]
    assert len(logged) == 1
    assert f"Reason: {expected_reason} - Headers:" in logged[0]
    assert len(agent.events) == 1
    event = agent.events[0]
    assert event.reason == expected_reason
    assert event.metadata["decorator_type"] == decorator_type
    assert event.metadata["violation_type"] == violation_type
    assert event.metadata[field] == header
