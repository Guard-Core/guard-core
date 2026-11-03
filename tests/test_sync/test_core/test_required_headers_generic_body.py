import logging
from typing import Any

import pytest

from guard_core.models import SyncSecurityConfig
from tests.test_sync.test_core.conftest import build_route_pipeline, send_request

SECRET = "s3cret-value"


class _RecordingAgent:
    def __init__(self) -> None:
        self.events: list[Any] = []

    def send_event(self, event: object) -> None:
        self.events.append(event)


def _config() -> SyncSecurityConfig:
    return SyncSecurityConfig(
        enable_redis=False,
        enable_penetration_detection=False,
        enable_rate_limiting=False,
    )


@pytest.mark.parametrize(
    ("headers", "reason"),
    [
        ({}, "Missing required header: X-Internal-Secret"),
        (
            {"X-Internal-Secret": "wrong"},
            "Header 'X-Internal-Secret' does not match the required value",
        ),
    ],
)
def test_the_400_body_does_not_name_the_header_or_confirm_a_value(
    headers: dict[str, str], reason: str, caplog: pytest.LogCaptureFixture
) -> None:
    pipeline, middleware, route_id = build_route_pipeline(
        _config(), lambda d: d.require_headers({"X-Internal-Secret": SECRET})
    )
    agent = _RecordingAgent()
    middleware.guard_decorator.initialize_agent(agent)

    with caplog.at_level(logging.WARNING):
        response = send_request(pipeline, route_id, ip="203.0.113.60", headers=headers)

    assert response is not None
    assert response.status_code == 400
    assert response.body == b"Bad request"
    assert any(reason in record.getMessage() for record in caplog.records)
    assert [event.reason for event in agent.events] == [reason]
