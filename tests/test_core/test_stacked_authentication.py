from collections.abc import Callable
from typing import Any
from unittest.mock import MagicMock

import pytest

from guard_core.core.checks.pipeline import SecurityCheckPipeline
from guard_core.models import SecurityConfig
from guard_core.protocols.request_protocol import GuardRequest
from tests.test_core.conftest import build_route_pipeline, send_request

CLIENT = "203.0.113.20"
GOOD = {"authorization": "Bearer good-token", "X-API-Key": "good-key"}


class _RecordingAgent:
    def __init__(self) -> None:
        self.events: list[object] = []

    async def send_event(self, event: object) -> None:
        self.events.append(event)


def _config(**overrides: object) -> SecurityConfig:
    settings: dict[str, Any] = {
        "enable_redis": False,
        "enable_penetration_detection": False,
        "enable_rate_limiting": False,
    }
    settings.update(overrides)
    return SecurityConfig(**settings)


def _bearer_verifier(calls: list[str]) -> Callable[[GuardRequest, str], object]:
    def verify(request: GuardRequest, credential: str) -> object:
        calls.append(f"bearer:{credential}")
        return "bearer-principal" if credential == "good-token" else None

    return verify


def _key_verifier(
    calls: list[str], header: str = "X-API-Key"
) -> Callable[[GuardRequest, str], object]:
    def verify(request: GuardRequest, credential: str) -> object:
        calls.append(f"key:{credential}")
        return "key-principal" if credential == "good-key" else None

    return verify


def _stacked(
    calls: list[str], **config: object
) -> tuple[SecurityCheckPipeline, MagicMock, str]:
    return build_route_pipeline(
        _config(**config),
        lambda d: d.require_auth("bearer", verifier=_bearer_verifier(calls)),
        lambda d: d.api_key_auth("X-API-Key", verifier=_key_verifier(calls)),
    )


@pytest.mark.parametrize(
    ("headers", "expected"),
    [
        (GOOD, None),
        ({**GOOD, "X-API-Key": "wrong-key"}, 401),
        ({**GOOD, "authorization": "Bearer wrong-token"}, 401),
        ({"authorization": "Bearer good-token"}, 401),
        ({"X-API-Key": "good-key"}, 401),
        ({}, 401),
    ],
)
async def test_every_credential_on_the_route_must_verify(
    headers: dict[str, str], expected: int | None
) -> None:
    pipeline, _, route_id = _stacked([])

    response = await send_request(pipeline, route_id, ip=CLIENT, headers=headers)

    if expected is None:
        assert response is None
    else:
        assert response is not None
        assert response.status_code == expected


async def test_each_verifier_receives_its_own_credential() -> None:
    calls: list[str] = []
    pipeline, _, route_id = _stacked(calls)

    await send_request(pipeline, route_id, ip=CLIENT, headers=GOOD)

    assert sorted(calls) == ["bearer:good-token", "key:good-key"]


async def test_a_missing_api_key_on_an_api_key_route_is_a_401_not_a_400() -> None:
    pipeline, _, route_id = build_route_pipeline(
        _config(), lambda d: d.api_key_auth("X-Custom-Key", verifier=lambda r, k: True)
    )

    response = await send_request(pipeline, route_id, ip=CLIENT, headers={})

    assert response is not None
    assert response.status_code == 401


async def test_a_custom_api_key_header_failure_is_an_authentication_event() -> None:
    pipeline, middleware, route_id = build_route_pipeline(
        _config(), lambda d: d.api_key_auth("X-Custom-Key", verifier=lambda r, k: False)
    )
    agent = _RecordingAgent()
    await middleware.guard_decorator.initialize_agent(agent)

    await send_request(
        pipeline, route_id, ip=CLIENT, headers={"X-Custom-Key": "anything"}
    )

    assert [vars(e)["event_type"] for e in agent.events] == ["authentication_failed"]
    assert vars(agent.events[0])["decorator_type"] == "authentication"


@pytest.mark.parametrize(
    "headers", [{}, {"X-API-Key": "wrong"}, {"X-API-Key": "good-key"}]
)
async def test_passive_mode_reports_one_failure_per_request(
    headers: dict[str, str],
) -> None:
    pipeline, middleware, route_id = build_route_pipeline(
        _config(passive_mode=True),
        lambda d: d.api_key_auth("X-API-Key", verifier=_key_verifier([])),
    )
    agent = _RecordingAgent()
    await middleware.guard_decorator.initialize_agent(agent)

    response = await send_request(pipeline, route_id, ip=CLIENT, headers=headers)

    assert response is None
    expected = 0 if headers.get("X-API-Key") == "good-key" else 1
    assert len(agent.events) == expected


async def test_passive_mode_without_a_verifier_reports_one_failure() -> None:
    pipeline, middleware, route_id = build_route_pipeline(
        _config(passive_mode=True), lambda d: d.api_key_auth("X-API-Key")
    )
    agent = _RecordingAgent()
    await middleware.guard_decorator.initialize_agent(agent)

    await send_request(pipeline, route_id, ip=CLIENT, headers={})

    assert len(agent.events) == 1
