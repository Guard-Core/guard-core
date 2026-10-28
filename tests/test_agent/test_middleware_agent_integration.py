from collections.abc import Awaitable, Callable
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from guard_core.core.checks.implementations.https_enforcement import (
    HttpsEnforcementCheck,
)
from guard_core.core.checks.pipeline import SecurityCheckPipeline
from guard_core.core.events.event_types import EVENT_HTTPS_ENFORCED
from guard_core.core.initialization.handler_initializer import HandlerInitializer
from guard_core.models import SecurityConfig
from guard_core.protocols.agent_protocol import DynamicRulesProtocol, JsonValue
from guard_core.protocols.redis_protocol import RedisHandlerProtocol
from tests.conftest import MockGuardRequest


class _RecordingAgent:
    """An agent transport that keeps what the engine hands it, in memory."""

    def __init__(self, fail_on_send: bool = False) -> None:
        self.fail_on_send = fail_on_send
        self.events: list[Any] = []
        self.started = 0
        self.stopped = 0

    async def initialize_redis(self, redis_handler: RedisHandlerProtocol) -> None:
        return None

    async def send_event(self, event: object) -> None:
        if self.fail_on_send:
            raise ConnectionError("the collector is unreachable")
        self.events.append(event)

    async def send_metric(self, metric: object) -> None:
        return None

    async def start(self) -> None:
        self.started += 1

    async def stop(self) -> None:
        self.stopped += 1

    async def flush_buffer(self) -> None:
        return None

    async def get_dynamic_rules(self) -> DynamicRulesProtocol | None:
        return None

    async def health_check(self) -> bool:
        return True

    def get_stats(self) -> dict[str, JsonValue]:
        return {}


class _Wiring:
    """What an adapter builds: the initializer, the event bus and a middleware."""

    def __init__(self, agent: _RecordingAgent, config: SecurityConfig) -> None:
        self.config = config
        self.initializer = HandlerInitializer(config, agent_handler=agent)
        self.middleware = MagicMock()
        self.middleware.config = config
        self.middleware.response_factory.create_https_redirect = AsyncMock(
            return_value=SimpleNamespace(status_code=301, headers={})
        )

    async def start(self) -> SecurityCheckPipeline:
        await self.initializer.initialize_agent_integrations()
        self.middleware.event_bus = self.initializer.build_event_bus()
        return SecurityCheckPipeline([HttpsEnforcementCheck(self.middleware)])


Wire = Callable[..., Awaitable[SecurityCheckPipeline]]


@pytest.fixture
def agent() -> _RecordingAgent:
    return _RecordingAgent()


@pytest.fixture
async def wire(agent: _RecordingAgent) -> Any:
    wirings: list[_Wiring] = []

    async def build(**config: Any) -> SecurityCheckPipeline:
        wiring = _Wiring(
            agent,
            SecurityConfig(
                **{
                    "enable_redis": False,
                    "enforce_https": True,
                    "agent_enable_events": True,
                    **config,
                }
            ),
        )
        wirings.append(wiring)
        return await wiring.start()

    yield build
    for wiring in wirings:
        await wiring.initializer.shutdown_agent_integrations()


def _request(scheme: str = "http") -> MockGuardRequest:
    request = MockGuardRequest(path="/account", method="POST", scheme=scheme)
    request.state.client_ip = "203.0.113.9"
    return request


async def test_the_agent_is_started_with_the_engine_and_stopped_with_it(
    agent: _RecordingAgent,
) -> None:
    wiring = _Wiring(agent, SecurityConfig(enable_redis=False))
    await wiring.start()
    assert agent.started == 1
    assert agent.stopped == 0

    await wiring.initializer.shutdown_agent_integrations()

    assert agent.stopped == 1


async def test_a_request_the_pipeline_redirects_reaches_the_agent_as_an_event(
    wire: Wire, agent: _RecordingAgent
) -> None:
    pipeline = await wire()

    response = await pipeline.execute(_request())

    assert response is not None
    assert response.status_code == 301
    [event] = agent.events
    assert event.event_type == EVENT_HTTPS_ENFORCED
    assert event.action_taken == "https_redirect"
    assert event.method == "POST"
    assert event.ip_address == "203.0.113.9"
    assert event.endpoint == "/account"
    assert event.metadata["original_scheme"] == "http"


async def test_passive_mode_lets_the_request_through_and_still_reports_it(
    wire: Wire, agent: _RecordingAgent
) -> None:
    pipeline = await wire(passive_mode=True)

    response = await pipeline.execute(_request())

    assert response is None
    assert [event.event_type for event in agent.events] == [EVENT_HTTPS_ENFORCED]


async def test_a_secure_request_sends_the_agent_nothing(
    wire: Wire, agent: _RecordingAgent
) -> None:
    pipeline = await wire()

    assert await pipeline.execute(_request("https")) is None
    assert agent.events == []


async def test_agent_events_off_keeps_the_agent_silent_but_the_block_stays(
    wire: Wire, agent: _RecordingAgent
) -> None:
    pipeline = await wire(agent_enable_events=False)

    response = await pipeline.execute(_request())

    assert response is not None
    assert response.status_code == 301
    assert agent.events == []


async def test_a_muted_event_type_is_not_handed_to_the_agent(
    wire: Wire, agent: _RecordingAgent
) -> None:
    pipeline = await wire(muted_event_types={EVENT_HTTPS_ENFORCED})

    response = await pipeline.execute(_request())

    assert response is not None
    assert agent.events == []


async def test_an_unreachable_collector_never_fails_the_request(
    wire: Wire, agent: _RecordingAgent
) -> None:
    agent.fail_on_send = True
    pipeline = await wire()

    response = await pipeline.execute(_request())

    assert response is not None
    assert response.status_code == 301
    assert agent.events == []
