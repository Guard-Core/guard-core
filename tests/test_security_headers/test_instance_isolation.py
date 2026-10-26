from unittest.mock import AsyncMock, MagicMock

from guard_core.core.events.metrics import MetricsCollector
from guard_core.core.responses.context import ResponseContext
from guard_core.core.responses.factory import ErrorResponseFactory
from guard_core.handlers.security_headers_handler import (
    SecurityHeadersManager,
    security_headers_manager,
)
from guard_core.models import SecurityConfig
from guard_core.protocols.agent_protocol import AgentHandlerProtocol
from tests.conftest import MockGuardResponse, MockGuardResponseFactory


def _factory(
    config: SecurityConfig, agent: AgentHandlerProtocol | None = None
) -> ErrorResponseFactory:
    metrics = MagicMock(spec=MetricsCollector)
    metrics.collect_request_metrics = AsyncMock()
    return ErrorResponseFactory(
        ResponseContext(
            config=config,
            logger=MagicMock(),
            metrics_collector=metrics,
            response_factory=MockGuardResponseFactory(),
            agent_handler=agent,
        )
    )


def _config(**security_headers: object) -> SecurityConfig:
    return SecurityConfig(
        enable_redis=False, security_headers={"enabled": True, **security_headers}
    )


def test_each_factory_owns_its_own_manager() -> None:
    first = _factory(_config())
    second = _factory(_config())

    assert first.security_headers_manager is not second.security_headers_manager
    assert first.security_headers_manager is not security_headers_manager
    assert isinstance(first.security_headers_manager, SecurityHeadersManager)


def test_the_module_singleton_is_still_the_shared_default_instance() -> None:
    assert SecurityHeadersManager() is security_headers_manager


async def test_two_apps_in_one_process_keep_their_own_header_config() -> None:
    app_a = _factory(_config(frame_options="DENY", csp={"default-src": ["'none'"]}))
    app_b = _factory(_config(frame_options="SAMEORIGIN"))

    response_a = await app_a.apply_security_headers(MockGuardResponse("a", 200))
    response_b = await app_b.apply_security_headers(MockGuardResponse("b", 200))
    response_a_again = await app_a.apply_security_headers(MockGuardResponse("a", 200))

    assert response_a.headers["X-Frame-Options"] == "DENY"
    assert response_b.headers["X-Frame-Options"] == "SAMEORIGIN"
    assert "Content-Security-Policy" not in response_b.headers
    assert response_a_again.headers == response_a.headers


async def test_reconfiguring_the_shared_singleton_does_not_reach_an_app() -> None:
    app = _factory(_config(frame_options="DENY"))

    security_headers_manager.configure(enabled=False)
    response = await app.apply_security_headers(MockGuardResponse("a", 200))

    assert response.headers["X-Frame-Options"] == "DENY"


async def test_each_app_sends_its_headers_event_to_its_own_agent() -> None:
    agent_a, agent_b = MagicMock(), MagicMock()
    agent_a.send_event = AsyncMock()
    agent_b.send_event = AsyncMock()
    app_a = _factory(_config(frame_options="DENY"), agent_a)
    app_b = _factory(_config(), agent_b)

    await app_a.apply_security_headers(MockGuardResponse("a", 200), "/a")
    await app_b.apply_security_headers(MockGuardResponse("b", 200), "/b")

    assert agent_a.send_event.await_count == 1
    assert agent_b.send_event.await_count == 1
