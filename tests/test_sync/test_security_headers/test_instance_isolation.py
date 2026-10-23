from unittest.mock import MagicMock

from guard_core.models import SyncSecurityConfig
from guard_core.sync.core.events.metrics import MetricsCollector
from guard_core.sync.core.responses.context import ResponseContext
from guard_core.sync.core.responses.factory import ErrorResponseFactory
from guard_core.sync.handlers.security_headers_handler import (
    SecurityHeadersManager,
    security_headers_manager,
)
from tests.test_sync.conftest import MockGuardResponse, MockGuardResponseFactory


def _factory(
    config: SyncSecurityConfig, agent: object | None = None
) -> ErrorResponseFactory:
    metrics = MagicMock(spec=MetricsCollector)
    metrics.collect_request_metrics = MagicMock()
    return ErrorResponseFactory(
        ResponseContext(
            config=config,
            logger=MagicMock(),
            metrics_collector=metrics,
            response_factory=MockGuardResponseFactory(),
            agent_handler=agent,
        )
    )


def _config(**security_headers: object) -> SyncSecurityConfig:
    return SyncSecurityConfig(
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


def test_two_apps_in_one_process_keep_their_own_header_config() -> None:
    app_a = _factory(_config(frame_options="DENY", csp={"default-src": ["'none'"]}))
    app_b = _factory(_config(frame_options="SAMEORIGIN"))

    response_a = app_a.apply_security_headers(MockGuardResponse("a", 200))
    response_b = app_b.apply_security_headers(MockGuardResponse("b", 200))
    response_a_again = app_a.apply_security_headers(MockGuardResponse("a", 200))

    assert response_a.headers["X-Frame-Options"] == "DENY"
    assert response_b.headers["X-Frame-Options"] == "SAMEORIGIN"
    assert "Content-Security-Policy" not in response_b.headers
    assert response_a_again.headers == response_a.headers


def test_reconfiguring_the_shared_singleton_does_not_reach_an_app() -> None:
    app = _factory(_config(frame_options="DENY"))

    security_headers_manager.configure(enabled=False)
    response = app.apply_security_headers(MockGuardResponse("a", 200))

    assert response.headers["X-Frame-Options"] == "DENY"


def test_each_app_sends_its_headers_event_to_its_own_agent() -> None:
    agent_a, agent_b = MagicMock(), MagicMock()
    agent_a.send_event = MagicMock()
    agent_b.send_event = MagicMock()
    app_a = _factory(_config(frame_options="DENY"), agent_a)
    app_b = _factory(_config(), agent_b)

    app_a.apply_security_headers(MockGuardResponse("a", 200), "/a")
    app_b.apply_security_headers(MockGuardResponse("b", 200), "/b")

    assert agent_a.send_event.call_count == 1
    assert agent_b.send_event.call_count == 1
