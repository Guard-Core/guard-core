from unittest.mock import MagicMock

import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.sync.core.bypass.context import BypassContext
from guard_core.sync.core.bypass.handler import BypassHandler
from guard_core.sync.decorators.base import RouteConfig
from tests.test_sync.conftest import MockGuardResponse, SyncMockGuardRequest


def _handler(config: SyncSecurityConfig, blocks: list[object]) -> BypassHandler:
    event_bus = MagicMock()
    event_bus.agent_handler = None
    event_bus.send_middleware_event = MagicMock()
    resolver = MagicMock()
    resolver.should_bypass_check = MagicMock(return_value=True)
    factory = MagicMock()
    factory.create_error_response = MagicMock(
        side_effect=lambda status_code, default_message: MockGuardResponse(
            default_message, status_code
        )
    )
    factory.apply_security_headers = MagicMock(side_effect=lambda r, _p: r)
    factory.apply_modifier = MagicMock(side_effect=lambda r, _q: r)
    return BypassHandler(
        BypassContext(
            config=config,
            logger=MagicMock(),
            event_bus=event_bus,
            route_resolver=resolver,
            response_factory=factory,
            validator=MagicMock(),
        )
    )


def _call_next(_request: object) -> MockGuardResponse:
    return MockGuardResponse("ok", 200)


def _route() -> RouteConfig:
    route = RouteConfig()
    route.bypassed_checks = {"all"}
    return route


@pytest.mark.parametrize("passive", [False, True])
def test_a_bypass_all_route_is_locked_down_in_emergency_mode(
    passive: bool,
) -> None:
    blocks: list[object] = []
    config = SyncSecurityConfig(
        emergency_mode=True,
        emergency_whitelist=["10.0.0.1"],
        passive_mode=passive,
        on_block=lambda request, payload: blocks.append(payload),
    )
    handler = _handler(config, blocks)
    request = SyncMockGuardRequest(path="/health", client_host="198.51.100.7")

    response = handler.handle_security_bypass(request, _call_next, _route())

    if passive:
        assert response is not None
        assert response.status_code == 200
        assert len(blocks) == 1
    else:
        assert response is not None
        assert response.status_code == 503
        assert response.headers["Retry-After"] == "60"
        assert len(blocks) == 1


def test_a_whitelisted_client_still_reaches_a_bypass_all_route() -> None:
    config = SyncSecurityConfig(emergency_mode=True, emergency_whitelist=["10.0.0.1"])
    handler = _handler(config, [])
    request = SyncMockGuardRequest(path="/health", client_host="10.0.0.1")

    response = handler.handle_security_bypass(request, _call_next, _route())

    assert response is not None
    assert response.status_code == 200


def test_a_bypass_all_route_is_untouched_without_emergency_mode() -> None:
    handler = _handler(SyncSecurityConfig(), [])
    request = SyncMockGuardRequest(path="/health", client_host="198.51.100.7")

    response = handler.handle_security_bypass(request, _call_next, _route())

    assert response is not None
    assert response.status_code == 200
