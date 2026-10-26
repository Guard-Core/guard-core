from ipaddress import ip_network
from typing import Any
from unittest.mock import MagicMock, Mock, patch

import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.sync.core.checks.implementations.cloud_provider import (
    CloudProviderCheck,
)
from guard_core.sync.core.events.middleware_events import SecurityEventBus
from guard_core.sync.decorators.base import RouteConfig
from guard_core.sync.handlers.cloud_handler import cloud_handler

BLOCKED_IP = "198.51.100.7"
BLOCKED_NETWORK = "198.51.100.0/24"


def _check_and_agent(passive_mode: bool) -> tuple[CloudProviderCheck, MagicMock]:
    config = SyncSecurityConfig(
        ban_on_hostile_signals=False,
        passive_mode=passive_mode,
        agent_enable_events=True,
    )
    config.block_cloud_providers = frozenset({"AWS"})
    agent = MagicMock()
    middleware = Mock()
    middleware.config = config
    middleware.logger = Mock()
    middleware.event_bus = SecurityEventBus(agent, config)
    middleware.create_error_response = MagicMock(return_value=Mock(status_code=403))
    middleware.route_resolver = Mock()
    middleware.route_resolver.should_bypass_check = Mock(return_value=False)
    middleware.route_resolver.get_cloud_providers_to_check = Mock(return_value=["AWS"])
    return CloudProviderCheck(middleware), agent


def _request(route_config: RouteConfig | None) -> Mock:
    request = Mock()
    request.state = Mock()
    request.state.client_ip = BLOCKED_IP
    request.state.route_config = route_config
    request.state.is_whitelisted = False
    request.state.is_exempt = False
    request.headers = {}
    request.url_path = "/api"
    request.method = "GET"
    return request


def _route_blocking_aws() -> RouteConfig:
    route_config = RouteConfig()
    route_config.block_cloud_providers = {"AWS"}
    return route_config


def _sent_events(route_config: RouteConfig | None, passive_mode: bool) -> list[Any]:
    check, agent = _check_and_agent(passive_mode)
    with (
        patch.dict(cloud_handler.ip_ranges, {"AWS": {ip_network(BLOCKED_NETWORK)}}),
        patch.object(cloud_handler, "agent_handler", agent),
        patch(
            "guard_core.sync.core.checks.implementations.cloud_provider.log_activity",
            new=MagicMock(),
        ),
    ):
        check.check(_request(route_config))
    return [call.args[0] for call in agent.send_event.call_args_list]


@pytest.mark.parametrize("passive_mode", [False, True])
@pytest.mark.parametrize("route_config", [None, _route_blocking_aws()])
def test_cloud_blocked_carries_cloud_blacklist_rule_type(
    route_config: RouteConfig | None, passive_mode: bool
) -> None:
    events = _sent_events(route_config, passive_mode)

    cloud = [e for e in events if e.event_type == "cloud_blocked"]
    assert len(cloud) == 1
    assert cloud[0].rule_type == "cloud_blacklist"
    assert cloud[0].metadata["rule_type"] == "cloud_blacklist"
    assert cloud[0].action_taken == (
        "logged_only" if passive_mode else "request_blocked"
    )


def test_route_cloud_denial_keeps_its_decorator_violation_unchanged() -> None:
    events = _sent_events(_route_blocking_aws(), False)

    violation = [e for e in events if e.event_type == "decorator_violation"]
    assert len(violation) == 1
    assert violation[0].rule_type is None
    assert "rule_type" not in violation[0].metadata
