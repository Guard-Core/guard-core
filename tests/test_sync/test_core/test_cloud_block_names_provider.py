from collections.abc import Callable
from ipaddress import ip_network
from unittest.mock import MagicMock, Mock, patch

import pytest

from guard_core.models import SecurityConfig
from guard_core.sync.core.checks.implementations.cloud_provider import (
    CloudProviderCheck,
)
from guard_core.sync.decorators.base import RouteConfig
from guard_core.sync.handlers.cloud_handler import cloud_handler

BLOCKED_IP = "198.51.100.7"
BLOCKED_NETWORK = "198.51.100.0/24"


@pytest.fixture
def cloud_check() -> CloudProviderCheck:
    config = SecurityConfig()
    config.block_cloud_providers = frozenset({"AWS"})
    middleware = Mock()
    middleware.config = config
    middleware.logger = Mock()
    middleware.event_bus = Mock()
    middleware.event_bus.send_cloud_detection_events = MagicMock()
    middleware.event_bus.send_middleware_event = MagicMock()
    middleware.create_error_response = MagicMock(return_value=Mock(status_code=403))
    middleware.route_resolver = Mock()
    middleware.route_resolver.should_bypass_check = Mock(return_value=False)
    middleware.route_resolver.get_cloud_providers_to_check = Mock(return_value=["AWS"])
    return CloudProviderCheck(middleware)


def _request(route_config: RouteConfig | None) -> Mock:
    request = Mock()
    request.state = Mock()
    request.state.client_ip = BLOCKED_IP
    request.state.route_config = route_config
    request.state.is_whitelisted = False
    request.state.is_exempt = False
    return request


def _no_route_config() -> RouteConfig | None:
    return None


def _route_blocking_aws() -> RouteConfig | None:
    route_config = RouteConfig()
    route_config.block_cloud_providers = {"AWS"}
    return route_config


@pytest.mark.parametrize(
    "route_config_factory", [_no_route_config, _route_blocking_aws]
)
def test_cloud_block_log_names_provider_and_network(
    cloud_check: CloudProviderCheck,
    route_config_factory: Callable[[], RouteConfig | None],
) -> None:
    route_config = route_config_factory()
    with (
        patch.dict(cloud_handler.ip_ranges, {"AWS": {ip_network(BLOCKED_NETWORK)}}),
        patch(
            "guard_core.sync.core.checks.implementations.cloud_provider.log_activity",
            new=MagicMock(),
        ) as log_activity,
    ):
        response = cloud_check.check(_request(route_config))

    assert response is not None and response.status_code == 403
    reason = log_activity.call_args.kwargs["reason"]
    assert reason == (
        f"Blocked cloud provider IP: {BLOCKED_IP} - "
        f"IP belongs to blocked cloud provider: AWS ({BLOCKED_NETWORK})"
    )
    events = cloud_check.middleware.event_bus.send_cloud_detection_events
    assert events.call_args.kwargs["cloud_details"] == ("AWS", BLOCKED_NETWORK)


def test_global_cloud_block_sends_the_ip_blocked_event_with_provider(
    cloud_check: CloudProviderCheck,
) -> None:
    request = _request(None)
    with (
        patch.dict(cloud_handler.ip_ranges, {"AWS": {ip_network(BLOCKED_NETWORK)}}),
        patch(
            "guard_core.sync.core.checks.implementations.cloud_provider.log_activity",
            new=MagicMock(),
        ),
    ):
        cloud_check.check(request)

    sent = cloud_check.middleware.event_bus.send_middleware_event.call_args_list
    ip_blocked = [c.kwargs for c in sent if c.kwargs["event_type"] == "ip_blocked"]
    assert ip_blocked == [
        {
            "event_type": "ip_blocked",
            "request": request,
            "action_taken": "request_blocked",
            "reason": "IP belongs to blocked cloud provider: AWS",
            "ip_address": BLOCKED_IP,
            "filter_type": "global",
            "cloud_provider": "AWS",
            "network": BLOCKED_NETWORK,
        }
    ]


def test_route_cloud_block_sends_no_ip_blocked_event(
    cloud_check: CloudProviderCheck,
) -> None:
    with (
        patch.dict(cloud_handler.ip_ranges, {"AWS": {ip_network(BLOCKED_NETWORK)}}),
        patch(
            "guard_core.sync.core.checks.implementations.cloud_provider.log_activity",
            new=MagicMock(),
        ),
    ):
        cloud_check.check(_request(_route_blocking_aws()))

    sent = cloud_check.middleware.event_bus.send_middleware_event.call_args_list
    assert [call.kwargs["event_type"] for call in sent] == ["decorator_violation"]
