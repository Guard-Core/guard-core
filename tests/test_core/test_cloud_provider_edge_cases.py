from typing import Any, cast
from unittest.mock import AsyncMock, Mock, patch

import pytest

from guard_core.core.checks.implementations.cloud_provider import CloudProviderCheck
from guard_core.decorators.base import RouteConfig
from guard_core.models import SecurityConfig


@pytest.fixture
def mock_middleware() -> Mock:
    config = SecurityConfig()
    config.block_cloud_providers = frozenset({"AWS", "GCP"})
    config.passive_mode = False

    middleware = Mock()
    middleware.config = config
    middleware.logger = Mock()
    middleware.event_bus = Mock()
    middleware.event_bus.send_cloud_detection_events = AsyncMock()
    middleware.event_bus.send_middleware_event = AsyncMock()
    middleware.create_error_response = AsyncMock(return_value=Mock(status_code=403))
    middleware.route_resolver = Mock()
    middleware.route_resolver.should_bypass_check = Mock(return_value=False)
    middleware.route_resolver.get_cloud_providers_to_check = Mock(
        return_value=["aws", "gcp"]
    )
    return middleware


@pytest.fixture
def cloud_check(mock_middleware: Mock) -> CloudProviderCheck:
    return CloudProviderCheck(mock_middleware)


@pytest.fixture
def mock_request() -> Mock:
    request = Mock()
    request.state = Mock()
    request.state.client_ip = "1.2.3.4"
    request.state.route_config = None
    request.state.is_whitelisted = False
    return request


async def test_check_no_client_ip(
    cloud_check: CloudProviderCheck, mock_request: Mock
) -> None:
    mock_request.state.client_ip = None

    result = await cloud_check.check(mock_request)
    assert result is None


async def test_check_bypass_clouds_check(
    cloud_check: CloudProviderCheck, mock_request: Mock
) -> None:
    route_config = RouteConfig()
    mock_request.state.route_config = route_config
    mock_resolver = Mock()
    mock_resolver.should_bypass_check = Mock(return_value=True)
    mock_resolver.get_cloud_providers_to_check = Mock(return_value=["aws", "gcp"])
    cast(Any, cloud_check.middleware).route_resolver = mock_resolver

    result = await cloud_check.check(mock_request)
    assert result is None


async def test_check_passive_mode(
    cloud_check: CloudProviderCheck,
    mock_request: Mock,
) -> None:
    cloud_check.config.passive_mode = True

    with patch.object(cloud_check, "cloud_handler") as mock_cloud_handler:
        mock_cloud_handler.is_cloud_ip.return_value = True
        mock_cloud_handler.get_cloud_provider_details.return_value = (
            "AWS",
            "1.2.3.0/24",
        )

        with patch(
            "guard_core.core.checks.implementations.cloud_provider.log_activity"
        ) as mock_log:
            mock_log.return_value = AsyncMock()

            result = await cloud_check.check(mock_request)
            assert result is None


async def test_check_no_cloud_providers_to_check(
    cloud_check: CloudProviderCheck, mock_request: Mock
) -> None:
    mock_resolver2 = Mock()
    mock_resolver2.should_bypass_check = Mock(return_value=False)
    mock_resolver2.get_cloud_providers_to_check = Mock(return_value=None)
    cast(Any, cloud_check.middleware).route_resolver = mock_resolver2

    result = await cloud_check.check(mock_request)
    assert result is None


async def test_check_not_cloud_ip(
    cloud_check: CloudProviderCheck, mock_request: Mock
) -> None:
    with patch.object(cloud_check, "cloud_handler") as mock_cloud_handler:
        mock_cloud_handler.is_cloud_ip.return_value = False

        result = await cloud_check.check(mock_request)
        assert result is None


async def test_check_cloud_ip_active_mode(
    cloud_check: CloudProviderCheck,
    mock_request: Mock,
) -> None:
    cloud_check.config.passive_mode = False

    with patch.object(cloud_check, "cloud_handler") as mock_cloud_handler:
        mock_cloud_handler.is_cloud_ip.return_value = True
        mock_cloud_handler.get_cloud_provider_details.return_value = (
            "AWS",
            "1.2.3.0/24",
        )

        with patch(
            "guard_core.core.checks.implementations.cloud_provider.log_activity"
        ) as mock_log:
            mock_log.return_value = AsyncMock()

            result = await cloud_check.check(mock_request)
            assert result is not None
            assert result.status_code == 403
