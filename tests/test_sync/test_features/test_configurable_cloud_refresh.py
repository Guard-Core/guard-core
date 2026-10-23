import ipaddress
import time
from unittest.mock import MagicMock, patch

import pytest
from pydantic import ValidationError

from guard_core.models import SyncSecurityConfig
from guard_core.sync.handlers.cloud_handler import cloud_handler


@pytest.fixture(autouse=True)
def reset_cloud_handler() -> None:
    from guard_core.sync.handlers.cloud_ip_stores import InMemoryCloudIpStore

    cloud_handler.ip_ranges = {"AWS": set(), "GCP": set(), "Azure": set()}
    cloud_handler.last_updated = {"AWS": None, "GCP": None, "Azure": None}
    cloud_handler.redis_handler = None
    cloud_handler.agent_handler = None
    cloud_handler._store = InMemoryCloudIpStore()


def test_config_default_value() -> None:
    config = SyncSecurityConfig(enable_redis=False)
    assert config.cloud_ip_refresh_interval == 3600


def test_config_custom_value() -> None:
    config = SyncSecurityConfig(enable_redis=False, cloud_ip_refresh_interval=120)
    assert config.cloud_ip_refresh_interval == 120


def test_config_rejects_below_minimum() -> None:
    with pytest.raises(ValidationError, match="greater than or equal to 60"):
        SyncSecurityConfig(enable_redis=False, cloud_ip_refresh_interval=30)


def test_config_rejects_above_maximum() -> None:
    with pytest.raises(ValidationError, match="less than or equal to 86400"):
        SyncSecurityConfig(enable_redis=False, cloud_ip_refresh_interval=100000)


def test_config_accepts_boundary_values() -> None:
    low = SyncSecurityConfig(enable_redis=False, cloud_ip_refresh_interval=60)
    assert low.cloud_ip_refresh_interval == 60
    high = SyncSecurityConfig(enable_redis=False, cloud_ip_refresh_interval=86400)
    assert high.cloud_ip_refresh_interval == 86400


def test_cloud_ip_refresh_check_uses_config_value() -> None:
    from guard_core.sync.core.checks.implementations.cloud_ip_refresh import (
        CloudIpRefreshCheck,
    )

    config = SyncSecurityConfig(
        enable_redis=False,
        block_cloud_providers={"AWS"},
        cloud_ip_refresh_interval=120,
    )
    middleware = MagicMock()
    middleware.config = config
    middleware.last_cloud_ip_refresh = time.time() - 130
    middleware.refresh_cloud_ip_ranges = MagicMock()
    middleware.route_resolver.get_cloud_providers_to_check = MagicMock(
        return_value=["AWS"]
    )

    check = CloudIpRefreshCheck(middleware)
    request = MagicMock()
    with patch.object(cloud_handler, "schedule_refresh") as schedule:
        check.check(request)

    schedule.assert_called_once()
    middleware.refresh_cloud_ip_ranges.assert_not_called()


def test_cloud_ip_refresh_check_skips_within_interval() -> None:
    from guard_core.sync.core.checks.implementations.cloud_ip_refresh import (
        CloudIpRefreshCheck,
    )

    config = SyncSecurityConfig(
        enable_redis=False,
        block_cloud_providers={"AWS"},
        cloud_ip_refresh_interval=120,
    )
    middleware = MagicMock()
    middleware.config = config
    middleware.last_cloud_ip_refresh = time.time() - 60
    middleware.refresh_cloud_ip_ranges = MagicMock()
    middleware.route_resolver.get_cloud_providers_to_check = MagicMock(
        return_value=["AWS"]
    )

    check = CloudIpRefreshCheck(middleware)
    request = MagicMock()
    check.check(request)

    middleware.refresh_cloud_ip_ranges.assert_not_called()


def test_refresh_async_passes_ttl_to_redis() -> None:
    from guard_core.sync.handlers.cloud_ip_stores import RedisCloudIpStore

    mock_redis = MagicMock()
    mock_redis.get_key = MagicMock(return_value=None)
    mock_redis.set_key = MagicMock()

    cloud_handler.redis_handler = mock_redis
    cloud_handler._store = RedisCloudIpStore(mock_redis)

    test_ranges = {ipaddress.ip_network("10.0.0.0/8")}
    with patch(
        "guard_core.sync.handlers.cloud_handler.fetch_aws_ip_ranges",
        return_value=test_ranges,
    ):
        cloud_handler.refresh_async({"AWS"}, ttl=7200)

    mock_redis.set_key.assert_called_once()
    call_kwargs = mock_redis.set_key.call_args
    assert call_kwargs.kwargs["ttl"] == 7200


def test_log_range_changes_logs_when_changed(caplog: pytest.LogCaptureFixture) -> None:
    old = {ipaddress.ip_network("10.0.0.0/8")}
    new = {
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("172.16.0.0/12"),
    }

    import logging

    with caplog.at_level(logging.INFO):
        cloud_handler._log_range_changes("AWS", old, new)

    assert "+1 added, -0 removed" in caplog.text


def test_log_range_changes_silent_when_unchanged(
    caplog: pytest.LogCaptureFixture,
) -> None:
    ranges = {ipaddress.ip_network("10.0.0.0/8")}

    import logging

    with caplog.at_level(logging.INFO):
        cloud_handler._log_range_changes("AWS", ranges, ranges)

    assert "Cloud IP range update" not in caplog.text
