from unittest.mock import Mock

import pytest

from guard_core.sync.core.checks import build_default_pipeline
from tests.test_sync.test_core.conftest import (
    fully_enabled_config,
    fully_enabled_route_config,
    middleware_for,
)


@pytest.fixture
def mock_middleware() -> Mock:
    return middleware_for(
        fully_enabled_config(), route_configs=(fully_enabled_route_config(),)
    )


def test_default_pipeline_contains_all_checks_in_canonical_order(
    mock_middleware: Mock,
) -> None:
    pipeline = build_default_pipeline(mock_middleware)
    assert pipeline.get_check_names() == [
        "route_config",
        "emergency_mode",
        "https_enforcement",
        "request_logging",
        "request_size_content",
        "cloud_ip_refresh",
        "ip_security",
        "cloud_provider",
        "user_agent",
        "rate_limit",
        "required_headers",
        "authentication",
        "referrer",
        "custom_validators",
        "time_window",
        "suspicious_activity",
        "custom_request",
    ]


def test_default_pipeline_builds_fresh_check_instances_per_call(
    mock_middleware: Mock,
) -> None:
    first = build_default_pipeline(mock_middleware)
    second = build_default_pipeline(mock_middleware)
    assert first.checks[0] is not second.checks[0]
