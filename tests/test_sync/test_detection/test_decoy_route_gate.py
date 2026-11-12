import logging
from unittest.mock import MagicMock

import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.sync.core.checks.implementations.suspicious_activity import (
    SuspiciousActivityCheck,
)
from tests.test_sync.conftest import SyncMockGuardRequest

PROBE = "/wp-login.php"


def _check(template: str | None) -> SuspiciousActivityCheck:
    middleware = MagicMock()
    middleware.config = SyncSecurityConfig(
        enable_redis=False, enable_penetration_detection=True
    )
    middleware.logger = logging.getLogger("test_decoy_route_gate")
    middleware.suspicious_request_counts = {}
    middleware.event_bus.send_middleware_event = MagicMock()
    middleware.create_error_response = MagicMock(
        side_effect=lambda status_code, default_message: MagicMock(
            status_code=status_code
        )
    )
    middleware.route_resolver.should_bypass_check = lambda *_: False
    middleware.route_template = MagicMock(return_value=template)
    return SuspiciousActivityCheck(middleware)


def _status(template: str | None) -> int | None:
    request = SyncMockGuardRequest(path=PROBE)
    request.state.client_ip = "203.0.113.31"
    request.state.route_config = None
    response = _check(template).check(request)
    return None if response is None else response.status_code


def test_a_decoy_registered_as_a_literal_route_is_clean() -> None:
    assert _status(PROBE) is None


def test_a_probe_the_app_does_not_declare_is_flagged() -> None:
    assert _status(None) == 400


@pytest.mark.parametrize("template", ["/{page:path}", "/<path:filename>", "/{page}"])
def test_a_catch_all_or_converter_route_does_not_declare_the_probe(
    template: str,
) -> None:
    assert _status(template) == 400
