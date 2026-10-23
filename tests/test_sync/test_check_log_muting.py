import logging
from unittest.mock import MagicMock

import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.protocols.response_protocol import GuardResponse
from guard_core.sync.protocols.request_protocol import SyncGuardRequest
from guard_core.sync.utils import log_activity


def _make_request() -> MagicMock:
    request = MagicMock()
    request.state.client_ip = None
    request.client_host = "1.2.3.4"
    request.method = "GET"
    request.url_path = "/x"
    request.url_full = "https://test/x"
    request.headers = {}
    return request


def test_log_activity_emits_when_check_not_muted(
    caplog: pytest.LogCaptureFixture,
) -> None:
    logger = logging.getLogger("guard_core.test.check_not_muted")
    with caplog.at_level(logging.WARNING, logger=logger.name):
        log_activity(
            _make_request(),
            logger,
            log_type="request",
            check_name="rate_limit",
            muted_check_logs=frozenset({"suspicious_activity"}),
        )
    assert any("1.2.3.4" in r.getMessage() for r in caplog.records)


def test_log_activity_skips_when_check_muted(
    caplog: pytest.LogCaptureFixture,
) -> None:
    logger = logging.getLogger("guard_core.test.check_muted")
    with caplog.at_level(logging.WARNING, logger=logger.name):
        log_activity(
            _make_request(),
            logger,
            log_type="request",
            check_name="rate_limit",
            muted_check_logs=frozenset({"rate_limit"}),
        )
    assert not [r for r in caplog.records if r.name == logger.name]


def test_log_activity_no_check_name_never_mutes(
    caplog: pytest.LogCaptureFixture,
) -> None:
    logger = logging.getLogger("guard_core.test.no_check_name")
    with caplog.at_level(logging.WARNING, logger=logger.name):
        log_activity(
            _make_request(),
            logger,
            log_type="request",
            muted_check_logs=frozenset({"rate_limit"}),
        )
    assert any("1.2.3.4" in r.getMessage() for r in caplog.records)


def test_security_check_log_if_allowed_respects_config(
    caplog: pytest.LogCaptureFixture,
) -> None:
    from guard_core.sync.core.checks.base import SecurityCheck

    class _Check(SecurityCheck):
        @property
        def check_name(self) -> str:
            return "suspicious_activity"

        def check(self, request: SyncGuardRequest) -> GuardResponse | None:
            return None

    middleware = MagicMock()
    middleware.config = SyncSecurityConfig(muted_check_logs={"suspicious_activity"})
    middleware.logger = logging.getLogger("guard_core.test.muted_check")
    check = _Check(middleware)

    with caplog.at_level(logging.WARNING, logger=middleware.logger.name):
        check.log_if_allowed(
            _make_request(),
            log_type="suspicious",
            reason="test",
            level="WARNING",
        )
    assert not [r for r in caplog.records if r.name == middleware.logger.name]


def test_security_check_log_if_allowed_emits_when_not_muted(
    caplog: pytest.LogCaptureFixture,
) -> None:
    from guard_core.sync.core.checks.base import SecurityCheck

    class _Check(SecurityCheck):
        @property
        def check_name(self) -> str:
            return "authentication"

        def check(self, request: SyncGuardRequest) -> GuardResponse | None:
            return None

    middleware = MagicMock()
    middleware.config = SyncSecurityConfig(muted_check_logs={"rate_limit"})
    middleware.logger = logging.getLogger("guard_core.test.unmuted_check")
    check = _Check(middleware)

    with caplog.at_level(logging.WARNING, logger=middleware.logger.name):
        check.log_if_allowed(
            _make_request(),
            log_type="request",
            reason="test",
            level="WARNING",
        )
    records = [r for r in caplog.records if r.name == middleware.logger.name]
    assert records
