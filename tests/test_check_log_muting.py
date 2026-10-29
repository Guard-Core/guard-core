import logging
from unittest.mock import MagicMock

import pytest

from guard_core._utils.logging_utils import _logs_at_level
from guard_core.models import SecurityConfig
from guard_core.protocols.request_protocol import GuardRequest
from guard_core.protocols.response_protocol import GuardResponse
from guard_core.utils import log_activity


def _make_request() -> MagicMock:
    request = MagicMock()
    request.state.client_ip = None
    request.client_host = "1.2.3.4"
    request.method = "GET"
    request.url_path = "/x"
    request.url_full = "https://test/x"
    request.headers = {}
    return request


async def test_log_activity_emits_when_check_not_muted(
    caplog: pytest.LogCaptureFixture,
) -> None:
    logger = logging.getLogger("guard_core.test.check_not_muted")
    with caplog.at_level(logging.WARNING, logger=logger.name):
        await log_activity(
            _make_request(),
            logger,
            log_type="request",
            check_name="rate_limit",
            muted_check_logs=frozenset({"suspicious_activity"}),
        )
    assert any("1.2.3.4" in r.getMessage() for r in caplog.records)


async def test_log_activity_skips_when_check_muted(
    caplog: pytest.LogCaptureFixture,
) -> None:
    logger = logging.getLogger("guard_core.test.check_muted")
    with caplog.at_level(logging.WARNING, logger=logger.name):
        await log_activity(
            _make_request(),
            logger,
            log_type="request",
            check_name="rate_limit",
            muted_check_logs=frozenset({"rate_limit"}),
        )
    assert not [r for r in caplog.records if r.name == logger.name]


async def test_log_activity_no_check_name_never_mutes(
    caplog: pytest.LogCaptureFixture,
) -> None:
    logger = logging.getLogger("guard_core.test.no_check_name")
    with caplog.at_level(logging.WARNING, logger=logger.name):
        await log_activity(
            _make_request(),
            logger,
            log_type="request",
            muted_check_logs=frozenset({"rate_limit"}),
        )
    assert any("1.2.3.4" in r.getMessage() for r in caplog.records)


async def test_security_check_log_if_allowed_respects_config(
    caplog: pytest.LogCaptureFixture,
) -> None:
    from guard_core.core.checks.base import SecurityCheck

    class _Check(SecurityCheck):
        @property
        def check_name(self) -> str:
            return "suspicious_activity"

        async def check(self, request: GuardRequest) -> GuardResponse | None:
            return None

    middleware = MagicMock()
    middleware.config = SecurityConfig(muted_check_logs={"suspicious_activity"})
    middleware.logger = logging.getLogger("guard_core.test.muted_check")
    check = _Check(middleware)

    with caplog.at_level(logging.WARNING, logger=middleware.logger.name):
        await check.log_if_allowed(
            _make_request(),
            log_type="suspicious",
            reason="test",
            level="WARNING",
        )
    assert not [r for r in caplog.records if r.name == middleware.logger.name]


async def test_security_check_log_if_allowed_emits_when_not_muted(
    caplog: pytest.LogCaptureFixture,
) -> None:
    from guard_core.core.checks.base import SecurityCheck

    class _Check(SecurityCheck):
        @property
        def check_name(self) -> str:
            return "authentication"

        async def check(self, request: GuardRequest) -> GuardResponse | None:
            return None

    middleware = MagicMock()
    middleware.config = SecurityConfig(muted_check_logs={"rate_limit"})
    middleware.logger = logging.getLogger("guard_core.test.unmuted_check")
    check = _Check(middleware)

    with caplog.at_level(logging.WARNING, logger=middleware.logger.name):
        await check.log_if_allowed(
            _make_request(),
            log_type="request",
            reason="test",
            level="WARNING",
        )
    records = [r for r in caplog.records if r.name == middleware.logger.name]
    assert records


async def test_log_activity_builds_no_message_when_its_level_is_off(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    logger = logging.getLogger("guard_core.test.level_off")
    logger.setLevel(logging.CRITICAL)
    redactions: list[object] = []
    monkeypatch.setattr(
        "guard_core._utils.request_logging._extract_request_context",
        lambda *args: redactions.append(args),
    )
    await log_activity(_make_request(), logger, log_type="request", level="WARNING")
    assert redactions == []


def test_an_unknown_level_name_is_never_enabled() -> None:
    logger = logging.getLogger("guard_core.test.level_unknown")
    logger.setLevel(logging.DEBUG)
    assert not _logs_at_level(logger, "NOTICE")
    assert _logs_at_level(logger, "ERROR")
