import logging
import warnings
from typing import Any

import pytest

from guard_core._misconfiguration import WILDCARD_CORS_CREDENTIALS_PROBLEM
from guard_core.handlers._security_headers_apply import (
    apply_security_headers_settings,
)
from guard_core.handlers.cors_handler import CorsHandler
from guard_core.handlers.security_headers_handler import SecurityHeadersManager
from guard_core.models import SecurityConfig

WILDCARD_WITH_CREDENTIALS: dict[str, Any] = {
    "enable_cors": True,
    "cors_allow_origins": ["*"],
    "cors_allow_credentials": True,
    "security_headers": {"enabled": True},
    "enable_redis": False,
}
HEADERS_LOGGER = "guard_core.handlers.security_headers"
CORS_LOGGER = "guard_core.handlers.cors_handler"


def _wildcard_config() -> SecurityConfig:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        return SecurityConfig(
            fail_on_misconfiguration=False, **WILDCARD_WITH_CREDENTIALS
        )


def _warnings_and_errors(caplog: pytest.LogCaptureFixture) -> list[logging.LogRecord]:
    return [r for r in caplog.records if r.levelno >= logging.WARNING]


def test_the_apply_path_adds_no_second_report_of_the_wildcard_credentials(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.DEBUG):
        config = SecurityConfig(
            fail_on_misconfiguration=False, **WILDCARD_WITH_CREDENTIALS
        )
        caplog.clear()
        apply_security_headers_settings(SecurityHeadersManager.isolated(), config)

    assert _warnings_and_errors(caplog) == []


def test_the_config_reports_the_wildcard_credentials_as_one_warning(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.DEBUG):
        SecurityConfig(fail_on_misconfiguration=False, **WILDCARD_WITH_CREDENTIALS)

    reports = _warnings_and_errors(caplog)
    assert [r.levelno for r in reports] == [logging.WARNING]
    assert WILDCARD_CORS_CREDENTIALS_PROBLEM in reports[0].getMessage()


def test_the_apply_path_still_serves_the_dropped_credentials() -> None:
    config = _wildcard_config()
    manager = SecurityHeadersManager.isolated()

    apply_security_headers_settings(manager, config)

    assert manager.cors_config is not None
    assert manager.cors_config["allow_credentials"] is False


def test_a_direct_configure_logs_the_shared_text_as_one_warning(
    caplog: pytest.LogCaptureFixture,
) -> None:
    manager = SecurityHeadersManager.isolated()

    with caplog.at_level(logging.DEBUG, logger=HEADERS_LOGGER):
        manager.configure(cors_origins=["*"], cors_allow_credentials=True)

    reports = _warnings_and_errors(caplog)
    assert [(r.levelno, r.getMessage()) for r in reports] == [
        (logging.WARNING, WILDCARD_CORS_CREDENTIALS_PROBLEM)
    ]


def test_a_direct_cors_handler_still_logs_its_one_warning(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = _wildcard_config()

    with caplog.at_level(logging.DEBUG, logger=CORS_LOGGER):
        caplog.clear()
        CorsHandler(config)

    reports = _warnings_and_errors(caplog)
    assert [r.levelno for r in reports] == [logging.WARNING]
    assert WILDCARD_CORS_CREDENTIALS_PROBLEM in reports[0].getMessage()
