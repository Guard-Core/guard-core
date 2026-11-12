import logging
import warnings
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from guard_core._misconfiguration import WILDCARD_CORS_CREDENTIALS_PROBLEM
from guard_core.core.events.metrics import MetricsCollector
from guard_core.core.responses.context import ResponseContext
from guard_core.core.responses.factory import ErrorResponseFactory
from guard_core.handlers._security_headers_apply import (
    apply_security_headers_settings,
)
from guard_core.handlers.cors_handler import CorsHandler
from guard_core.handlers.security_headers_handler import SecurityHeadersManager
from guard_core.models import SecurityConfig
from tests.conftest import MockGuardResponse, MockGuardResponseFactory

FIELDS: dict[str, Any] = {
    "enable_cors": True,
    "cors_allow_origins": ["*"],
    "cors_allow_credentials": True,
    "security_headers": {"enabled": True},
    "enable_redis": False,
}
REQUESTS = 5


def _warnings(caplog: pytest.LogCaptureFixture) -> list[logging.LogRecord]:
    return [r for r in caplog.records if r.levelno >= logging.WARNING]


def _factory(
    config: SecurityConfig, manager: SecurityHeadersManager
) -> ErrorResponseFactory:
    metrics = MagicMock(spec=MetricsCollector)
    metrics.collect_request_metrics = AsyncMock()
    return ErrorResponseFactory(
        ResponseContext(
            config=config,
            logger=logging.getLogger("guard_core.core.responses.factory"),
            metrics_collector=metrics,
            response_factory=MockGuardResponseFactory(),
            security_headers_manager=manager,
        )
    )


async def _serve(config: SecurityConfig) -> None:
    manager = SecurityHeadersManager.isolated()
    apply_security_headers_settings(manager, config)
    CorsHandler(config)
    factory = _factory(config, manager)
    for _ in range(REQUESTS):
        await factory.apply_cors_headers(MockGuardResponse(), "https://a.example")


async def test_a_validated_config_reports_the_wildcard_once_over_many_requests(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.DEBUG):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            config = SecurityConfig(fail_on_misconfiguration=False, **FIELDS)
        await _serve(config)

    assert len(_warnings(caplog)) == 1


async def test_requests_add_no_warning_to_a_validated_config(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        config = SecurityConfig(fail_on_misconfiguration=False, **FIELDS)
    manager = SecurityHeadersManager.isolated()
    apply_security_headers_settings(manager, config)
    factory = _factory(config, manager)
    caplog.clear()

    with caplog.at_level(logging.DEBUG):
        for _ in range(REQUESTS):
            await factory.apply_cors_headers(MockGuardResponse(), "https://a.example")

    assert _warnings(caplog) == []


async def test_a_constructed_config_still_gets_the_handlers_warning(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = SecurityConfig.model_construct(fail_on_misconfiguration=False, **FIELDS)

    with caplog.at_level(logging.DEBUG, logger="guard_core.handlers.cors_handler"):
        CorsHandler(config)

    assert len(_warnings(caplog)) == 1


def _config_without_the_pair(*, strict: bool) -> SecurityConfig:
    return SecurityConfig(
        **{**FIELDS, "cors_allow_credentials": False}, fail_on_misconfiguration=strict
    )


async def test_an_assignment_that_adds_the_pair_reports_once_over_many_requests(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = _config_without_the_pair(strict=False)

    with caplog.at_level(logging.DEBUG):
        caplog.clear()
        config.cors_allow_credentials = True
        await _serve(config)

    reports = _warnings(caplog)
    assert len(reports) == 1
    assert WILDCARD_CORS_CREDENTIALS_PROBLEM in reports[0].getMessage()


def test_an_assignment_that_adds_the_pair_raises_under_the_strict_flag() -> None:
    config = _config_without_the_pair(strict=True)

    with pytest.raises(ValueError, match="wildcard origin"):
        config.cors_allow_credentials = True
