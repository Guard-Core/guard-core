"""Each app decodes its own clients with its own nat64_prefixes (LEDGER 6.294).

Two apps in one process used to share one prefix table: the app that started last
decided the embedded-IPv4 identity of every request, and one once-a-minute
warning hid the other app's.
"""

import logging

import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.sync.core.checks.factory import build_default_pipeline
from guard_core.sync.core.initialization.handler_initializer import HandlerInitializer
from guard_core.sync.decorators import SecurityDecorator
from guard_core.sync.utils import extract_client_ip
from tests.test_sync.conftest import SyncMockGuardRequest
from tests.test_sync.test_core.conftest import build_middleware

PUBLIC_V4 = "8.8.8.8"
PREFIX_OF_APP_A = "2001:db8:64::/96"
CLIENT_OF_APP_A = "2001:db8:64::808:808"


def _config(**settings: object) -> SyncSecurityConfig:
    return SyncSecurityConfig(
        enable_redis=False,
        enable_penetration_detection=False,
        enable_rate_limiting=False,
        **settings,
    )


def _client_of(config: SyncSecurityConfig, client_host: str) -> str:
    return extract_client_ip(
        SyncMockGuardRequest(path="/x", client_host=client_host), config
    )


def _status(config: SyncSecurityConfig, client_host: str) -> int | None:
    middleware = build_middleware(config, SecurityDecorator(config))
    pipeline = build_default_pipeline(middleware)
    response = pipeline.execute(
        SyncMockGuardRequest(path="/x", client_host=client_host)
    )
    return None if response is None else response.status_code


def test_a_second_app_starting_does_not_turn_off_the_first_apps_decoding() -> None:
    app_a = _config(nat64_prefixes=[PREFIX_OF_APP_A])
    app_b = _config()

    HandlerInitializer(config=app_a).initialize_redis_handlers()
    assert _client_of(app_a, CLIENT_OF_APP_A) == PUBLIC_V4
    HandlerInitializer(config=app_b).initialize_redis_handlers()

    assert _client_of(app_a, CLIENT_OF_APP_A) == PUBLIC_V4
    assert _client_of(app_b, CLIENT_OF_APP_A) == CLIENT_OF_APP_A


def test_each_app_decodes_its_own_clients_through_the_pipeline() -> None:
    app_a = _config(nat64_prefixes=[PREFIX_OF_APP_A], blacklist=[PUBLIC_V4])
    app_b = _config(blacklist=[PUBLIC_V4])
    HandlerInitializer(config=app_a).initialize_redis_handlers()
    HandlerInitializer(config=app_b).initialize_redis_handlers()

    assert _status(app_a, CLIENT_OF_APP_A) == 403
    assert _status(app_b, CLIENT_OF_APP_A) is None


def test_each_app_logs_its_own_non_global_embedded_warning(
    caplog: pytest.LogCaptureFixture,
) -> None:
    app_a = _config()
    app_b = _config()
    HandlerInitializer(config=app_a).initialize_redis_handlers()
    HandlerInitializer(config=app_b).initialize_redis_handlers()

    with caplog.at_level(logging.WARNING, logger="guard_core"):
        for config in (app_a, app_a, app_b):
            _client_of(config, "64:ff9b::a00:5")

    assert len([r for r in caplog.records if "NAT64" in r.getMessage()]) == 2
