import logging

import pytest

from guard_core.models import SyncSecurityConfig

LOGGER = "guard_core.models"


def _config(endpoint: str, **extra: object) -> SyncSecurityConfig:
    return SyncSecurityConfig(
        enable_agent=True, agent_api_key="key", agent_endpoint=endpoint, **extra
    )


def test_an_http_endpoint_on_another_host_warns_that_the_key_travels_in_clear(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.WARNING, logger=LOGGER):
        _config("http://api.example.com")

    assert "travel unencrypted" in caplog.text


@pytest.mark.parametrize(
    "endpoint",
    [
        "https://api.example.com",
        "http://localhost:8000",
        "http://127.0.0.1:8000",
        "http://[::1]:8000",
    ],
)
def test_an_https_or_loopback_endpoint_does_not_warn(
    endpoint: str, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.WARNING, logger=LOGGER):
        _config(endpoint)

    assert "travel unencrypted" not in caplog.text


def test_a_disabled_agent_does_not_warn(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.WARNING, logger=LOGGER):
        SyncSecurityConfig(agent_endpoint="http://api.example.com")

    assert "travel unencrypted" not in caplog.text


def test_an_unparseable_endpoint_does_not_raise_from_the_warning() -> None:
    from guard_core._security_config_field_validators import (
        warn_agent_endpoint_in_clear,
    )

    config = SyncSecurityConfig.model_construct(
        enable_agent=True, agent_endpoint="http://[::1"
    )

    warn_agent_endpoint_in_clear(config)
