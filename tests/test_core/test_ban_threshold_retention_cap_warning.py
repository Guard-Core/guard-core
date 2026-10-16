import logging
from typing import Any

import pytest

from guard_core.core.checks.helpers import _MAX_RETAINED_EVENTS_PER_CATEGORY
from guard_core.core.initialization.handler_initializer import HandlerInitializer
from guard_core.models import SecurityConfig

CAP = _MAX_RETAINED_EVENTS_PER_CATEGORY


async def _startup_warnings(
    caplog: pytest.LogCaptureFixture, **overrides: Any
) -> list[str]:
    config = SecurityConfig(
        enable_redis=False, enable_penetration_detection=False, **overrides
    )
    with caplog.at_level(logging.WARNING, logger="guard_core.core.initialization"):
        await HandlerInitializer(config).initialize_redis_handlers()
    return [
        record.getMessage()
        for record in caplog.records
        if "can never fire" in record.getMessage()
    ]


async def test_auto_ban_threshold_at_the_cap_does_not_warn(
    caplog: pytest.LogCaptureFixture,
) -> None:
    assert await _startup_warnings(caplog, auto_ban_threshold=CAP) == []


async def test_auto_ban_threshold_above_the_cap_warns_once_naming_the_field(
    caplog: pytest.LogCaptureFixture,
) -> None:
    messages = await _startup_warnings(caplog, auto_ban_threshold=CAP + 1)

    assert len(messages) == 1
    assert "auto_ban_threshold" in messages[0]
    assert str(CAP + 1) in messages[0]
    assert "10,000" in messages[0]


async def test_threat_ban_config_threshold_at_the_cap_does_not_warn(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = {"honeypot": {"threshold": CAP, "duration": 60}}

    assert await _startup_warnings(caplog, threat_ban_config=config) == []


async def test_threat_ban_config_threshold_above_the_cap_warns_naming_the_category(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = {"honeypot": {"threshold": CAP + 1, "duration": 60}}

    messages = await _startup_warnings(caplog, threat_ban_config=config)

    assert len(messages) == 1
    assert "threat_ban_config['honeypot']" in messages[0]
    assert str(CAP + 1) in messages[0]
    assert "10,000" in messages[0]
