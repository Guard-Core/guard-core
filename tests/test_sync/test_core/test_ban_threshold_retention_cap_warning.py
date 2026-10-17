import logging
import warnings
from typing import Any

import pytest

from guard_core.models import SecurityConfig
from guard_core.sync.core.checks.helpers import _MAX_RETAINED_EVENTS_PER_CATEGORY
from guard_core.sync.core.initialization.handler_initializer import HandlerInitializer

CAP = _MAX_RETAINED_EVENTS_PER_CATEGORY


def _initialize(**overrides: Any) -> None:
    config = SecurityConfig(
        enable_redis=False, enable_penetration_detection=False, **overrides
    )
    HandlerInitializer(config).initialize_redis_handlers()


def _startup_warnings(caplog: pytest.LogCaptureFixture, **overrides: Any) -> list[str]:
    with caplog.at_level(logging.WARNING, logger="guard_core"):
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            _initialize(**overrides)
    messages = [
        str(item.message) for item in caught if "can never fire" in str(item.message)
    ]
    logged = [
        record.getMessage()
        for record in caplog.records
        if "can never fire" in record.getMessage()
    ]
    assert logged == messages
    return messages


def test_auto_ban_threshold_at_the_cap_does_not_warn(
    caplog: pytest.LogCaptureFixture,
) -> None:
    assert _startup_warnings(caplog, auto_ban_threshold=CAP) == []


def test_auto_ban_threshold_above_the_cap_warns_once_naming_the_field(
    caplog: pytest.LogCaptureFixture,
) -> None:
    messages = _startup_warnings(caplog, auto_ban_threshold=CAP + 1)

    assert len(messages) == 1
    assert "auto_ban_threshold" in messages[0]
    assert str(CAP + 1) in messages[0]
    assert "10,000" in messages[0]
    assert "fail_on_misconfiguration is not set" in messages[0]


def test_threat_ban_config_threshold_at_the_cap_does_not_warn(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = {"honeypot": {"threshold": CAP, "duration": 60}}

    assert _startup_warnings(caplog, threat_ban_config=config) == []


def test_threat_ban_config_threshold_above_the_cap_warns_naming_the_category(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = {"honeypot": {"threshold": CAP + 1, "duration": 60}}

    messages = _startup_warnings(caplog, threat_ban_config=config)

    assert len(messages) == 1
    assert "threat_ban_config['honeypot']" in messages[0]
    assert str(CAP + 1) in messages[0]
    assert "10,000" in messages[0]


def test_flag_true_makes_an_unreachable_auto_ban_threshold_fatal() -> None:
    with pytest.raises(ValueError, match="auto_ban_threshold") as caught:
        _initialize(fail_on_misconfiguration=True, auto_ban_threshold=CAP + 1)

    assert "can never fire" in str(caught.value)


def test_flag_true_makes_an_unreachable_category_threshold_fatal() -> None:
    config = {"sqli": {"threshold": CAP + 1, "duration": 60}}

    with pytest.raises(ValueError, match=r"threat_ban_config\['sqli'\]"):
        _initialize(fail_on_misconfiguration=True, threat_ban_config=config)


def test_flag_true_accepts_thresholds_at_the_cap() -> None:
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        _initialize(fail_on_misconfiguration=True, auto_ban_threshold=CAP)


def test_flag_false_warns_without_the_not_set_part(
    caplog: pytest.LogCaptureFixture,
) -> None:
    messages = _startup_warnings(
        caplog, fail_on_misconfiguration=False, auto_ban_threshold=CAP + 1
    )

    assert len(messages) == 1
    assert "is not set" not in messages[0]
    assert "fail_on_misconfiguration=False keeps starting" in messages[0]
