import logging
import warnings

import pytest

from guard_core.models import SecurityConfig, SyncSecurityConfig


def test_v440_after_validators_keep_their_public_names() -> None:
    validators = SecurityConfig.__pydantic_decorators__.model_validators

    assert {
        "warn_exempt_ips_prefix_zero",
        "warn_empty_enabled_detection_categories",
    } <= set(validators)


def test_risky_setting_warnings_keep_their_order(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with (
        warnings.catch_warnings(),
        caplog.at_level(logging.WARNING, logger="guard_core.models"),
    ):
        warnings.simplefilter("ignore", DeprecationWarning)
        SyncSecurityConfig(
            enable_redis=False,
            exempt_ips=["0.0.0.0/0"],
            enabled_detection_categories=frozenset(),
        )

    starts = [r.getMessage().split(" ", 1)[0] for r in caplog.records]
    v440_warnings = [s for s in starts if s != "ban_on_hostile_signals"]
    assert v440_warnings == ["exempt_ips", "enabled_detection_categories"]
