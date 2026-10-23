import logging

import pytest
from pydantic import Field, ValidationError

from guard_core.models import SecurityConfig, SyncSecurityConfig


def test_unknown_field_logs_warning(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.WARNING, logger="guard_core.models"):
        SyncSecurityConfig(agent_compresion_enabled=False)

    messages = [record.message for record in caplog.records]
    assert any(
        "unknown field 'agent_compresion_enabled'" in message
        and "ignored and had no effect" in message
        for message in messages
    )


def test_unknown_field_with_close_match_suggests_it(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.WARNING, logger="guard_core.models"):
        SyncSecurityConfig(agent_compresion_enabled=False)

    messages = [record.message for record in caplog.records]
    assert any(
        "Did you mean 'agent_compression_enabled'?" in message for message in messages
    )


def test_unknown_field_with_no_close_match_omits_suggestion(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.WARNING, logger="guard_core.models"):
        SyncSecurityConfig(totally_unrelated_nonsense_xyz=1)

    messages = [record.message for record in caplog.records]
    target = next(
        message
        for message in messages
        if "unknown field 'totally_unrelated_nonsense_xyz'" in message
    )
    assert "Did you mean" not in target


def test_unknown_field_is_still_ignored_not_rejected() -> None:
    config = SyncSecurityConfig(agent_compresion_enabled=False)

    assert not hasattr(config, "agent_compresion_enabled")


def test_no_warning_for_known_fields(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.WARNING, logger="guard_core.models"):
        SyncSecurityConfig(rate_limit=5, enable_agent=True, agent_api_key="key")

    unknown_field_records = [
        record.message for record in caplog.records if "unknown field" in record.message
    ]
    assert unknown_field_records == []


def test_non_mapping_input_is_passed_through_to_normal_validation() -> None:
    with pytest.raises(ValidationError):
        SecurityConfig.model_validate(["not", "a", "mapping"])


def test_field_alias_is_not_flagged_as_unknown(
    caplog: pytest.LogCaptureFixture,
) -> None:
    class _ConfigWithAlias(SyncSecurityConfig):
        widget_count: int = Field(default=0, alias="widgetCount")

    with caplog.at_level(logging.WARNING, logger="guard_core.models"):
        config = _ConfigWithAlias(widgetCount=5)

    assert config.widget_count == 5
    unknown_field_records = [
        record.message for record in caplog.records if "unknown field" in record.message
    ]
    assert unknown_field_records == []
