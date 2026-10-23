from unittest.mock import MagicMock, patch

import pytest

from guard_core.exceptions import AgentPackageNotInstalledError
from guard_core.models import SecurityConfig


def test_agent_config_validation_missing_api_key() -> None:
    from pydantic import ValidationError

    with pytest.raises(ValidationError) as exc_info:
        SecurityConfig(
            enable_agent=True,
            agent_api_key=None,
        )

    assert "agent_api_key is required when enable_agent is True" in str(exc_info.value)


def test_agent_config_validation_dynamic_rules_without_agent() -> None:
    from pydantic import ValidationError

    with pytest.raises(ValidationError) as exc_info:
        SecurityConfig(
            enable_agent=False,
            enable_dynamic_rules=True,
            agent_api_key="test-key",
        )

    assert "enable_agent must be True when enable_dynamic_rules is True" in str(
        exc_info.value
    )


def test_to_agent_config_returns_none_when_disabled() -> None:
    config = SecurityConfig(
        enable_agent=False,
        agent_api_key="test-key",
    )

    result = config.to_agent_config()
    assert result is None


def test_to_agent_config_returns_none_when_no_api_key() -> None:
    config = SecurityConfig(
        enable_agent=False,
    )
    config.enable_agent = True
    config.agent_api_key = None

    result = config.to_agent_config()
    assert result is None


def test_to_agent_config_success() -> None:
    config = SecurityConfig(
        enable_agent=True,
        agent_api_key="test-api-key",
        agent_endpoint="https://test.example.com",
        agent_project_id="test-project",
        agent_buffer_size=200,
        agent_flush_interval=60,
        agent_enable_events=True,
        agent_enable_metrics=False,
        agent_timeout=45,
        agent_retry_attempts=5,
    )

    result = config.to_agent_config()

    assert result is not None


def test_to_agent_config_propagates_encryption_key() -> None:
    config = SecurityConfig(
        enable_agent=True,
        agent_api_key="test-api-key",
        agent_project_encryption_key="bXlfMzJfYnl0ZV9rZXlfYmFzZTY0X2VuY29kZWRfaGVyZQ==",
    )

    result = config.to_agent_config()

    assert result is not None
    assert (
        result.project_encryption_key
        == "bXlfMzJfYnl0ZV9rZXlfYmFzZTY0X2VuY29kZWRfaGVyZQ=="
    )


def test_to_agent_config_propagates_guard_version() -> None:
    import guard_agent

    config = SecurityConfig(
        enable_agent=True,
        agent_api_key="test-api-key",
        agent_guard_version="6.7.8",
    )

    spy = MagicMock(name="AgentConfig")
    with patch.object(guard_agent, "AgentConfig", spy):
        config.to_agent_config()

    spy.assert_called_once()
    assert spy.call_args.kwargs.get("guard_version") == "6.7.8"


def test_to_agent_config_propagates_guard_core_version_automatically() -> None:
    import guard_agent

    import guard_core

    config = SecurityConfig(
        enable_agent=True,
        agent_api_key="test-api-key",
    )

    spy = MagicMock(name="AgentConfig")
    with patch.object(guard_agent, "AgentConfig", spy):
        config.to_agent_config()

    spy.assert_called_once()
    assert spy.call_args.kwargs.get("guard_core_version") == guard_core.__version__


def test_to_agent_config_sends_distinct_wrapper_and_core_versions() -> None:
    import guard_agent

    import guard_core

    config = SecurityConfig(
        enable_agent=True,
        agent_api_key="test-api-key",
        agent_guard_version="fastapi-guard-7.1.0",
    )

    spy = MagicMock(name="AgentConfig")
    with patch.object(guard_agent, "AgentConfig", spy):
        config.to_agent_config()

    kwargs = spy.call_args.kwargs
    assert kwargs.get("guard_version") == "fastapi-guard-7.1.0"
    assert kwargs.get("guard_core_version") == guard_core.__version__
    assert kwargs["guard_version"] != kwargs["guard_core_version"]


def test_to_agent_config_import_error() -> None:
    import sys

    config = SecurityConfig(
        enable_agent=True,
        agent_api_key="test-api-key",
    )

    original_module = sys.modules.get("guard_agent")
    if "guard_agent" in sys.modules:
        del sys.modules["guard_agent"]

    mock_module = MagicMock()
    mock_module.AgentConfig.side_effect = ImportError("No module named 'guard_agent'")
    sys.modules["guard_agent"] = mock_module

    try:
        with pytest.raises(AgentPackageNotInstalledError):
            config.to_agent_config()
    finally:
        if original_module:
            sys.modules["guard_agent"] = original_module
        elif "guard_agent" in sys.modules:
            del sys.modules["guard_agent"]


def test_agent_config_with_all_defaults() -> None:
    config = SecurityConfig(
        enable_agent=True,
        agent_api_key="test-key",
    )

    assert config.agent_endpoint == "https://api.guard-core.com"
    assert config.agent_project_id is None
    assert config.agent_buffer_size == 100
    assert config.agent_flush_interval == 30
    assert config.agent_enable_events is True
    assert config.agent_enable_metrics is True
    assert config.agent_timeout == 30
    assert config.agent_retry_attempts == 3
    assert config.agent_project_encryption_key is None
    assert config.agent_guard_version is None
    assert config.enable_dynamic_rules is False
    assert config.dynamic_rule_interval == 300


def test_emergency_mode_defaults() -> None:
    config = SecurityConfig()

    assert config.emergency_mode is False
    assert config.emergency_whitelist == []
    assert config.endpoint_rate_limits == {}


def test_valid_agent_and_dynamic_rules_config() -> None:
    config = SecurityConfig(
        enable_agent=True,
        agent_api_key="test-key",
        enable_dynamic_rules=True,
        dynamic_rule_interval=600,
    )

    assert config.enable_agent is True
    assert config.enable_dynamic_rules is True
    assert config.dynamic_rule_interval == 600


def test_dynamic_rule_interval_below_agent_config_floor_is_rejected() -> None:
    with pytest.raises(ValueError):
        SecurityConfig(
            enable_agent=True,
            agent_api_key="test-key",
            enable_dynamic_rules=True,
            dynamic_rule_interval=59,
        )


def test_dynamic_rule_interval_at_agent_config_floor_is_accepted() -> None:
    config = SecurityConfig(
        enable_agent=True,
        agent_api_key="test-key",
        enable_dynamic_rules=True,
        dynamic_rule_interval=60,
    )

    assert config.dynamic_rule_interval == 60


def test_to_agent_config_forwards_dynamic_rule_interval() -> None:
    import guard_agent

    config = SecurityConfig(
        enable_agent=True,
        agent_api_key="test-key",
        dynamic_rule_interval=600,
    )

    spy = MagicMock(name="AgentConfig")
    with patch.object(guard_agent, "AgentConfig", spy):
        config.to_agent_config()

    spy.assert_called_once()
    assert spy.call_args.kwargs.get("dynamic_rule_interval") == 600


def test_to_agent_config_forwards_agent_status_interval() -> None:
    """`status_interval` was added to AgentConfig in guard-agent 2.6.0.

    Asserted at the call-site contract level, to_agent_config() must pass
    status_interval as a kwarg to AgentConfig.
    """
    import guard_agent

    config = SecurityConfig(
        enable_agent=True,
        agent_api_key="test-key",
        agent_status_interval=900,
    )

    spy = MagicMock(name="AgentConfig")
    with patch.object(guard_agent, "AgentConfig", spy):
        config.to_agent_config()

    spy.assert_called_once()
    assert spy.call_args.kwargs.get("status_interval") == 900


def test_agent_status_interval_defaults_to_300() -> None:
    config = SecurityConfig()
    assert config.agent_status_interval == 300


def test_agent_status_interval_rejects_below_60() -> None:
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        SecurityConfig(agent_status_interval=30)


def test_agent_status_interval_rejects_above_86400() -> None:
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        SecurityConfig(agent_status_interval=86401)


def _sample_on_error_hook(
    stage: str, exc: BaseException, context: dict[str, object]
) -> None:
    raise NotImplementedError


FORWARDED_OPTIONAL_AGENT_FIELDS: list[tuple[str, str, object]] = [
    ("agent_high_watermark_ratio", "high_watermark_ratio", 0.5),
    ("agent_max_concurrent_flushes", "max_concurrent_flushes", 4),
    ("agent_buffer_overflow_policy", "buffer_overflow_policy", "block"),
    ("agent_backoff_factor", "backoff_factor", 2.5),
    ("agent_sensitive_headers", "sensitive_headers", ["x-secret"]),
    ("agent_max_payload_size", "max_payload_size", 2048),
    ("agent_compression_enabled", "compression_enabled", False),
    ("agent_compression_threshold", "compression_threshold", 4096),
    ("agent_install_id", "install_id", "custom-install-id"),
    ("agent_payload_signing_secret", "payload_signing_secret", "sekret"),
    ("on_error", "on_error", _sample_on_error_hook),
]


@pytest.mark.parametrize(
    "security_field, agent_field, value", FORWARDED_OPTIONAL_AGENT_FIELDS
)
def test_to_agent_config_forwards_optional_field_when_set(
    security_field: str, agent_field: str, value: object
) -> None:
    config = SecurityConfig(
        enable_agent=True,
        agent_api_key="test-key",
        **{security_field: value},
    )

    result = config.to_agent_config()

    assert result is not None
    assert getattr(result, agent_field) == value


def test_to_agent_config_forwards_on_error_by_identity() -> None:
    config = SecurityConfig(
        enable_agent=True,
        agent_api_key="test-key",
        on_error=_sample_on_error_hook,
    )

    result = config.to_agent_config()

    assert result is not None
    assert result.on_error is _sample_on_error_hook


def test_to_agent_config_omits_none_optional_fields_leaving_agent_defaults() -> None:
    from guard_agent import AgentConfig

    config = SecurityConfig(
        enable_agent=True,
        agent_api_key="test-key",
    )

    result = config.to_agent_config()

    assert result is not None
    for security_field, agent_field, _value in FORWARDED_OPTIONAL_AGENT_FIELDS:
        assert getattr(config, security_field) is None
        expected_default = AgentConfig.model_fields[agent_field].get_default(
            call_default_factory=True
        )
        assert getattr(result, agent_field) == expected_default


def test_agent_buffer_overflow_policy_rejects_invalid_value() -> None:
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        SecurityConfig(agent_buffer_overflow_policy="nonsense")


def test_agent_optional_fields_default_to_none() -> None:
    config = SecurityConfig()

    assert config.agent_high_watermark_ratio is None
    assert config.agent_max_concurrent_flushes is None
    assert config.agent_buffer_overflow_policy is None
    assert config.agent_backoff_factor is None
    assert config.agent_sensitive_headers is None
    assert config.agent_max_payload_size is None
    assert config.agent_compression_enabled is None
    assert config.agent_compression_threshold is None
    assert config.agent_install_id is None
    assert config.agent_payload_signing_secret is None
