from typing import Any, cast

import pytest
from pydantic import ValidationError

from guard_core.models import SecurityConfig, SyncSecurityConfig


def test_log_sensitive_params_default_is_empty_frozenset() -> None:
    config = SyncSecurityConfig()
    assert config.log_sensitive_params == frozenset()


def test_log_sensitive_params_accepts_list_and_coerces_to_frozenset() -> None:
    config = SyncSecurityConfig(log_sensitive_params=["sig"])
    assert isinstance(config.log_sensitive_params, frozenset)
    assert config.log_sensitive_params == frozenset({"sig"})


def test_log_sensitive_params_accepts_set() -> None:
    config = SyncSecurityConfig(log_sensitive_params={"sig", "trace_id"})
    assert config.log_sensitive_params == frozenset({"sig", "trace_id"})


def test_log_sensitive_params_is_a_security_config_field() -> None:
    assert "log_sensitive_params" in SecurityConfig.model_fields


def test_log_sensitive_params_construction_with_bare_string_raises() -> None:
    with pytest.raises(ValidationError, match="not a bare string"):
        SyncSecurityConfig(log_sensitive_params="sig")


def test_log_sensitive_params_construction_with_non_str_item_raises() -> None:
    with pytest.raises(ValidationError, match="must be strings"):
        SyncSecurityConfig(log_sensitive_params=[123])


def test_log_sensitive_params_reassignment_with_list_coerces_to_frozenset() -> None:
    config = SyncSecurityConfig()

    cast(Any, config).log_sensitive_params = ["sig"]

    assert config.log_sensitive_params == frozenset({"sig"})


def test_log_sensitive_params_reassignment_with_bare_string_raises() -> None:
    config = SyncSecurityConfig()

    with pytest.raises(ValueError, match="not a bare string"):
        cast(Any, config).log_sensitive_params = "sig"

    assert config.log_sensitive_params == frozenset()


def test_log_sensitive_params_model_copy_update_with_bare_string_raises() -> None:
    base = SyncSecurityConfig()

    with pytest.raises(ValueError, match="not a bare string"):
        base.model_copy(update={"log_sensitive_params": "sig"})

    assert base.log_sensitive_params == frozenset()


def test_log_sensitive_params_model_copy_update_with_list_yields_frozenset() -> None:
    base = SyncSecurityConfig()

    copied = base.model_copy(update={"log_sensitive_params": ["sig"]})

    assert copied.log_sensitive_params == frozenset({"sig"})
