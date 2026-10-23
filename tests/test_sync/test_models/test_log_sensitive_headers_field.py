from typing import Any, cast

import pytest
from pydantic import ValidationError

from guard_core.models import SecurityConfig, SyncSecurityConfig


def test_log_sensitive_headers_default_is_empty_frozenset() -> None:
    config = SyncSecurityConfig()
    assert config.log_sensitive_headers == frozenset()


def test_log_sensitive_headers_accepts_list_and_coerces_to_frozenset() -> None:
    config = SyncSecurityConfig(log_sensitive_headers=["X-Internal-Token"])
    assert isinstance(config.log_sensitive_headers, frozenset)
    assert config.log_sensitive_headers == frozenset({"X-Internal-Token"})


def test_log_sensitive_headers_accepts_set() -> None:
    config = SyncSecurityConfig(
        log_sensitive_headers={"X-Internal-Token", "X-Trace-Id"}
    )
    assert config.log_sensitive_headers == frozenset({"X-Internal-Token", "X-Trace-Id"})


def test_log_sensitive_headers_is_a_security_config_field() -> None:
    assert "log_sensitive_headers" in SecurityConfig.model_fields


def test_log_sensitive_headers_construction_with_bare_string_raises() -> None:
    with pytest.raises(ValidationError, match="not a bare string"):
        SyncSecurityConfig(log_sensitive_headers="x-token")


def test_log_sensitive_headers_construction_with_non_str_item_raises() -> None:
    with pytest.raises(ValidationError, match="must be strings"):
        SyncSecurityConfig(log_sensitive_headers=[123])


def test_log_sensitive_headers_reassignment_with_list_coerces_to_frozenset() -> None:
    config = SyncSecurityConfig()

    cast(Any, config).log_sensitive_headers = ["X-Session"]

    assert config.log_sensitive_headers == frozenset({"X-Session"})


def test_log_sensitive_headers_reassignment_with_bare_string_raises() -> None:
    config = SyncSecurityConfig()

    with pytest.raises(ValueError, match="not a bare string"):
        cast(Any, config).log_sensitive_headers = "x-token"

    assert config.log_sensitive_headers == frozenset()


def test_log_sensitive_headers_model_copy_update_with_bare_string_raises() -> None:
    base = SyncSecurityConfig()

    with pytest.raises(ValueError, match="not a bare string"):
        base.model_copy(update={"log_sensitive_headers": "x-token"})

    assert base.log_sensitive_headers == frozenset()


def test_log_sensitive_headers_model_copy_update_with_list_yields_frozenset() -> None:
    base = SyncSecurityConfig()

    copied = base.model_copy(update={"log_sensitive_headers": ["x-token"]})

    assert copied.log_sensitive_headers == frozenset({"x-token"})
