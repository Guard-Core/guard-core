from pathlib import Path

import pytest

from guard_core.models import SyncSecurityConfig


def test_dynamic_rules_cache_path_defaults_to_none_disabling_the_file_fallback() -> (
    None
):
    config = SyncSecurityConfig()

    assert config.dynamic_rules_cache_path is None


def test_dynamic_rules_cache_path_accepts_a_string_path() -> None:
    config = SyncSecurityConfig(dynamic_rules_cache_path="/var/lib/guard/rules.json")

    assert config.dynamic_rules_cache_path == Path("/var/lib/guard/rules.json")


def test_dynamic_rules_cache_path_accepts_a_path_object(tmp_path: Path) -> None:
    cache_path = tmp_path / "dynamic_rules.json"
    config = SyncSecurityConfig(dynamic_rules_cache_path=cache_path)

    assert config.dynamic_rules_cache_path == cache_path


def test_dynamic_rules_cache_path_rejects_non_string_values() -> None:
    with pytest.raises(ValueError, match="must be a non-empty filesystem path"):
        SyncSecurityConfig(dynamic_rules_cache_path=123)


def test_dynamic_rules_cache_path_rejects_empty_string() -> None:
    with pytest.raises(ValueError, match="must not be empty or whitespace-only"):
        SyncSecurityConfig(dynamic_rules_cache_path="")


@pytest.mark.parametrize("value", ["", "   ", "\t"])
def test_dynamic_rules_cache_path_rejects_blank_values(value: str) -> None:
    with pytest.raises(ValueError, match="must not be empty or whitespace-only"):
        SyncSecurityConfig(dynamic_rules_cache_path=value)


def test_dynamic_rules_cache_path_runtime_assignment_rejects_non_string() -> None:
    config = SyncSecurityConfig(dynamic_rules_cache_path="/tmp/rules.json")
    field_name = "dynamic_rules_cache_path"

    with pytest.raises(ValueError, match="must be a non-empty filesystem path"):
        setattr(config, field_name, 123)


def test_dynamic_rules_cache_path_runtime_rejection_leaves_field_unchanged() -> None:
    config = SyncSecurityConfig(dynamic_rules_cache_path="/tmp/rules.json")
    revision_before = config.revision
    field_name = "dynamic_rules_cache_path"

    with pytest.raises(ValueError):
        setattr(config, field_name, "")

    assert config.dynamic_rules_cache_path == Path("/tmp/rules.json")
    assert config.revision == revision_before


def test_dynamic_rules_cache_path_runtime_assignment_accepts_valid_value() -> None:
    config = SyncSecurityConfig()
    revision_before = config.revision
    field_name = "dynamic_rules_cache_path"

    setattr(config, field_name, "/tmp/rules.json")

    assert config.dynamic_rules_cache_path == Path("/tmp/rules.json")
    assert config.revision == revision_before + 1


def test_dynamic_rules_cache_path_runtime_reassignment_to_none_is_accepted() -> None:
    config = SyncSecurityConfig(dynamic_rules_cache_path="/tmp/rules.json")

    config.dynamic_rules_cache_path = None

    assert config.dynamic_rules_cache_path is None


def test_model_copy_update_rejects_invalid_dynamic_rules_cache_path() -> None:
    base = SyncSecurityConfig(dynamic_rules_cache_path="/tmp/rules.json")

    with pytest.raises(ValueError, match="must be a non-empty filesystem path"):
        base.model_copy(update={"dynamic_rules_cache_path": 123})

    assert base.dynamic_rules_cache_path == Path("/tmp/rules.json")


def test_model_copy_update_accepts_valid_dynamic_rules_cache_path() -> None:
    base = SyncSecurityConfig(dynamic_rules_cache_path="/tmp/rules.json")

    copied = base.model_copy(update={"dynamic_rules_cache_path": "/var/rules.json"})

    assert copied.dynamic_rules_cache_path == Path("/var/rules.json")
