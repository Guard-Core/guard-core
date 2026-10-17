import pytest
from pydantic import ValidationError

from guard_core.models import SecurityConfig


def test_a_bad_emergency_whitelist_entry_is_rejected_at_construction() -> None:
    with pytest.raises(ValidationError, match="Invalid IP or CIDR range"):
        SecurityConfig(enable_redis=False, emergency_whitelist=["10.0.0.0/33"])


def test_a_bad_emergency_whitelist_entry_is_rejected_on_assignment() -> None:
    config = SecurityConfig(enable_redis=False, emergency_whitelist=["10.0.0.1"])

    with pytest.raises(ValueError, match="Invalid IP or CIDR range"):
        config.emergency_whitelist = ["10.0.0.0/33"]

    assert config.emergency_whitelist == ["10.0.0.1"]


def test_a_rejected_assignment_leaves_the_request_path_working() -> None:
    config = SecurityConfig(enable_redis=False, emergency_whitelist=["10.0.0.1"])
    with pytest.raises(ValueError, match="Invalid IP or CIDR range"):
        config.emergency_whitelist = ["not-an-ip"]
    assert list(config.emergency_whitelist) == ["10.0.0.1"]


def test_valid_emergency_whitelist_entries_are_kept_as_a_list() -> None:
    config = SecurityConfig(
        enable_redis=False, emergency_whitelist=["10.0.0.1", "192.0.2.0/24"]
    )
    assert config.emergency_whitelist == ["10.0.0.1", "192.0.2.0/24"]
    config.emergency_whitelist = ["2001:db8::/32"]
    assert config.emergency_whitelist == ["2001:db8::/32"]
