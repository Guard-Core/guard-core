from types import MappingProxyType
from typing import Any, cast

import pytest

from guard_core.models import SyncSecurityConfig, ThreatBanConfig

IP_CIDR_FIELDS = [
    ("whitelist", ["10.0.0.0/24"], "not-an-ip", "Invalid IP or CIDR range"),
    ("blacklist", ["192.168.1.1"], "not-an-ip", "Invalid IP or CIDR range"),
    ("exempt_ips", ["198.51.100.0/28"], "not-an-ip", "Invalid IP or CIDR range"),
    ("trusted_proxies", ["127.0.0.1"], "not-an-ip", "Invalid proxy IP or CIDR range"),
]

MEMBERSHIP_FROZENSET_FIELDS = [
    ("enabled_detection_categories", {"xss"}, {"not_a_real_category"}, "Unknown"),
    ("muted_event_types", {"penetration_attempt"}, {"not_a_real_event"}, "Unknown"),
    ("muted_metric_types", {"response_time"}, {"not_a_real_metric"}, "Unknown"),
    ("muted_check_logs", {"authentication"}, {"not_a_real_check"}, "Unknown"),
]


@pytest.mark.parametrize(("field", "seed", "bad_entry", "error_match"), IP_CIDR_FIELDS)
def test_ip_cidr_field_is_stored_as_tuple(
    field: str, seed: list[str], bad_entry: str, error_match: str
) -> None:
    config = SyncSecurityConfig(**{field: seed})
    assert isinstance(getattr(config, field), tuple)


@pytest.mark.parametrize(("field", "seed", "bad_entry", "error_match"), IP_CIDR_FIELDS)
def test_ip_cidr_field_in_place_append_is_rejected(
    field: str, seed: list[str], bad_entry: str, error_match: str
) -> None:
    config = SyncSecurityConfig(**{field: seed})
    entries: Any = getattr(config, field)

    with pytest.raises(AttributeError):
        entries.append("10.0.0.1")


@pytest.mark.parametrize(("field", "seed", "bad_entry", "error_match"), IP_CIDR_FIELDS)
def test_ip_cidr_field_reassignment_with_invalid_entry_raises(
    field: str, seed: list[str], bad_entry: str, error_match: str
) -> None:
    config = SyncSecurityConfig(**{field: seed})

    with pytest.raises(ValueError, match=error_match):
        setattr(config, field, [bad_entry])

    assert getattr(config, field) == tuple(seed)


@pytest.mark.parametrize(("field", "seed", "bad_entry", "error_match"), IP_CIDR_FIELDS)
def test_ip_cidr_field_reassignment_with_valid_entries_normalizes(
    field: str, seed: list[str], bad_entry: str, error_match: str
) -> None:
    config = SyncSecurityConfig(**{field: seed})

    setattr(config, field, ["10.0.0.5", "172.16.0.0/12"])

    assert getattr(config, field) == ("10.0.0.5", "172.16.0.0/12")


@pytest.mark.parametrize(("field", "seed", "bad_entry", "error_match"), IP_CIDR_FIELDS)
def test_ip_cidr_field_model_copy_update_with_invalid_entry_raises(
    field: str, seed: list[str], bad_entry: str, error_match: str
) -> None:
    base = SyncSecurityConfig(**{field: seed})

    with pytest.raises(ValueError, match=error_match):
        base.model_copy(update={field: [bad_entry]})

    assert getattr(base, field) == tuple(seed)


@pytest.mark.parametrize(("field", "seed", "bad_entry", "error_match"), IP_CIDR_FIELDS)
def test_ip_cidr_field_model_copy_update_with_valid_entries_normalizes(
    field: str, seed: list[str], bad_entry: str, error_match: str
) -> None:
    base = SyncSecurityConfig(**{field: seed})

    copied = base.model_copy(update={field: ["10.0.0.6"]})

    assert getattr(copied, field) == ("10.0.0.6",)


def test_whitelist_reassignment_to_none_is_accepted() -> None:
    config = SyncSecurityConfig(whitelist=["10.0.0.0/24"])

    config.whitelist = None

    assert config.whitelist is None


@pytest.mark.parametrize(
    ("field", "seed", "bad_value", "error_match"), MEMBERSHIP_FROZENSET_FIELDS
)
def test_membership_field_is_stored_as_frozenset(
    field: str, seed: set[str], bad_value: set[str], error_match: str
) -> None:
    config = SyncSecurityConfig(**{field: seed})
    assert isinstance(getattr(config, field), frozenset)


@pytest.mark.parametrize(
    ("field", "seed", "bad_value", "error_match"), MEMBERSHIP_FROZENSET_FIELDS
)
def test_membership_field_in_place_add_is_rejected(
    field: str, seed: set[str], bad_value: set[str], error_match: str
) -> None:
    config = SyncSecurityConfig(**{field: seed})
    values: Any = getattr(config, field)

    with pytest.raises(AttributeError):
        values.add("intruder")


@pytest.mark.parametrize(
    ("field", "seed", "bad_value", "error_match"), MEMBERSHIP_FROZENSET_FIELDS
)
def test_membership_field_reassignment_with_unknown_value_raises(
    field: str, seed: set[str], bad_value: set[str], error_match: str
) -> None:
    config = SyncSecurityConfig(**{field: seed})

    with pytest.raises(ValueError, match=error_match):
        setattr(config, field, bad_value)

    assert getattr(config, field) == frozenset(seed)


@pytest.mark.parametrize(
    ("field", "seed", "bad_value", "error_match"), MEMBERSHIP_FROZENSET_FIELDS
)
def test_membership_field_model_copy_update_with_unknown_value_raises(
    field: str, seed: set[str], bad_value: set[str], error_match: str
) -> None:
    base = SyncSecurityConfig(**{field: seed})

    with pytest.raises(ValueError, match=error_match):
        base.model_copy(update={field: bad_value})

    assert getattr(base, field) == frozenset(seed)


def test_threat_ban_config_is_stored_as_mappingproxy() -> None:
    config = SyncSecurityConfig(
        threat_ban_config={"xss": ThreatBanConfig(threshold=1, duration=1)}
    )
    assert isinstance(config.threat_ban_config, MappingProxyType)


def test_threat_ban_config_in_place_item_assignment_is_rejected() -> None:
    config = SyncSecurityConfig(
        threat_ban_config={"xss": ThreatBanConfig(threshold=1, duration=1)}
    )

    with pytest.raises(TypeError):
        cast(Any, config.threat_ban_config)["xss"] = ThreatBanConfig(
            threshold=99, duration=99
        )


def test_threat_ban_config_reassignment_with_unknown_category_raises() -> None:
    config = SyncSecurityConfig(
        threat_ban_config={"xss": ThreatBanConfig(threshold=1, duration=1)}
    )

    with pytest.raises(ValueError, match="Unknown threat categories"):
        config.threat_ban_config = cast(
            Any, {"bogus": ThreatBanConfig(threshold=1, duration=1)}
        )

    assert set(config.threat_ban_config.keys()) == {"xss"}


def test_threat_ban_config_reassignment_accepts_valid_category() -> None:
    config = SyncSecurityConfig(
        threat_ban_config={"xss": ThreatBanConfig(threshold=1, duration=1)}
    )

    config.threat_ban_config = cast(
        Any, {"sqli": ThreatBanConfig(threshold=5, duration=60)}
    )

    assert config.threat_ban_config["sqli"].threshold == 5


def test_threat_ban_config_reassignment_coerces_raw_dict_values() -> None:
    config = SyncSecurityConfig()

    config.threat_ban_config = cast(Any, {"xss": {"threshold": 2, "duration": 30}})

    entry = config.threat_ban_config["xss"]
    assert isinstance(entry, ThreatBanConfig)
    assert entry.threshold == 2


def test_threat_ban_config_model_copy_update_with_unknown_category_raises() -> None:
    base = SyncSecurityConfig(
        threat_ban_config={"xss": ThreatBanConfig(threshold=1, duration=1)}
    )

    with pytest.raises(ValueError, match="Unknown threat categories"):
        base.model_copy(
            update={
                "threat_ban_config": {"bogus": ThreatBanConfig(threshold=1, duration=1)}
            }
        )

    assert set(base.threat_ban_config.keys()) == {"xss"}


def test_threat_ban_config_model_copy_update_accepts_valid_category() -> None:
    base = SyncSecurityConfig()

    copied = base.model_copy(
        update={"threat_ban_config": {"sqli": ThreatBanConfig(threshold=3, duration=9)}}
    )

    assert copied.threat_ban_config["sqli"].duration == 9
