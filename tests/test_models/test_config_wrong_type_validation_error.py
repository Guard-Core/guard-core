from typing import Any

import pytest
from pydantic import ValidationError

from guard_core.models import SecurityConfig

_NAME_SET_FIELDS = [
    "enabled_detection_categories",
    "muted_event_types",
    "muted_metric_types",
    "muted_check_logs",
    "log_sensitive_headers",
    "log_sensitive_params",
    "log_sensitive_body_fields",
    "block_cloud_providers",
]
_IP_LIST_FIELDS = ["whitelist", "blacklist", "exempt_ips", "trusted_proxies"]
_NOT_A_COLLECTION: list[Any] = [42, 3.5, object(), True]
_UNHASHABLE_ITEM: list[Any] = [[1]]
_MIXED_ITEMS: list[Any] = [[1, "x"]]


def _loc_of_only_error(error: ValidationError) -> tuple[int | str, ...]:
    (entry,) = error.errors()
    return entry["loc"]


@pytest.mark.parametrize("field", _NAME_SET_FIELDS)
@pytest.mark.parametrize("value", [*_NOT_A_COLLECTION, *_UNHASHABLE_ITEM])
def test_name_set_field_wrong_type_is_validation_error_at_field(
    field: str, value: object
) -> None:
    with pytest.raises(ValidationError) as caught:
        SecurityConfig(**{field: value})
    assert _loc_of_only_error(caught.value) == (field,)


@pytest.mark.parametrize("field", _NAME_SET_FIELDS)
def test_name_set_field_mixed_types_are_validation_error_at_field(field: str) -> None:
    with pytest.raises(ValidationError) as caught:
        SecurityConfig(**{field: _MIXED_ITEMS[0]})
    assert _loc_of_only_error(caught.value) == (field,)


@pytest.mark.parametrize("field", _IP_LIST_FIELDS)
@pytest.mark.parametrize("value", [*_NOT_A_COLLECTION, [object()], [None], [1]])
def test_ip_list_field_wrong_type_is_validation_error_at_field(
    field: str, value: object
) -> None:
    with pytest.raises(ValidationError) as caught:
        SecurityConfig(**{field: value})
    assert _loc_of_only_error(caught.value) == (field,)


@pytest.mark.parametrize(
    "value",
    [
        42,
        object(),
        True,
        None,
        [object()],
        [1],
        {"rate_limit": 5},
        {"rate_limit": {1: 2}},
        {1: {"threshold": 1, "duration": 1}, "rate_limit": {"threshold": 1}},
    ],
)
def test_threat_ban_config_wrong_type_is_validation_error_at_field(
    value: object,
) -> None:
    with pytest.raises(ValidationError) as caught:
        SecurityConfig(threat_ban_config=value)
    assert _loc_of_only_error(caught.value)[0] == "threat_ban_config"


class _MappingLike:
    def keys(self) -> list[str]:
        return ["threshold", "duration"]

    def __getitem__(self, key: str) -> int:
        return {"threshold": 3, "duration": 60}[key]


def test_threat_ban_config_accepts_a_mapping_like_entry() -> None:
    config = SecurityConfig(threat_ban_config={"sqli": _MappingLike()})
    assert config.threat_ban_config["sqli"].threshold == 3
    assert config.threat_ban_config["sqli"].duration == 60


@pytest.mark.parametrize("field", [*_NAME_SET_FIELDS, "threat_ban_config"])
def test_wrong_type_assignment_is_value_error_not_type_error(field: str) -> None:
    config = SecurityConfig()
    with pytest.raises(ValueError, match=field):
        setattr(config, field, 42)
