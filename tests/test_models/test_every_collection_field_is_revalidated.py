import types
import typing
from typing import Any, cast

import pytest

from guard_core._security_config_field_validators import _FIELD_REVALIDATORS
from guard_core.models import BehaviorRuleConfig, SecurityConfig
from tests.test_models.test_immutable_collection_fields import (
    IP_CIDR_FIELDS,
    MEMBERSHIP_FROZENSET_FIELDS,
)

_UNION_TYPES = (typing.Union, types.UnionType)
_COLLECTION_ORIGINS = (list, set, frozenset, tuple, dict)


def _unwrap_optional(annotation: Any) -> Any:
    origin = typing.get_origin(annotation)
    if origin in _UNION_TYPES:
        args = [a for a in typing.get_args(annotation) if a is not type(None)]
        if len(args) == 1:
            return _unwrap_optional(args[0])
    return annotation


def _is_collection_annotation(annotation: Any) -> bool:
    unwrapped = _unwrap_optional(annotation)
    origin = typing.get_origin(unwrapped)
    return origin in _COLLECTION_ORIGINS or unwrapped in _COLLECTION_ORIGINS


def _collection_field_names() -> list[str]:
    return sorted(
        name
        for name, field in SecurityConfig.model_fields.items()
        if _is_collection_annotation(field.annotation)
    )


_THREAT_BAN_CONFIG_FIELD = "threat_ban_config"

_IMMUTABLE_COLLECTION_FIELDS = frozenset(
    {field for field, *_ in IP_CIDR_FIELDS}
    | {field for field, *_ in MEMBERSHIP_FROZENSET_FIELDS}
    | {_THREAT_BAN_CONFIG_FIELD}
)


@pytest.mark.parametrize("field_name", _collection_field_names())
def test_collection_field_is_revalidated_or_immutable(field_name: str) -> None:
    assert (
        field_name in _FIELD_REVALIDATORS or field_name in _IMMUTABLE_COLLECTION_FIELDS
    )


_NEWLY_REGISTERED_FIELDS: tuple[tuple[str, Any, Any], ...] = (
    ("global_behavior_rules", [{"rule_type": "usage", "threshold": 3}], "nope"),
    ("custom_error_responses", {404: "not found"}, "nope"),
    ("security_headers", {"X-Frame-Options": "DENY"}, "nope"),
    ("cors_allow_origins", ["https://a.example"], "nope"),
    ("cors_allow_methods", ["GET"], "nope"),
    ("cors_allow_headers", ["X-Custom"], "nope"),
    ("cors_expose_headers", ["X-Custom"], "nope"),
    ("agent_sensitive_headers", ["authorization"], "nope"),
    ("otel_resource_attributes", {"service.name": "guard"}, "nope"),
    ("excluded_detection_headers", {"x-foo"}, "nope"),
    ("excluded_semantic_detection_headers", {"cookie"}, "nope"),
    ("excluded_detection_params", {"token"}, "nope"),
    ("excluded_detection_body_fields", {"password"}, "nope"),
)


@pytest.mark.parametrize(
    ("field_name", "valid_value", "bad_value"), _NEWLY_REGISTERED_FIELDS
)
def test_newly_registered_field_reassignment_accepts_valid_value(
    field_name: str, valid_value: Any, bad_value: Any
) -> None:
    config = SecurityConfig()

    setattr(config, field_name, valid_value)

    assert bool(getattr(config, field_name))


@pytest.mark.parametrize(
    ("field_name", "valid_value", "bad_value"), _NEWLY_REGISTERED_FIELDS
)
def test_newly_registered_field_reassignment_rejects_bare_string(
    field_name: str, valid_value: Any, bad_value: Any
) -> None:
    config = SecurityConfig()

    with pytest.raises(ValueError, match=field_name):
        setattr(config, field_name, bad_value)

    assert getattr(config, field_name) != bad_value


def test_global_behavior_rules_reassignment_coerces_dicts_to_model() -> None:
    config = SecurityConfig()

    cast(Any, config).global_behavior_rules = [{"rule_type": "usage", "threshold": 3}]

    assert config.global_behavior_rules == (
        BehaviorRuleConfig(rule_type="usage", threshold=3),
    )
    assert isinstance(config.global_behavior_rules, tuple)


def test_security_headers_reassignment_accepts_none() -> None:
    config = SecurityConfig(security_headers={"X-Frame-Options": "DENY"})

    config.security_headers = None

    assert config.security_headers is None


def test_agent_sensitive_headers_reassignment_accepts_none() -> None:
    config = SecurityConfig(agent_sensitive_headers=["authorization"])

    config.agent_sensitive_headers = None

    assert config.agent_sensitive_headers is None


def test_excluded_detection_headers_reassignment_stores_plain_set() -> None:
    config = SecurityConfig()

    cast(Any, config).excluded_detection_headers = ["x-foo", "x-bar"]

    assert config.excluded_detection_headers == {"x-foo", "x-bar"}
    assert isinstance(config.excluded_detection_headers, set)


def test_custom_error_responses_reassignment_rejects_non_int_key() -> None:
    config = SecurityConfig()

    with pytest.raises(ValueError, match="custom_error_responses"):
        cast(Any, config).custom_error_responses = {"not-an-int": "oops"}
