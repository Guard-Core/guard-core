import copy
import pickle

import pytest

from guard_core._security_config_field_validators import (
    _threat_ban_entry,
    _validate_ip_or_cidr_list,
    _validate_threat_ban_config_value,
)
from guard_core.models import SyncSecurityConfig


class _IndexedOnly:
    def __getitem__(self, index: int) -> str:
        if index > 1:
            raise IndexError(index)
        return "10.0.0.1"


class _EntryLike:
    def keys(self) -> list[str]:
        return ["threshold", "duration"]

    def __getitem__(self, key: str) -> int:
        return {"threshold": 3, "duration": 60}[key]


class _KeysAndItems:
    def keys(self) -> list[str]:
        return ["sqli"]

    def __getitem__(self, key: str) -> dict[str, int]:
        return {"threshold": 3, "duration": 60}


def test_an_object_iterable_only_through_getitem_is_refused_as_an_ip_list() -> None:
    with pytest.raises(
        ValueError, match="expected a list of strings, got _IndexedOnly"
    ):
        _validate_ip_or_cidr_list(_IndexedOnly(), invalid_message="Invalid IP")


def test_a_non_mapping_threat_ban_entry_keeps_its_message() -> None:
    with pytest.raises(ValueError, match=r"threat_ban_config\['sqli'\] must be a"):
        _threat_ban_entry("sqli", 5)


def test_a_keys_and_getitem_object_is_still_a_threat_ban_entry() -> None:
    assert _threat_ban_entry("sqli", _EntryLike()).threshold == 3


def test_a_keys_and_getitem_object_is_still_the_threat_ban_config() -> None:
    assert _validate_threat_ban_config_value(_KeysAndItems())["sqli"].threshold == 3


def test_a_pair_list_is_still_accepted_as_the_threat_ban_config() -> None:
    result = _validate_threat_ban_config_value(
        [("sqli", {"threshold": 3, "duration": 60})]
    )
    assert result["sqli"].threshold == 3


def test_a_prevalidated_rule_assignment_that_is_not_iterable_is_refused() -> None:
    config = SyncSecurityConfig()
    with pytest.raises(TypeError, match="'int' object is not iterable"):
        config._set_prevalidated("global_behavior_rules", 5)


def test_a_prevalidated_rule_assignment_holding_a_non_rule_is_refused() -> None:
    config = SyncSecurityConfig()
    with pytest.raises(TypeError, match="holds a str, expected a BehaviorRuleConfig"):
        config._set_prevalidated("global_behavior_rules", ["not a rule"])


def test_a_pickled_state_without_its_fields_is_refused() -> None:
    config = SyncSecurityConfig()
    with pytest.raises(TypeError, match="lacks its fields"):
        config.__setstate__({"__dict__": 5})


def test_a_pickled_state_without_its_threat_ban_config_is_refused() -> None:
    config = SyncSecurityConfig()
    with pytest.raises(TypeError, match="lacks its threat_ban_config"):
        config.__setstate__({"__dict__": {"threat_ban_config": 5}})


def test_a_config_still_survives_pickle_and_deepcopy() -> None:
    config = SyncSecurityConfig()
    assert pickle.loads(pickle.dumps(config)).threat_ban_config == (
        config.threat_ban_config
    )
    assert copy.deepcopy(config).threat_ban_config == config.threat_ban_config
