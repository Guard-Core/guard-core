from types import ModuleType

import pytest

import guard_core.adapter_support as adapter_support
from guard_core import (
    _config_capabilities,
    _misconfiguration,
    _misconfiguration_kinds,
    _parked_records,
)
from guard_core._utils import app_scope, config_registry, route_gate, sampling

ADAPTER_FACING: dict[str, ModuleType] = {
    "AppScope": app_scope,
    "Problem": _misconfiguration_kinds,
    "REDIS_HANDLERS": config_registry,
    "config_logger": _misconfiguration,
    "detection_exclusion_path_param_problems": route_gate,
    "hold_app_scope": app_scope,
    "observe_sampled_key": sampling,
    "register_adapter": _config_capabilities,
    "register_per_app_record": _parked_records,
    "release_app_scope": app_scope,
    "report_declared_path_param_problems": _misconfiguration,
    "route_unknown_to_decorator_problem": route_gate,
}


def test_public_names_are_exactly_what_the_adapters_import() -> None:
    assert sorted(adapter_support.__all__) == sorted(ADAPTER_FACING)


@pytest.mark.parametrize("name", sorted(ADAPTER_FACING))
def test_each_public_name_is_the_private_object_not_a_copy(name: str) -> None:
    assert getattr(adapter_support, name) is getattr(ADAPTER_FACING[name], name)


def test_every_name_in_all_resolves() -> None:
    assert all(hasattr(adapter_support, name) for name in adapter_support.__all__)
