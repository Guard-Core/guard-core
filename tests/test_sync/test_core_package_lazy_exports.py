import sys
from types import ModuleType
from typing import cast

import pytest

from guard_core.sync.core.events import metrics as _metrics_module
from guard_core.sync.core.validation import path_matching as _path_matching_module

events_package = sys.modules[_metrics_module.__name__.rpartition(".")[0]]
core_package = sys.modules[events_package.__name__.rpartition(".")[0]]
validation_package = sys.modules[_path_matching_module.__name__.rpartition(".")[0]]


def _resolved_lazily(module: ModuleType, name: str) -> object:
    if name in vars(module):
        delattr(module, name)
    return getattr(module, name)


@pytest.mark.parametrize("name", core_package.__all__)
def test_core_package_name_resolves_to_its_events_module_object(name: str) -> None:
    assert _resolved_lazily(core_package, name) is getattr(events_package, name)


@pytest.mark.parametrize("name", events_package.__all__)
def test_events_package_name_resolves_lazily(name: str) -> None:
    assert _resolved_lazily(events_package, name) is not None


@pytest.mark.parametrize("name", validation_package.__all__)
def test_validation_package_name_resolves_lazily(name: str) -> None:
    assert _resolved_lazily(validation_package, name) is not None


@pytest.mark.parametrize("name", ["enricher", "metrics", "middleware_events"])
def test_events_submodule_attribute_access_works(name: str) -> None:
    submodule = cast(ModuleType, _resolved_lazily(events_package, name))

    assert submodule.__name__ == f"{events_package.__name__}.{name}"


def test_validation_submodule_attribute_access_works() -> None:
    submodule = cast(ModuleType, _resolved_lazily(validation_package, "validator"))

    assert submodule.__name__ == f"{validation_package.__name__}.validator"


def test_core_package_submodule_attribute_access_works() -> None:
    submodule = cast(ModuleType, _resolved_lazily(core_package, "events"))

    assert submodule is events_package


@pytest.mark.parametrize("module", [core_package, events_package, validation_package])
def test_unknown_attribute_raises(module: ModuleType) -> None:
    with pytest.raises(AttributeError):
        module.__getattr__("does_not_exist")


@pytest.mark.parametrize("module", [core_package, events_package, validation_package])
def test_every_all_name_appears_in_dir(module: ModuleType) -> None:
    listed = dir(module)

    assert all(name in listed for name in module.__all__)
