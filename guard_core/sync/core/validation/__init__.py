import importlib.util
from importlib import import_module
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from guard_core.sync.core.validation.context import ValidationContext
    from guard_core.sync.core.validation.validator import RequestValidator

__all__ = ["ValidationContext", "RequestValidator"]

_MODULE_BY_NAME: dict[str, str] = {
    "ValidationContext": "guard_core.sync.core.validation.context",
    "RequestValidator": "guard_core.sync.core.validation.validator",
}


def __getattr__(name: str) -> Any:
    module_name = _MODULE_BY_NAME.get(name)
    if module_name is not None:
        value = getattr(import_module(module_name), name)
        globals()[name] = value
        return value

    submodule_name = f"{__name__}.{name}"
    if importlib.util.find_spec(submodule_name) is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    submodule = import_module(submodule_name)
    globals()[name] = submodule
    return submodule


def __dir__() -> list[str]:
    return sorted(set(globals()) | set(__all__))
