from importlib import import_module
from typing import TYPE_CHECKING

from guard_core.core.responses.context import ResponseContext
from guard_core.core.responses.factory import ErrorResponseFactory

if TYPE_CHECKING:
    from guard_core.core.responses.modifier_view import reads_response_body

__all__ = ["ResponseContext", "ErrorResponseFactory", "reads_response_body"]


def __getattr__(name: str) -> object:
    if name != "reads_response_body":
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    value = getattr(import_module("guard_core.core.responses.modifier_view"), name)
    globals()[name] = value
    return value
