import inspect
from collections.abc import Awaitable, Callable
from typing import TypeVar

from typing_extensions import TypeIs

_Argument = TypeVar("_Argument")
_Result = TypeVar("_Result")


def is_async_form(
    configured: Callable[[_Argument], Awaitable[_Result]]
    | Callable[[_Argument], _Result],
) -> TypeIs[Callable[[_Argument], Awaitable[_Result]]]:
    return inspect.iscoroutinefunction(configured) or inspect.iscoroutinefunction(
        type(configured).__call__
    )
