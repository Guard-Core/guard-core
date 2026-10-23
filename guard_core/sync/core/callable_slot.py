import inspect
from collections.abc import Awaitable, Callable
from functools import wraps
from typing import Generic, TypeVar

from guard_core._callable_shape import is_async_form
from guard_core.exceptions import CallableShapeError

_Argument = TypeVar("_Argument")
_Result = TypeVar("_Result")


class CallableSlot(Generic[_Argument, _Result]):
    """The callable one SecurityConfig field holds, classified once per object.

    The sync tree cannot await: an async callable fails when the slot adopts it
    (middleware start). A callable the start check cannot see (a sync decorator
    around an async function, a lambda returning a coroutine) is checked on its
    first result, which is closed before the same error is raised. After that
    first good result ``invoke`` is the configured callable itself.
    """

    def __init__(
        self,
        field: str,
        configured: Callable[[_Argument], Awaitable[_Result]]
        | Callable[[_Argument], _Result]
        | None = None,
    ) -> None:
        self.field = field
        self.source: object = None
        self.invoke: Callable[[_Argument], _Result] = self._not_configured
        if configured is not None:
            self.adopt(configured)

    def _not_configured(self, argument: _Argument) -> _Result:
        raise TypeError(f"{self.field} is not configured")

    def adopt(
        self,
        configured: Callable[[_Argument], Awaitable[_Result]]
        | Callable[[_Argument], _Result],
    ) -> None:
        if is_async_form(configured):
            raise CallableShapeError(self.field)
        plain = configured

        @wraps(configured)
        def first_result_checked(argument: _Argument) -> _Result:
            result = plain(argument)
            if inspect.isawaitable(result):
                if inspect.iscoroutine(result):
                    result.close()
                raise CallableShapeError(self.field)
            if self.source is plain:
                self.invoke = plain
            return result

        self.invoke = first_result_checked
        self.source = configured
