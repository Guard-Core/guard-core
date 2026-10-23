import inspect
from collections.abc import Awaitable, Callable
from functools import wraps
from typing import Generic, TypeVar

from typing_extensions import TypeIs

from guard_core._callable_shape import is_async_form

_Argument = TypeVar("_Argument")
_Result = TypeVar("_Result")


class CallableSlot(Generic[_Argument, _Result]):
    """The callable one SecurityConfig field holds, classified once per object.

    ``invoke`` is the configured callable itself when it is async, so the call
    site pays no call for it. A sync callable is wrapped once to await a result
    that turns out to be awaitable. The slot adopts again when the field holds
    another object (identity), never on a call.
    """

    def __init__(
        self,
        field: str,
        configured: object = None,
    ) -> None:
        self.field = field
        self.source: object = None
        self.invoke: Callable[[_Argument], Awaitable[_Result]] = self._not_configured
        if configured is not None:
            self.adopt(configured)

    async def _not_configured(self, argument: _Argument) -> _Result:
        raise TypeError(f"{self.field} is not configured")

    def _is_callable_of_this_tree(
        self, configured: object
    ) -> TypeIs[
        Callable[[_Argument], Awaitable[_Result]] | Callable[[_Argument], _Result]
    ]:
        # The config field also admits the other tree's request type (typing for
        # adopters of that tree, WP38 6.115). No type check tells the arms apart
        # at runtime: the slot's contract is the arm of its own tree, and a value
        # that is not callable at all is refused here.
        return callable(configured)

    def adopt(self, configured: object) -> None:
        if not self._is_callable_of_this_tree(configured):
            raise TypeError(f"{self.field} must be callable")
        if is_async_form(configured):
            self.invoke = configured
            self.source = configured
            return
        plain = configured

        @wraps(configured)
        async def settled(argument: _Argument) -> _Result:
            result = plain(argument)
            if inspect.isawaitable(result):
                awaited: _Result = await result
                return awaited
            return result

        self.invoke = settled
        self.source = configured
