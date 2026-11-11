import asyncio
import inspect
import weakref
from collections.abc import Awaitable, Callable, Iterator

Stop = Callable[[], Awaitable[None]]


class BackgroundUsers:
    """The stop callbacks a Redis client awaits before it closes. A bound method is
    held through its owner weakly, so a module-held client never keeps the app that
    registered it alive; a plain function stays strong."""

    def __init__(self) -> None:
        self._refs: list[Callable[[], Stop | None]] = []

    def add(self, stop: Stop) -> None:
        if stop in self:
            return
        if inspect.ismethod(stop):
            self._refs.append(weakref.WeakMethod(stop))
        else:
            self._refs.append(lambda: stop)

    def __iter__(self) -> Iterator[Stop]:
        live = [(ref, ref()) for ref in self._refs]
        self._refs = [ref for ref, stop in live if stop is not None]
        return iter([stop for _, stop in live if stop is not None])

    def __contains__(self, stop: object) -> bool:
        return any(stop == kept for kept in self)


def stop_before_redis_closes(
    redis_handler: object, stop: Callable[[], Awaitable[None]]
) -> None:
    # The class is asked, not the instance: a mock answers every attribute, and an
    # AsyncMock would hand back a coroutine nobody awaits.
    register = getattr(type(redis_handler), "register_background_user", None)
    if register is not None:
        register(redis_handler, stop)


async def stop_task_on_its_own_loop(task: asyncio.Task[None] | None) -> None:
    if task is None or task.done() or task.get_loop() is not asyncio.get_running_loop():
        return
    task.cancel()
    await asyncio.gather(task, return_exceptions=True)


def stop_task_from_another_thread(
    task: asyncio.Task[None] | None, stop_event: asyncio.Event
) -> None:
    """Ask a background task to end without awaiting it, from any thread. On its
    own loop the stop is immediate, from another thread it is queued there. A
    task whose loop is closed, stopped or done is only dropped."""
    if task is None or task.done():
        return
    loop = task.get_loop()
    if loop.is_closed() or not loop.is_running():
        return
    try:
        on_its_own_loop = asyncio.get_running_loop() is loop
    except RuntimeError:
        on_its_own_loop = False
    try:
        if on_its_own_loop:
            stop_event.set()
            task.cancel()
        else:
            loop.call_soon_threadsafe(stop_event.set)
            loop.call_soon_threadsafe(task.cancel)
    except RuntimeError:
        return


def background_task_is_live(task: asyncio.Task[None] | None) -> bool:
    return task is not None and not task.done()
