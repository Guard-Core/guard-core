import inspect
import threading
import weakref
from collections.abc import Callable, Iterator

Stop = Callable[[], None]


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


def stop_before_redis_closes(redis_handler: object, stop: Callable[[], None]) -> None:
    # The class is asked, not the instance: a mock answers every attribute, and an
    # AsyncMock would hand back a coroutine nobody awaits.
    register = getattr(type(redis_handler), "register_background_user", None)
    if register is not None:
        register(redis_handler, stop)


def stop_task_on_its_own_loop(task: threading.Thread | None) -> None:
    return None


def stop_task_from_another_thread(
    task: threading.Thread | None, stop_event: threading.Event
) -> None:
    """Ask a background thread to end without joining it, from any thread."""
    stop_event.set()
