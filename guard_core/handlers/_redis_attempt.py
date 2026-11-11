import asyncio
import weakref
from collections.abc import Callable, Coroutine


class ConnectionLocks:
    """The connection lock of one manager: one asyncio.Lock per running loop. A
    contended asyncio.Lock binds the loop it first waited on and raises on another."""

    def __init__(self) -> None:
        self._locks: weakref.WeakKeyDictionary[
            asyncio.AbstractEventLoop, asyncio.Lock
        ] = weakref.WeakKeyDictionary()

    def here(self) -> asyncio.Lock:
        loop = asyncio.get_running_loop()
        # A contended lock holds its loop, so a closed loop would never be freed.
        for ended in [known for known in self._locks if known.is_closed()]:
            del self._locks[ended]
        lock = self._locks.get(loop)
        if lock is None:
            lock = self._locks[loop] = asyncio.Lock()
        return lock

    def any_locked(self) -> bool:
        return any(lock.locked() for lock in self._locks.values())


class RedisAttemptSlot:
    """The one reconnect attempt a degraded manager runs off the request path. The
    task is held here because the loop keeps only a weak reference to its tasks."""

    def __init__(self) -> None:
        self._task: asyncio.Task[None] | None = None

    def spawn(self, work: Callable[[], Coroutine[object, object, None]]) -> None:
        self._task = asyncio.get_running_loop().create_task(work())

    async def stop(self) -> None:
        task = self._task
        if task is None or task.done():
            return
        loop = task.get_loop()
        if loop is asyncio.get_running_loop():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
        elif not loop.is_closed():
            loop.call_soon_threadsafe(task.cancel)
