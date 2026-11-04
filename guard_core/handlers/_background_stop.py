import asyncio
from collections.abc import Awaitable, Callable


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
