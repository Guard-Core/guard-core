import threading
from collections.abc import Callable


def stop_before_redis_closes(redis_handler: object, stop: Callable[[], None]) -> None:
    # The class is asked, not the instance: a mock answers every attribute, and an
    # AsyncMock would hand back a coroutine nobody awaits.
    register = getattr(type(redis_handler), "register_background_user", None)
    if register is not None:
        register(redis_handler, stop)


def stop_task_on_its_own_loop(task: threading.Thread | None) -> None:
    return None
