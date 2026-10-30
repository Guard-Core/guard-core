from asyncio import AbstractEventLoop as EventLoop
from asyncio import _get_running_loop as running_loop_or_none

__all__ = ["EventLoop", "running_loop_or_none"]
