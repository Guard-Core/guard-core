import sys
from collections.abc import Awaitable, Callable
from types import FrameType

from guard_core.handlers.redis_handler import RedisManager
from guard_core.models import SecurityConfig
from tests.conftest import REDIS_URL, suite_redis_prefix

# Calls one healthy RedisManager.get_key makes beyond the calls of the same GET
# sent straight on the manager's own client, counted with sys.setprofile (Python
# and C calls). Counting the difference keeps the bound the same on every Python
# and redis-py version. LEDGER 6.699: the weak config reads, the repeated
# enablement test, the safe_operation closure and the generator context manager
# had put the CPU per call about 7 percent above v4.4.0 (D-143). Measured on 3.10
# and 3.15: 29 to 32 before the fix, 12 to 14.2 after, v4.4.0 20 to 26.
EXTRA_CALLS_PER_GET_KEY = 16
CALLS = 100
UNCOUNTED_C_CALLS = ("setprofile",)


async def _calls_per_operation(operation: Callable[[], Awaitable[object]]) -> float:
    for _ in range(CALLS):
        await operation()
    calls = 0

    def count(frame: FrameType, event: str, arg: object) -> None:
        nonlocal calls
        calls += event == "call" or (
            event == "c_call" and getattr(arg, "__name__", "") not in UNCOUNTED_C_CALLS
        )

    sys.setprofile(count)
    try:
        for _ in range(CALLS):
            assert await operation() == "v"
    finally:
        sys.setprofile(None)
    return calls / CALLS


async def test_a_healthy_get_key_makes_no_more_extra_calls_than_the_bound() -> None:
    prefix = suite_redis_prefix("wp503calls")
    manager = RedisManager(
        SecurityConfig(enable_redis=True, redis_url=REDIS_URL, redis_prefix=prefix)
    )
    await manager.initialize()
    await manager.set_key("calls", "k", "v", ttl=30)
    client = manager._redis
    assert client is not None
    try:
        raw = await _calls_per_operation(lambda: client.get(f"{prefix}calls:k"))
        through_get_key = await _calls_per_operation(
            lambda: manager.get_key("calls", "k")
        )
    finally:
        await manager.close()

    print("PERCALL raw", raw, "get_key", through_get_key)
    assert through_get_key - raw <= EXTRA_CALLS_PER_GET_KEY
