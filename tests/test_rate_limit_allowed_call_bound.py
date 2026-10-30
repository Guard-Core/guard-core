import sys
from types import FrameType
from typing import Any

from guard_core.handlers.ratelimit_handler import RateLimitManager
from guard_core.models import SecurityConfig
from tests.conftest import MockGuardRequest, MockGuardResponse

# Python and C calls one allowed in-memory check_rate_limit made at v4.4.0, counted
# with sys.setprofile on 3.11. Lock enter and exit (the sync mirror holds a lock)
# and the profiler's own stop are left out. LEDGER 6.427: the multi-tier verdict
# machinery had raised it to 15 and the CPU per call to 2.2x v4.4.0.
CALLS_PER_ALLOWED_CHECK_AT_V440 = 8
CHECKS = 100
UNCOUNTED_C_CALLS = ("__enter__", "__exit__", "setprofile")


async def _error_response(status_code: int, message: str) -> MockGuardResponse:
    return MockGuardResponse(message, status_code)


async def test_an_allowed_in_memory_check_makes_no_more_calls_than_v440() -> None:
    manager = RateLimitManager(
        SecurityConfig(enable_redis=False, rate_limit=10**9, rate_limit_window=60)
    )
    request = MockGuardRequest(path="/x", client_host="10.1.1.1")
    for _ in range(CHECKS):
        await manager.check_rate_limit(request, "10.1.1.1", _error_response)
    calls = 0

    def count(frame: FrameType, event: str, arg: Any) -> None:
        nonlocal calls
        calls += event == "call" or (
            event == "c_call" and getattr(arg, "__name__", "") not in UNCOUNTED_C_CALLS
        )

    sys.setprofile(count)
    try:
        for _ in range(CHECKS):
            assert (
                await manager.check_rate_limit(request, "10.1.1.1", _error_response)
                is None
            )
    finally:
        sys.setprofile(None)

    print("PERCALL", calls / CHECKS)
    assert calls / CHECKS <= CALLS_PER_ALLOWED_CHECK_AT_V440
