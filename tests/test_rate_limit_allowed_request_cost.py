from unittest.mock import patch

from guard_core.handlers import ratelimit_handler
from guard_core.handlers.ratelimit_handler import RateLimitManager
from guard_core.models import SecurityConfig
from tests.conftest import MockGuardRequest, MockGuardResponse

IP = "198.51.100.20"


async def _error_response(status_code: int, message: str) -> MockGuardResponse:
    return MockGuardResponse(message, status_code)


async def test_only_the_first_request_of_a_client_makes_an_lru_create_call() -> None:
    manager = RateLimitManager(
        SecurityConfig(enable_redis=False, rate_limit=1000, rate_limit_window=60)
    )
    request = MockGuardRequest(path="/x", client_host=IP)
    with patch.object(
        ratelimit_handler,
        "_lru_pop_or_create",
        wraps=ratelimit_handler._lru_pop_or_create,
    ) as create:
        for _ in range(5):
            assert await manager.check_rate_limit(request, IP, _error_response) is None

    assert create.call_count == 1
    assert len(manager.request_timestamps[IP]) == 5


async def test_a_new_client_past_the_cap_still_evicts_the_oldest() -> None:
    manager = RateLimitManager(
        SecurityConfig(
            enable_redis=False,
            rate_limit=1000,
            rate_limit_window=60,
            rate_limit_max_tracked_keys=2,
        )
    )
    request = MockGuardRequest(path="/x", client_host=IP)
    for client in ("203.0.113.1", "203.0.113.2", "203.0.113.3"):
        await manager.check_rate_limit(request, client, _error_response)

    assert list(manager.request_timestamps) == ["203.0.113.2", "203.0.113.3"]
