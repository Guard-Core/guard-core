from guard_core.models import SecurityConfig
from guard_core.sync.handlers.ratelimit_handler import (
    RateLimitManager,
    rate_limit_handler,
)
from tests.test_sync.conftest import MockGuardResponse, SyncMockGuardRequest

IP = "198.51.100.40"


def _error_response(status_code: int, message: str) -> MockGuardResponse:
    return MockGuardResponse(message, status_code)


def _manager(limit: int) -> tuple[RateLimitManager, SecurityConfig]:
    config = SecurityConfig(enable_redis=False, rate_limit=limit, rate_limit_window=60)
    return RateLimitManager(config), config


def _hit(manager: RateLimitManager) -> bool:
    request = SyncMockGuardRequest(path="/x", client_host=IP)
    return manager.check_rate_limit(request, IP, _error_response) is None


def test_each_construction_is_its_own_manager_with_its_own_config() -> None:
    manager_a, config_a = _manager(3)
    manager_b, config_b = _manager(1000)

    assert manager_a is not manager_b
    assert manager_a.config is config_a
    assert manager_b.config is config_b


def test_one_apps_hits_never_count_against_another_app() -> None:
    manager_a, _ = _manager(3)
    manager_b, _ = _manager(1000)

    for _ in range(5):
        assert _hit(manager_b)

    assert [_hit(manager_a) for _ in range(5)] == [True, True, True, False, False]


def test_resetting_one_app_leaves_the_other_alone() -> None:
    manager_a, _ = _manager(1)
    manager_b, _ = _manager(1)
    assert _hit(manager_a)
    assert _hit(manager_b)

    manager_a.reset()

    assert _hit(manager_a)
    assert not _hit(manager_b)


def test_the_class_and_its_module_alias_keep_their_constructor() -> None:
    config = SecurityConfig(enable_redis=False)

    assert isinstance(rate_limit_handler(config), RateLimitManager)
    assert rate_limit_handler is RateLimitManager
