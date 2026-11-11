import sys
import threading
from collections.abc import Iterator

import pytest

from guard_core._utils.app_managers import AppManagers, release_app

_THREADS = 8
_ROUNDS = 3000


class _NoRedisConfig:
    redis_url = None
    enable_redis = False
    redis_prefix = "wp616:threads:"


class _Manager:
    pass


@pytest.fixture
def fast_thread_switching() -> Iterator[None]:
    before = sys.getswitchinterval()
    sys.setswitchinterval(1e-6)
    yield
    sys.setswitchinterval(before)


def test_bind_and_release_from_many_threads_leave_no_error_and_a_free_default(
    fast_thread_switching: None,
) -> None:
    managers: AppManagers[_Manager] = AppManagers("pin_threads")
    default = _Manager()
    errors: list[str] = []

    def bind_then_release() -> None:
        try:
            for _ in range(_ROUNDS):
                config = _NoRedisConfig()
                managers.bind(config, default, _Manager)
                release_app(config)
        except Exception as error:
            errors.append(repr(error))

    threads = [threading.Thread(target=bind_then_release) for _ in range(_THREADS)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert errors == []
    assert managers.bind(_NoRedisConfig(), default, _Manager) is default
