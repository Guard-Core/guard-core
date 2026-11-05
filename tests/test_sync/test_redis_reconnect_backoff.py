import socket
import time
from collections.abc import Iterator
from time import monotonic
from urllib.parse import urlparse

import pytest

from guard_core.exceptions import GuardRedisError
from guard_core.models import SyncSecurityConfig
from guard_core.sync.handlers.redis_handler import RedisManager
from tests.test_sync.conftest import REDIS_URL, suite_redis_prefix

CONNECT_TIMEOUT = 0.5


class SilentServer:
    """A loopback port whose connections complete in the kernel backlog and are never
    answered: a Redis behind a partition, where the connect works and the read hangs."""

    def __init__(self) -> None:
        self._listener = socket.socket()
        self._listener.bind(("127.0.0.1", 0))
        self._listener.listen(128)
        self.port = int(self._listener.getsockname()[1])

    @property
    def url(self) -> str:
        return urlparse(REDIS_URL)._replace(netloc=f"127.0.0.1:{self.port}").geturl()

    def close(self) -> None:
        self._listener.close()


class Events:
    def __init__(self) -> None:
        self.actions: list[str] = []

    def send_event(self, event: object) -> None:
        self.actions.append(str(getattr(event, "action_taken", "")))

    def count(self, action: str) -> int:
        return self.actions.count(action)


@pytest.fixture
def silent() -> Iterator[SilentServer]:
    server = SilentServer()
    yield server
    server.close()


def partitioned_manager(server: SilentServer) -> tuple[RedisManager, Events]:
    manager = RedisManager(
        SyncSecurityConfig(
            enable_redis=True,
            redis_url=server.url,
            redis_prefix=suite_redis_prefix("wp450b"),
            redis_fail_open=True,
            enable_rate_limiting=False,
            redis_socket_connect_timeout=CONNECT_TIMEOUT,
            redis_socket_timeout=CONNECT_TIMEOUT,
            redis_retries=0,
        )
    )
    events = Events()
    manager.agent_handler = events
    return manager, events


def refused_after(manager: RedisManager) -> float:
    began = monotonic()
    with pytest.raises(GuardRedisError):
        with manager.get_connection():
            pass
    return monotonic() - began


def test_requests_a_second_apart_do_not_each_pay_a_connect(
    silent: SilentServer,
) -> None:
    manager, events = partitioned_manager(silent)
    durations = []
    for _ in range(3):
        durations.append(refused_after(manager))
        time.sleep(0.25)
    assert durations[0] >= CONNECT_TIMEOUT * 0.8
    assert durations[1] < 0.1
    assert durations[2] < 0.1
    assert events.count("connection_failed") == 1
