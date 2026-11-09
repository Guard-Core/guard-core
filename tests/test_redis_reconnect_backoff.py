import asyncio
import socket
from collections.abc import Iterator
from time import monotonic
from urllib.parse import urlparse

import pytest

from guard_core.exceptions import GuardRedisError
from guard_core.handlers import redis_handler as redis_handler_module
from guard_core.handlers.redis_handler import RedisManager
from guard_core.models import SecurityConfig
from tests.conftest import REDIS_URL, suite_redis_prefix

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

    async def send_event(self, event: object) -> None:
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
        SecurityConfig(
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


async def refused_after(manager: RedisManager) -> float:
    began = monotonic()
    with pytest.raises(GuardRedisError):
        async with manager.get_connection():
            pass
    return monotonic() - began


async def test_requests_a_second_apart_do_not_each_pay_a_connect(
    silent: SilentServer,
) -> None:
    manager, events = partitioned_manager(silent)
    durations = []
    for _ in range(3):
        durations.append(await refused_after(manager))
        await asyncio.sleep(0.25)
    assert durations[0] >= CONNECT_TIMEOUT * 0.8
    assert durations[1] < 0.1
    assert durations[2] < 0.1
    assert events.count("connection_failed") == 1


async def test_concurrent_callers_share_one_attempt(  # async-only
    silent: SilentServer, monkeypatch: pytest.MonkeyPatch
) -> None:
    builds: list[int] = []
    real_build = redis_handler_module._build_redis_client

    def counting(url: str, size: int, pool_timeout: float, **kwargs: object) -> object:
        builds.append(1)
        return real_build(url, size, pool_timeout, **kwargs)

    monkeypatch.setattr(redis_handler_module, "_build_redis_client", counting)
    manager, events = partitioned_manager(silent)
    durations = list(await asyncio.gather(*(refused_after(manager) for _ in range(10))))
    durations.sort()
    assert len(builds) == 1
    # The callers of a first connect wait for that one attempt, as on v4.4.0 (D-290
    # item 1), and none starts a second: one failure is reported.
    assert durations[-1] < CONNECT_TIMEOUT * 1 + 1.0
    assert durations[0] >= CONNECT_TIMEOUT * 0.5
    assert events.count("connection_failed") == 1
