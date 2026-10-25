import logging
import subprocess
import sys
import textwrap
from collections.abc import Iterator
from typing import Any
from unittest.mock import MagicMock, Mock

import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.sync.handlers.redis_handler import (
    RedisHandlerBase,
    RedisManager,
    scan_unlink,
)

_SHA1_CALLS_PROBE = textwrap.dedent(
    """
    import hashlib

    real = hashlib.sha1
    calls = []

    def spy(data=b"", *args, **kwargs):
        calls.append(kwargs)
        return real(data, *args, **kwargs)

    hashlib.sha1 = spy
    import guard_core.handlers.redis_handler

    print(len(calls), all(c == {"usedforsecurity": False} for c in calls))
    """
)


def test_a_redis_event_names_the_redis_handler_as_its_source() -> None:
    manager = RedisManager(SyncSecurityConfig(enable_redis=True, redis_url="redis://x"))
    agent = MagicMock()
    manager.agent_handler = agent

    manager._send_redis_event("redis_connection", "established", "ok", a=1)

    event = agent.send_event.call_args[0][0]
    assert event.handler_name == "redis"
    assert event.metadata == {"a": 1}


def test_every_script_digest_is_declared_not_for_security() -> None:
    result = subprocess.run(
        [sys.executable, "-I", "-c", _SHA1_CALLS_PROBE],
        capture_output=True,
        text=True,
        check=True,
        timeout=60,
    )

    assert result.stdout.split() == ["8", "True"]


def test_a_redis_event_carries_the_action_and_the_system_address() -> None:
    manager = RedisManager(SyncSecurityConfig(enable_redis=True, redis_url="redis://x"))
    agent = MagicMock()
    manager.agent_handler = agent

    manager._send_redis_event("redis_connection", "established", "why")

    event = agent.send_event.call_args[0][0]
    assert event.event_type == "redis_connection"
    assert event.ip_address == "system"
    assert event.action_taken == "established"
    assert event.reason == "why"
    assert event.metadata == {}


def test_a_redis_event_failure_is_logged_with_its_cause(
    caplog: pytest.LogCaptureFixture,
) -> None:
    manager = RedisManager(SyncSecurityConfig(enable_redis=True, redis_url="redis://x"))
    manager.agent_handler = MagicMock(send_event=MagicMock(side_effect=OSError("boom")))

    with caplog.at_level(logging.ERROR, logger="guard_core.sync.handlers.redis"):
        manager._send_redis_event("t", "a", "r")

    assert "Failed to send Redis event to agent: boom" in [
        r.getMessage() for r in caplog.records
    ]


class _ScanConnection:
    def __init__(self, keys: list[str]) -> None:
        self.keys = keys
        self.scan_counts: list[int] = []
        self.scanned: list[str] = []
        self.unlinked: list[tuple[str, ...]] = []

    def scan_iter(self, match: str, count: int) -> Iterator[str]:
        self.scan_counts.append(count)
        for key in self.keys:
            self.scanned.append(key)
            yield key

    def unlink(self, *keys: str) -> int:
        self.unlinked.append(keys)
        return len(keys)


def test_scan_unlink_scans_and_unlinks_in_batches_of_500() -> None:
    connection = _ScanConnection([f"k{i}" for i in range(1001)])

    removed = scan_unlink(Mock(wraps=connection), "k*")

    assert removed == 1001
    assert connection.scan_counts == [500]
    assert len(connection.scanned) == 1001
    assert [len(batch) for batch in connection.unlinked] == [500, 500, 1]


def test_keys_scans_with_a_count_of_500() -> None:
    handler = RedisHandlerBase(
        SyncSecurityConfig(enable_redis=True, redis_url="redis://x", redis_prefix="p:")
    )
    connection = _ScanConnection(["p:a", "p:b", "p:a"])
    handler._redis = Mock(wraps=connection)

    assert handler.keys("*") == ["p:a", "p:b"]
    assert connection.scan_counts == [500]


def _built_with(monkeypatch: pytest.MonkeyPatch, **settings: Any) -> tuple[Any, ...]:
    calls: list[tuple[Any, ...]] = []

    def build(*args: Any, **kwargs: Any) -> Any:
        calls.append(args)
        return Mock(ping=MagicMock(), aclose=MagicMock())

    monkeypatch.setattr(
        "guard_core.sync.handlers.redis_handler._build_redis_client", build
    )
    config = SyncSecurityConfig(enable_redis=True, redis_url="redis://x", **settings)
    RedisHandlerBase(config).initialize()
    return calls[0]


def test_the_pool_defaults_to_100_connections(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    args = _built_with(monkeypatch)

    assert args[1] == 100


def test_a_configured_pool_size_is_used(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    args = _built_with(monkeypatch, redis_max_connections=7)

    assert args[1] == 7


def test_connection_kwargs_come_from_the_given_config_not_the_managers() -> None:
    manager = RedisHandlerBase(
        SyncSecurityConfig(
            enable_redis=True, redis_url="redis://x", redis_socket_timeout=1
        )
    )
    other = SyncSecurityConfig(
        enable_redis=True, redis_url="redis://x", redis_socket_timeout=9
    )

    assert manager._connection_kwargs(other)["socket_timeout"] == 9
    assert manager._connection_kwargs()["socket_timeout"] == 1


def test_a_fresh_redis_manager_is_open_and_has_no_agent_client_or_odd_logger() -> None:
    original = RedisManager._instance
    RedisManager._instance = None
    try:
        manager = RedisManager(
            SyncSecurityConfig(enable_redis=True, redis_url="redis://x")
        )

        assert RedisManager._redis is None
        assert RedisManager._closed is False
        assert manager._closed is False
        assert manager.agent_handler is None
        assert manager.logger.name == "guard_core.sync.handlers.redis"
    finally:
        RedisManager._instance = original


def test_initialize_agent_stores_the_agent_handler() -> None:
    handler = RedisHandlerBase(
        SyncSecurityConfig(enable_redis=True, redis_url="redis://x")
    )
    agent = MagicMock()

    handler.initialize_agent(agent)

    assert handler.agent_handler is agent


def test_a_custom_handler_starts_without_an_agent() -> None:
    handler = RedisHandlerBase(
        SyncSecurityConfig(enable_redis=True, redis_url="redis://x")
    )

    assert handler.agent_handler is None
