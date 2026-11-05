import logging

import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.sync._utils.app_managers import AppManagers, _warn_split_connection

LOGGER = "guard_core.sync.handlers.app_managers"
URL = "redis://one.invalid:6379/0"


class _Manager:
    pass


def _config(
    url: str = URL,
    *,
    redis_max_connections: int | None = None,
    redis_pool_timeout: float = 5.0,
    redis_socket_timeout: float | None = 5.0,
    redis_retries: int = 0,
) -> SyncSecurityConfig:
    return SyncSecurityConfig(
        enable_redis=True,
        redis_url=url,
        redis_prefix="wp461:",
        enable_agent=False,
        redis_max_connections=redis_max_connections,
        redis_pool_timeout=redis_pool_timeout,
        redis_socket_timeout=redis_socket_timeout,
        redis_retries=redis_retries,
    )


def _bind(first: SyncSecurityConfig, second: SyncSecurityConfig) -> None:
    managers: AppManagers[_Manager] = AppManagers(
        "wp461", warns_on_split_connection=True
    )
    default = _Manager()
    managers.bind(first, default, _Manager)
    assert managers.bind(second, default, _Manager) is not default


def _warnings(caplog: pytest.LogCaptureFixture) -> list[str]:
    return [r.getMessage() for r in caplog.records if r.name == LOGGER]


def test_max_connections_difference_is_named_with_both_values(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.WARNING, logger=LOGGER)
    _bind(_config(redis_max_connections=10), _config(redis_max_connections=20))
    (message,) = _warnings(caplog)
    assert (
        "redis_max_connections=10" in message and "redis_max_connections=20" in message
    )
    assert "event loop" not in message
    assert "redis_pool_timeout" not in message


def test_pool_timeout_and_socket_settings_are_named(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.WARNING, logger=LOGGER)
    _bind(
        _config(redis_pool_timeout=5.0, redis_socket_timeout=1.0, redis_retries=0),
        _config(redis_pool_timeout=7.0, redis_socket_timeout=2.0, redis_retries=2),
    )
    (message,) = _warnings(caplog)
    assert "redis_pool_timeout=5.0" in message and "redis_pool_timeout=7.0" in message
    assert "socket_timeout=1.0" in message and "socket_timeout=2.0" in message
    assert "a different retry, a different retry_on_error" in message


def test_a_different_scope_is_named_as_the_event_loop(
    caplog: pytest.LogCaptureFixture,
) -> None:
    from guard_core.sync.handlers._redis_shared_clients import PoolKey

    caplog.set_level(logging.WARNING, logger=LOGGER)
    config = _config()
    _warn_split_connection(
        config,
        config,
        PoolKey(URL, 1, 1.0, (), 1),
        PoolKey(URL, 1, 1.0, (), 2),
    )
    (message,) = _warnings(caplog)
    assert "on one event loop" in message and "on another event loop" in message
    assert "redis_max_connections" not in message


def test_different_urls_name_both_redacted_urls(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.WARNING, logger=LOGGER)
    _bind(
        _config("redis://user:hunter2@one.invalid:6379/0"),
        _config("redis://two.invalid:6380/1?password=hunter3"),
    )
    (message,) = _warnings(caplog)
    assert "one.invalid:6379" in message
    assert "two.invalid:6380" in message
    assert "hunter2" not in message
    assert "hunter3" not in message


def test_a_credential_never_reaches_the_log(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.WARNING, logger=LOGGER)
    url = "redis://user:hunter2@one.invalid:6379/0"
    _bind(_config(url, redis_max_connections=10), _config(url, redis_retries=3))
    (message,) = _warnings(caplog)
    assert "hunter2" not in message
    assert "redis_max_connections=10" in message


def test_a_non_numeric_setting_value_is_never_printed(
    caplog: pytest.LogCaptureFixture,
) -> None:
    from guard_core.sync.handlers._redis_shared_clients import PoolKey

    caplog.set_level(logging.WARNING, logger=LOGGER)
    first = PoolKey(URL, 1, 1.0, (("password", "hunter2"), ("socket_timeout", "s3")), 1)
    second = PoolKey(URL, 1, 1.0, (("password", "hunter4"), ("socket_timeout", 2)), 1)
    config = _config()
    _warn_split_connection(config, config, first, second)
    (message,) = _warnings(caplog)
    assert "a different password" in message
    assert "socket_timeout=" not in message
    for secret in ("hunter2", "hunter4", "s3"):
        assert secret not in message
    assert "socket_timeout" in message


def test_without_keys_the_warning_names_the_redacted_urls(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.WARNING, logger=LOGGER)
    _warn_split_connection(
        _config("redis://u:hunter2@one.invalid:6379/0"),
        _config("redis://two.invalid:6379/0"),
        None,
        None,
    )
    (message,) = _warnings(caplog)
    assert "one.invalid" in message
    assert "two.invalid" in message
    assert "hunter2" not in message
