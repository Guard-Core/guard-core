import gc
import time
import weakref
from collections.abc import Generator
from unittest.mock import patch

import pytest
from redis import Redis

from guard_core.models import SyncSecurityConfig
from guard_core.sync.handlers import redis_handler as redis_handler_module
from guard_core.sync.handlers.redis_handler import RedisManager, close_redis_client
from tests.test_sync.conftest import suite_redis_prefix
from tests.test_sync.protocol_only_redis import REDIS_URL

IP_A = "198.51.100.10"
IP_B = "198.51.100.20"


def _config(prefix: str, **extra: object) -> SyncSecurityConfig:
    return SyncSecurityConfig(
        enable_redis=True, redis_url=REDIS_URL, redis_prefix=prefix, **extra
    )


def _prefix(tag: str) -> str:
    return suite_redis_prefix(f"wp74{tag}")


@pytest.fixture
def probe() -> Generator[Redis, None]:
    client = Redis.from_url(REDIS_URL, decode_responses=True)
    try:
        yield client
    finally:
        close_redis_client(client)


def _keys(probe: Redis, prefix: str) -> set[str]:
    return {key for key in probe.scan_iter(match=f"{prefix}*", count=500)}


def _drive_one_app(handler: RedisManager, ip: str) -> None:
    now = time.time()
    handler.write_ban_extending_only(
        "banned_ips", ip, str(now + 60), 60, version=("v", "c")
    )
    handler.record_sliding_window_hit("rate_limit", ip, now, now - 60, 60)
    handler.record_detection_strikes(ip, ["sqli"], now, now - 60, 60, 100)


def test_one_config_object_gives_one_manager() -> None:
    config = _config(_prefix("one"))
    assert RedisManager(config) is RedisManager(config)
    assert RedisManager(config).config is config


def test_two_config_objects_give_two_managers_each_keeping_its_own_config() -> None:
    first, second = _config(_prefix("a")), _config(_prefix("b"))
    manager_a, manager_b = RedisManager(first), RedisManager(second)
    assert manager_a is not manager_b
    assert manager_a.config is first
    assert manager_b.config is second
    assert manager_a.config.redis_prefix != manager_b.config.redis_prefix


def test_a_manager_nobody_holds_is_collected_and_its_config_gets_a_fresh_one() -> None:
    config = _config(_prefix("gc"))
    reference = weakref.ref(RedisManager(config))
    RedisManager._instance = None
    gc.collect()
    assert reference() is None
    assert RedisManager(config) is not None


def test_a_collected_config_leaves_no_registry_entry() -> None:
    config = _config(_prefix("cfg"))
    manager = RedisManager(config)
    from guard_core.sync.handlers import _redis_shared_clients

    kind = _redis_shared_clients._manager_kind(RedisManager)
    assert _redis_shared_clients._MANAGERS.lookup(config, kind) is manager
    key = (kind, id(config))
    del config, manager
    RedisManager._instance = None
    gc.collect()
    assert key not in _redis_shared_clients._MANAGERS._entries


def test_two_apps_keep_bans_rate_limits_and_strikes_under_their_own_prefix(
    probe: Redis,
) -> None:
    prefix_a, prefix_b = _prefix("a"), _prefix("b")
    app_a, app_b = RedisManager(_config(prefix_a)), RedisManager(_config(prefix_b))
    app_a.initialize()
    app_b.initialize()
    try:
        _drive_one_app(app_a, IP_A)
        _drive_one_app(app_b, IP_B)
        keys_a, keys_b = _keys(probe, prefix_a), _keys(probe, prefix_b)
        assert keys_a
        assert keys_b
        assert all(IP_B not in key for key in keys_a)
        assert all(IP_A not in key for key in keys_b)
        for kind in ("banned_ips", "rate_limit", "detection"):
            assert any(kind in key and IP_A in key for key in keys_a), kind
            assert any(kind in key and IP_B in key for key in keys_b), kind
        assert app_a.config.redis_prefix == prefix_a
        assert app_a.get_key("banned_ips", IP_B) is None
        assert app_b.get_key("banned_ips", IP_A) is None
    finally:
        app_a.delete_pattern("*")
        app_b.delete_pattern("*")
        app_a.close()
        app_b.close()


def test_instance_is_the_most_recently_initialized_manager_in_both_orders() -> None:
    app_a, app_b = (
        RedisManager(_config(_prefix("a"))),
        RedisManager(_config(_prefix("b"))),
    )
    try:
        app_a.initialize()
        app_b.initialize()
        assert RedisManager._instance is app_b
        app_b.initialize()
        app_a.initialize()
        assert RedisManager._instance is app_a
    finally:
        app_a.close()
        app_b.close()
    app_c, app_d = (
        RedisManager(_config(_prefix("c"))),
        RedisManager(_config(_prefix("d"))),
    )
    try:
        assert RedisManager._instance is app_d
        app_c.initialize()
        assert RedisManager._instance is app_c
    finally:
        app_c.close()
        app_d.close()


def _released_fastapi_guard_resolves_the_handler() -> RedisManager | None:
    # fastapi-guard 8.1.2 guard/lifespan.py:_find_security_redis_handler (the
    # websocket path, guard/websocket.py:303 -> lifespan.py:48-56) takes this.
    instance = RedisManager._instance
    if instance is not None and instance._redis is not None:
        return instance
    return None


def test_released_websocket_path_gets_the_last_initialized_handler() -> None:
    app_a, app_b = (
        RedisManager(_config(_prefix("a"))),
        RedisManager(_config(_prefix("b"))),
    )
    try:
        assert _released_fastapi_guard_resolves_the_handler() is None
        app_a.initialize()
        assert _released_fastapi_guard_resolves_the_handler() is app_a
        app_b.initialize()
        resolved = _released_fastapi_guard_resolves_the_handler()
        assert resolved is app_b
        assert resolved is not app_a
    finally:
        app_a.close()
        app_b.close()


def test_managers_on_the_same_connection_settings_share_one_client() -> None:
    app_a, app_b = (
        RedisManager(_config(_prefix("a"))),
        RedisManager(_config(_prefix("b"))),
    )
    builds: list[str] = []
    real = redis_handler_module._build_redis_client

    def counting(
        url: str, max_connections: int, pool_timeout: float, **connection_kwargs: object
    ) -> Redis:
        builds.append(url)
        return real(url, max_connections, pool_timeout, **connection_kwargs)

    with patch.object(redis_handler_module, "_build_redis_client", counting):
        app_a.initialize()
        app_b.initialize()
    try:
        assert len(builds) == 1
        assert app_a._redis is app_b._redis
        app_a.close()
        with app_b.get_connection() as conn:
            assert conn.ping()
    finally:
        app_b.close()
    assert app_b._redis is None


def test_the_last_manager_to_close_drops_the_shared_client() -> None:
    app_a, app_b = (
        RedisManager(_config(_prefix("a"))),
        RedisManager(_config(_prefix("b"))),
    )
    app_a.initialize()
    app_b.initialize()
    from guard_core.sync.handlers import _redis_shared_clients

    key = app_a._pool_key
    assert key is not None
    assert key == app_b._pool_key
    app_a.close()
    assert key in _redis_shared_clients._entries
    app_b.close()
    assert key not in _redis_shared_clients._entries


def test_different_connection_settings_get_different_clients() -> None:
    app_a = RedisManager(_config(_prefix("a"), redis_socket_timeout=3.0))
    app_b = RedisManager(_config(_prefix("b"), redis_socket_timeout=7.0))
    app_a.initialize()
    app_b.initialize()
    try:
        assert app_a._redis is not app_b._redis
    finally:
        app_a.close()
        app_b.close()


def test_ten_apps_on_one_redis_hold_the_connections_one_app_holds() -> None:
    def own_connections(handlers: list[RedisManager]) -> int:
        pools = {
            id(handler._redis.connection_pool): handler._redis.connection_pool
            for handler in handlers
            if handler._redis is not None
        }
        return sum(
            len(pool._available_connections) + len(pool._in_use_connections)
            for pool in pools.values()
        )

    def held_by(apps: int) -> int:
        handlers = [RedisManager(_config(_prefix(f"n{i}"))) for i in range(apps)]
        try:
            for handler in handlers:
                handler.initialize()
                assert handler.set_key("ns", "k", "v")
            return own_connections(handlers)
        finally:
            for handler in handlers:
                handler.delete_pattern("*")
            for handler in handlers:
                handler.close()

    one = held_by(1)
    assert one >= 1
    assert held_by(10) == one


class _Scope:
    pass


class _Owner:
    def __init__(self) -> None:
        self.closed: list[object] = []

    def _safe_aclose(self, client: object) -> None:
        self.closed.append(client)


def test_pool_keys_tell_settings_apart_by_value_never_by_object_identity() -> None:
    from guard_core.sync.handlers import _redis_shared_clients as pool

    scope = _Scope()
    same = [
        pool.pool_key(
            "u", 5, 1.0, {"retry": _Scope(), "ids": [1, 2], "r": range(3)}, scope
        )
        for _ in range(2)
    ]
    assert same[0] == same[1]
    assert same[0] != pool.pool_key("u", 5, 1.0, {"ids": [1, 3]}, scope)
    assert same[0] != pool.pool_key("u", 5, 1.0, {"retry": _Scope()}, _Scope())


def test_a_shared_client_of_another_scope_or_without_owners_is_never_handed_out() -> (
    None
):
    from guard_core.sync.handlers import _redis_shared_clients as pool

    scope, owner, client = _Scope(), _Owner(), object()
    key = ("stale", id(scope))
    assert pool.publish(key, scope, client, owner) is client
    assert pool.acquire(key, _Scope(), _Owner()) is None
    assert key not in pool._entries
    assert pool.publish(key, scope, client, owner) is client
    del owner
    gc.collect()
    assert pool.acquire(key, scope, _Owner()) is None
    assert key not in pool._entries


def test_a_client_published_first_wins_and_an_unknown_release_asks_for_a_close() -> (
    None
):
    from guard_core.sync.handlers import _redis_shared_clients as pool

    scope, first, second = _Scope(), _Owner(), _Owner()
    key = ("race", id(scope))
    winner, loser = object(), object()
    assert pool.publish(key, scope, winner, first) is winner
    assert pool.publish(key, scope, loser, second) is winner
    assert pool.release(key, winner, first) is False
    assert pool.release(key, winner, second) is True
    assert pool.release(key, winner, second) is True
    assert pool.release(("never", 0), loser, second) is True


def test_a_duplicate_client_is_closed_when_another_one_was_published_first() -> None:
    from guard_core.sync.handlers import _redis_shared_clients as pool

    scope, first, second = _Scope(), _Owner(), _Owner()
    key = ("dup", id(scope))
    winner, loser = object(), object()
    assert pool.register_client(first, winner, key, scope) is winner
    assert pool.register_client(second, loser, key, scope) is winner
    assert second.closed == [loser]
    assert first.closed == []
    assert pool.release(key, winner, first) is False
    assert pool.release(key, winner, second) is True
