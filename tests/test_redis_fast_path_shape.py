from redis import __version__ as REDIS_PY_VERSION
from redis.asyncio.connection import Connection

from guard_core.handlers._redis_fast_pool import (
    _COUNT_RECORDER,
    _RELEASE_EVENTS,
    _load_count_recorder,
    _load_release_events,
)
from guard_core.handlers.redis_handler import _build_redis_client
from tests.conftest import REDIS_URL

WHAT = (
    "the fast path of guard_core/handlers/_redis_fast_pool.py reads it; update "
    "the fast path before this redis-py is allowed in (it falls back to the "
    "plain pool, which is correct but slower)"
)


def test_the_release_event_and_its_default_listener_exist() -> None:
    assert _load_release_events() is not None, (
        f"redis-py {REDIS_PY_VERSION} lost AsyncAfterConnectionReleasedEvent or "
        f"AsyncReAuthConnectionListener in redis.event: {WHAT}"
    )


def test_the_dispatcher_keeps_its_listener_mapping_with_the_default_listener() -> None:
    assert _RELEASE_EVENTS is not None
    client = _build_redis_client(REDIS_URL, 2, 1.0)
    dispatcher = client.connection_pool._event_dispatcher
    mapping = getattr(dispatcher, "_event_listeners_mapping", None)
    assert isinstance(mapping, dict), (
        f"redis-py {REDIS_PY_VERSION}: EventDispatcher._event_listeners_mapping "
        f"is no longer a dict: {WHAT}"
    )
    listeners = mapping.get(_RELEASE_EVENTS[0])
    assert isinstance(listeners, list) and any(
        isinstance(item, _RELEASE_EVENTS[1]) for item in listeners
    ), (
        f"redis-py {REDIS_PY_VERSION}: the release event no longer has the "
        f"re-authentication listener in a list: {WHAT}"
    )


def test_a_connection_keeps_its_re_authentication_token() -> None:
    connection = Connection()
    assert hasattr(connection, "_re_auth_token"), (
        f"redis-py {REDIS_PY_VERSION}: Connection._re_auth_token is gone: {WHAT}"
    )
    assert connection._re_auth_token is None


def test_the_observability_singleton_and_its_provider_manager_exist() -> None:
    assert _load_count_recorder() is not None, (
        f"redis-py {REDIS_PY_VERSION} lost record_connection_count, "
        f"ConnectionState, get_pool_name or redis.observability.providers: {WHAT}"
    )
    assert _COUNT_RECORDER is not None
    providers = _COUNT_RECORDER[3]
    assert hasattr(providers, "_observability_instance"), (
        f"redis-py {REDIS_PY_VERSION}: redis.observability.providers."
        f"_observability_instance is gone: {WHAT}"
    )
    assert hasattr(providers.get_observability_instance(), "_provider_manager"), (
        f"redis-py {REDIS_PY_VERSION}: the observability instance has no "
        f"_provider_manager: {WHAT}"
    )


def test_an_async_connection_keeps_the_reader_the_fast_take_inspects() -> None:
    connection = Connection()
    assert hasattr(connection, "_reader"), (
        f"redis-py {REDIS_PY_VERSION}: Connection._reader is gone: {WHAT}"
    )
    assert connection._reader is None
