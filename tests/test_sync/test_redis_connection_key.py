from guard_core.models import SyncSecurityConfig
from guard_core.sync.handlers._redis_shared_clients import connection_key_of


def test_a_config_without_redis_has_no_connection_key() -> None:
    assert connection_key_of(SyncSecurityConfig()) is None


def test_a_config_with_a_redis_url_has_a_connection_key() -> None:
    config = SyncSecurityConfig(redis_url="redis://localhost:6379/0")

    assert connection_key_of(config) is not None
