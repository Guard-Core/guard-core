from guard_core.handlers._redis_shared_clients import connection_key_of
from guard_core.models import SecurityConfig


def test_a_config_without_redis_has_no_connection_key() -> None:
    assert connection_key_of(SecurityConfig()) is None


def test_a_config_with_a_redis_url_has_a_connection_key() -> None:
    config = SecurityConfig(redis_url="redis://localhost:6379/0")

    assert connection_key_of(config) is not None
