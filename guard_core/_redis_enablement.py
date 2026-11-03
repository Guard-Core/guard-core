from typing import Protocol


class RedisFieldsConfig(Protocol):
    @property
    def model_fields_set(self) -> set[str]: ...

    @property
    def redis_url(self) -> str | None: ...

    @property
    def enable_redis(self) -> bool: ...


REDIS_CONNECTION_FIELDS = (
    "redis_url",
    "redis_prefix",
    "redis_socket_connect_timeout",
    "redis_socket_timeout",
    "redis_health_check_interval",
    "redis_max_connections",
    "redis_pool_timeout",
    "redis_retries",
    "redis_fail_open",
)


def redis_connection_field_set_explicitly(config: RedisFieldsConfig) -> str | None:
    stated = config.model_fields_set
    if stated.isdisjoint(REDIS_CONNECTION_FIELDS):
        return None
    return next((name for name in REDIS_CONNECTION_FIELDS if name in stated), None)


def resolve_enable_redis(config: RedisFieldsConfig) -> None:
    stated = config.model_fields_set
    if "enable_redis" in stated:
        return
    # Written to __dict__ so enable_redis never joins model_fields_set: the
    # flag stays "unset" and resolves again when a connection field changes.
    config.__dict__["enable_redis"] = not stated.isdisjoint(REDIS_CONNECTION_FIELDS)


def configured_redis_url(config: RedisFieldsConfig) -> str | None:
    url: str | None = config.redis_url
    return url if config.enable_redis and url else None


def redis_is_configured(config: RedisFieldsConfig) -> bool:
    # Same rule as configured_redis_url, inline: this runs on every response.
    return bool(config.enable_redis and config.redis_url)
