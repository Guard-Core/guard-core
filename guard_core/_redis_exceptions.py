from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from redis.exceptions import ConnectionError as RedisConnectionError
    from redis.exceptions import NoScriptError, RedisError
    from redis.exceptions import TimeoutError as RedisTimeoutError
else:
    try:
        from redis.exceptions import ConnectionError as RedisConnectionError
        from redis.exceptions import NoScriptError, RedisError
        from redis.exceptions import TimeoutError as RedisTimeoutError
    except ImportError:

        class RedisError(Exception):
            pass

        class RedisConnectionError(RedisError):
            pass

        class RedisTimeoutError(RedisError):
            pass

        class NoScriptError(RedisError):
            pass


__all__ = [
    "NoScriptError",
    "RedisConnectionError",
    "RedisError",
    "RedisTimeoutError",
]
