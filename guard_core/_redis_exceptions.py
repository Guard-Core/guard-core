from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from redis.exceptions import ConnectionError as RedisConnectionError
    from redis.exceptions import NoScriptError, RedisError, ResponseError
    from redis.exceptions import TimeoutError as RedisTimeoutError
else:
    _resolved: dict[str, type[Exception]] = {}

    def __getattr__(name: str) -> type[Exception]:
        if name not in __all__:
            raise AttributeError(name)
        if _resolved:
            return _resolved[name]
        try:
            import redis.exceptions as redis_exceptions

            _resolved.update(
                {
                    "NoScriptError": redis_exceptions.NoScriptError,
                    "RedisConnectionError": redis_exceptions.ConnectionError,
                    "RedisError": redis_exceptions.RedisError,
                    "RedisTimeoutError": redis_exceptions.TimeoutError,
                    "ResponseError": redis_exceptions.ResponseError,
                }
            )
        except ImportError:

            class RedisError(Exception):
                pass

            class RedisConnectionError(RedisError):
                pass

            class RedisTimeoutError(RedisError):
                pass

            class NoScriptError(RedisError):
                pass

            class ResponseError(RedisError):
                pass

            _resolved.update(
                {
                    "NoScriptError": NoScriptError,
                    "RedisConnectionError": RedisConnectionError,
                    "RedisError": RedisError,
                    "RedisTimeoutError": RedisTimeoutError,
                    "ResponseError": ResponseError,
                }
            )
        return _resolved[name]


__all__ = [
    "NoScriptError",
    "RedisConnectionError",
    "RedisError",
    "RedisTimeoutError",
    "ResponseError",
]
