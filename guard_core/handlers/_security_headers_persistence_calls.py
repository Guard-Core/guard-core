from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from guard_core.models import SecurityConfig
    from guard_core.protocols.redis_protocol import SecurityHeadersRedisHandler


class SecurityHeadersPersistenceCalls:
    """The persistence methods the override mixin calls on the manager.

    They live in the cache mixin, which comes later in the manager's MRO, so the
    runtime finds them there. This class declares them for the type checker only
    and has no members at runtime, so it shadows nothing.
    """

    if TYPE_CHECKING:

        async def initialize_redis(
            self,
            redis_handler: SecurityHeadersRedisHandler,
            config: SecurityConfig | None = ...,
        ) -> None: ...

        async def _cache_configuration(self, own_state: bool = ...) -> None: ...

        async def _load_cached_config(self, own_state: bool = ...) -> None: ...

        def _apply_own_state(
            self,
            csp: str | bytes | None,
            hsts: str | bytes | None,
            custom: str | bytes | None,
        ) -> None: ...
