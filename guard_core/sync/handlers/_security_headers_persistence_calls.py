from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from guard_core.models import SyncSecurityConfig
    from guard_core.sync.protocols.redis_protocol import SyncSecurityHeadersRedisHandler


class SecurityHeadersPersistenceCalls:
    """The persistence methods the override mixin calls on the manager.

    They live in the cache mixin, which comes later in the manager's MRO, so the
    runtime finds them there. This class declares them for the type checker only
    and has no members at runtime, so it shadows nothing.
    """

    if TYPE_CHECKING:

        def initialize_redis(
            self,
            redis_handler: SyncSecurityHeadersRedisHandler,
            config: SyncSecurityConfig | None = ...,
        ) -> None: ...

        def _cache_configuration(self, own_state: bool = ...) -> None: ...

        def _load_cached_config(self, own_state: bool = ...) -> None: ...

        def _apply_own_state(
            self,
            csp: str | bytes | None,
            hsts: str | bytes | None,
            custom: str | bytes | None,
        ) -> None: ...
