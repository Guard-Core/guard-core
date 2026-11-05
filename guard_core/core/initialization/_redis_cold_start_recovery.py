import asyncio
import logging
from collections.abc import Awaitable, Callable
from time import monotonic
from typing import TYPE_CHECKING

from guard_core._utils.app_scope import app_scope_of, in_app_scope
from guard_core.core.checks.base import SecurityCheck
from guard_core.core.checks.pipeline import REDIS_OUTAGE_RETRY_AFTER
from guard_core.protocols.request_protocol import GuardRequest
from guard_core.protocols.response_protocol import GuardResponse

if TYPE_CHECKING:
    from guard_core.core.checks.pipeline import SecurityCheckPipeline
    from guard_core.models import SecurityConfig
    from guard_core.protocols.middleware_protocol import GuardMiddlewareProtocol

# The pause the 503 tells clients to wait: one attempt per 5 s at most.
REDIS_COLD_START_RETRY_INTERVAL = REDIS_OUTAGE_RETRY_AFTER


class RedisColdStartRecoveryCheck(SecurityCheck):
    """Present in a pipeline only between a cold Redis failure under
    redis_fail_open=True and the first successful reconnection."""

    def __init__(
        self,
        middleware: "GuardMiddlewareProtocol",
        recover: Callable[[], Awaitable[None]],
    ) -> None:
        super().__init__(middleware)
        self._recover = recover

    @property
    def check_name(self) -> str:
        return "redis_cold_start_recovery"

    async def check(self, request: GuardRequest) -> GuardResponse | None:
        await self._recover()
        return None


class RedisColdStartRecoveryMixin:
    config: "SecurityConfig"
    logger: logging.Logger

    _recovery_pipeline: "SecurityCheckPipeline | None" = None
    _recovery_middleware: "GuardMiddlewareProtocol | None" = None
    _recovery_check: RedisColdStartRecoveryCheck | None = None
    _recovery_retry_at = 0.0
    _recovery_lock: asyncio.Lock

    _connect_redis: Callable[[], Awaitable[bool]]

    async def _initialize_connected_redis_handlers(self) -> None: ...

    def bind_redis_recovery_pipeline(
        self,
        pipeline: "SecurityCheckPipeline",
        middleware: "GuardMiddlewareProtocol",
    ) -> None:
        self._recovery_pipeline = pipeline
        self._recovery_middleware = middleware
        self._recovery_lock = asyncio.Lock()

    def _arm_redis_cold_start_recovery(self) -> None:
        pipeline, middleware = self._recovery_pipeline, self._recovery_middleware
        if pipeline is None or middleware is None or self._recovery_check is not None:
            return
        self._recovery_retry_at = monotonic() + REDIS_COLD_START_RETRY_INTERVAL
        self._recovery_check = RedisColdStartRecoveryCheck(
            middleware, self._recover_redis_after_cold_start
        )
        # Appended last and popped last: a request already walking the list never
        # sees an earlier check shift, so none runs twice or is skipped.
        pipeline.add_check(self._recovery_check)

    def _disarm_redis_cold_start_recovery(self) -> None:
        check, self._recovery_check = self._recovery_check, None
        if check is not None and self._recovery_pipeline is not None:
            self._recovery_pipeline.remove_check(check.check_name)

    def _redis_recovery_due(self) -> bool:
        return (
            self._recovery_check is not None and monotonic() >= self._recovery_retry_at
        )

    async def _recover_redis_after_cold_start(self) -> None:
        if not self._redis_recovery_due() or self._recovery_lock.locked():
            return
        async with self._recovery_lock:
            if not self._redis_recovery_due():
                return
            self._recovery_retry_at = monotonic() + REDIS_COLD_START_RETRY_INTERVAL
            try:
                with in_app_scope(app_scope_of(self.config)):
                    if not await self._connect_redis():
                        return
                    await self._initialize_connected_redis_handlers()
            except Exception as e:
                self.logger.warning(
                    "Redis recovery after a cold start failed: %s", e, exc_info=True
                )
                return
            self._disarm_redis_cold_start_recovery()
            self.logger.info("Redis recovered after a cold start; handlers connected")
