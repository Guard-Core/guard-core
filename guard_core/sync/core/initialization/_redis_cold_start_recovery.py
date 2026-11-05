import logging
import threading
from collections.abc import Callable
from time import monotonic
from typing import TYPE_CHECKING

from guard_core.protocols.response_protocol import GuardResponse
from guard_core.sync._utils.app_scope import app_scope_of, in_app_scope
from guard_core.sync.core.checks.base import SecurityCheck
from guard_core.sync.core.checks.pipeline import REDIS_OUTAGE_RETRY_AFTER
from guard_core.sync.protocols.request_protocol import SyncGuardRequest

if TYPE_CHECKING:
    from guard_core.models import SyncSecurityConfig
    from guard_core.sync.core.checks.pipeline import SecurityCheckPipeline
    from guard_core.sync.protocols.middleware_protocol import (
        SyncGuardMiddlewareProtocol,
    )

# The pause the 503 tells clients to wait: one attempt per 5 s at most.
REDIS_COLD_START_RETRY_INTERVAL = REDIS_OUTAGE_RETRY_AFTER


class RedisColdStartRecoveryCheck(SecurityCheck):
    """Present in a pipeline only between a cold Redis failure under
    redis_fail_open=True and the first successful reconnection."""

    def __init__(
        self,
        middleware: "SyncGuardMiddlewareProtocol",
        recover: Callable[[], None],
    ) -> None:
        super().__init__(middleware)
        self._recover = recover

    @property
    def check_name(self) -> str:
        return "redis_cold_start_recovery"

    def check(self, request: SyncGuardRequest) -> GuardResponse | None:
        self._recover()
        return None


class RedisColdStartRecoveryMixin:
    config: "SyncSecurityConfig"
    logger: logging.Logger

    _recovery_pipeline: "SecurityCheckPipeline | None" = None
    _recovery_middleware: "SyncGuardMiddlewareProtocol | None" = None
    _recovery_check: RedisColdStartRecoveryCheck | None = None
    _recovery_retry_at = 0.0
    _recovery_lock: threading.Lock

    _connect_redis: Callable[[], bool]

    def _initialize_connected_redis_handlers(self) -> None: ...

    def bind_redis_recovery_pipeline(
        self,
        pipeline: "SecurityCheckPipeline",
        middleware: "SyncGuardMiddlewareProtocol",
    ) -> None:
        self._recovery_pipeline = pipeline
        self._recovery_middleware = middleware
        self._recovery_lock = threading.Lock()

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

    def _recover_redis_after_cold_start(self) -> None:
        if not self._redis_recovery_due() or self._recovery_lock.locked():
            return
        with self._recovery_lock:
            if not self._redis_recovery_due():
                return
            self._recovery_retry_at = monotonic() + REDIS_COLD_START_RETRY_INTERVAL
            try:
                with in_app_scope(app_scope_of(self.config)):
                    if not self._connect_redis():
                        return
                    self._initialize_connected_redis_handlers()
            except Exception as e:
                self.logger.warning(
                    "Redis recovery after a cold start failed: %s", e, exc_info=True
                )
                return
            self._disarm_redis_cold_start_recovery()
            self.logger.info("Redis recovered after a cold start; handlers connected")
