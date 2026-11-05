import logging
import threading
from collections.abc import Callable
from typing import TYPE_CHECKING

from guard_core.exceptions import GuardRedisError
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
    from guard_core.sync.protocols.redis_protocol import SyncRedisHandlerProtocol

# The pause the 503 tells clients to wait; the manager's reconnect window is the same.
REDIS_COLD_START_RETRY_INTERVAL = REDIS_OUTAGE_RETRY_AFTER


class RedisColdStartRecoveryCheck(SecurityCheck):
    """First in a pipeline, and only between a cold Redis failure under
    redis_fail_open=True and the first successful reconnection. It never blocks and
    runs on excluded paths too, so any traffic at all brings Redis back."""

    enforced_on_excluded_paths = True
    is_internal = True

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
    redis_handler: "SyncRedisHandlerProtocol | None" = None

    _recovery_pipeline: "SecurityCheckPipeline | None" = None
    _recovery_middleware: "SyncGuardMiddlewareProtocol | None" = None
    _recovery_check: RedisColdStartRecoveryCheck | None = None
    _recovery_claim = threading.Lock()

    _require_redis_handler: Callable[[], "SyncRedisHandlerProtocol"]

    def _initialize_connected_redis_handlers(self) -> None: ...

    def bind_redis_recovery_pipeline(
        self,
        pipeline: "SecurityCheckPipeline",
        middleware: "SyncGuardMiddlewareProtocol",
    ) -> None:
        self._recovery_pipeline = pipeline
        self._recovery_middleware = middleware
        self._recovery_claim = threading.Lock()

    def _arm_redis_cold_start_recovery(self) -> None:
        pipeline, middleware = self._recovery_pipeline, self._recovery_middleware
        if pipeline is None or middleware is None or self._recovery_check is not None:
            return
        self._recovery_check = RedisColdStartRecoveryCheck(
            middleware, self._recover_redis_after_cold_start
        )
        pipeline.insert_check(0, self._recovery_check)

    def _disarm_redis_cold_start_recovery(self) -> None:
        check, self._recovery_check = self._recovery_check, None
        if check is not None and self._recovery_pipeline is not None:
            self._recovery_pipeline.remove_check(check.check_name)

    def _redis_recovery_armed(self) -> bool:
        return self._recovery_check is not None

    def _recover_redis_after_cold_start(self) -> None:
        # One caller at a time, never waiting: a non-blocking acquire is atomic for
        # coroutines and threads. The reconnect itself is the manager's single-flight
        # entry, which refuses at once until its backoff window opens.
        if not self._redis_recovery_armed() or not self._recovery_claim.acquire(
            blocking=False
        ):
            return
        try:
            if not self._redis_recovery_armed():
                return
            self._bind_recovered_redis()
        except GuardRedisError:
            return
        except Exception as e:
            self.logger.warning(
                "Redis recovery after a cold start failed: %s", e, exc_info=True
            )
        finally:
            self._recovery_claim.release()

    def _bind_recovered_redis(self) -> None:
        from guard_core.sync.handlers.redis_handler import is_connected_redis_manager

        with in_app_scope(app_scope_of(self.config)):
            redis_handler = self._require_redis_handler()
            # initialize() drops a healthy client first, so a manager another caller
            # already reconnected is bound as it is.
            if not is_connected_redis_manager(redis_handler):
                redis_handler.initialize()
            self._initialize_connected_redis_handlers()
        self._disarm_redis_cold_start_recovery()
        self.logger.info("Redis recovered after a cold start; handlers connected")
