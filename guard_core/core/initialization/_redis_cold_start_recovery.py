import inspect
import logging
import threading
from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING

from guard_core._utils.app_scope import app_scope_of, in_app_scope
from guard_core.core.checks.base import SecurityCheck
from guard_core.core.checks.pipeline import REDIS_OUTAGE_RETRY_AFTER
from guard_core.exceptions import GuardRedisError
from guard_core.handlers._background_stop import stop_before_redis_closes
from guard_core.handlers._redis_attempt import RedisAttemptSlot
from guard_core.handlers._redis_reconnect_gate import RedisReconnectGate
from guard_core.protocols.request_protocol import GuardRequest
from guard_core.protocols.response_protocol import GuardResponse

if TYPE_CHECKING:
    from guard_core.core.checks.pipeline import SecurityCheckPipeline
    from guard_core.models import SecurityConfig
    from guard_core.protocols.middleware_protocol import GuardMiddlewareProtocol
    from guard_core.protocols.redis_protocol import RedisHandlerProtocol

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
    redis_handler: "RedisHandlerProtocol | None" = None

    _recovery_pipeline: "SecurityCheckPipeline | None" = None
    _recovery_middleware: "GuardMiddlewareProtocol | None" = None
    _recovery_check: RedisColdStartRecoveryCheck | None = None
    _recovery_claim: "threading.Lock | None" = None
    _recovery_own_gate: RedisReconnectGate | None = None
    _recovery_attempts: RedisAttemptSlot | None = None

    _require_redis_handler: Callable[[], "RedisHandlerProtocol"]

    async def _initialize_connected_redis_handlers(self) -> None: ...

    def bind_redis_recovery_pipeline(
        self,
        pipeline: "SecurityCheckPipeline",
        middleware: "GuardMiddlewareProtocol",
    ) -> None:
        self._recovery_pipeline = pipeline
        self._recovery_middleware = middleware
        self._recovery_claim = threading.Lock()
        self._recovery_own_gate = RedisReconnectGate()
        self._recovery_attempts = RedisAttemptSlot()

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

    async def _recover_redis_after_cold_start(self) -> None:
        # One caller at a time, never waiting: a non-blocking acquire is atomic for
        # coroutines and threads. The reconnect itself is the manager's single-flight
        # entry, which refuses at once until its backoff window opens.
        claim = self._recovery_claim
        if claim is None or not self._redis_recovery_armed():
            return
        if not claim.acquire(blocking=False):
            return
        try:
            if not self._redis_recovery_armed():
                return
            await self._bind_recovered_redis()
        except GuardRedisError:
            return
        except Exception as e:
            self.logger.warning(
                "Redis recovery after a cold start failed: %s", e, exc_info=True
            )
        finally:
            claim.release()

    async def _bind_recovered_redis(self) -> None:
        with in_app_scope(app_scope_of(self.config)):
            redis_handler = self._require_redis_handler()
            # initialize() drops a healthy client first, so a manager another caller
            # already reconnected is bound as it is.
            if not self._redis_handler_holds_a_client(redis_handler):
                await self._initialize_redis_handler(redis_handler)
            await self._initialize_connected_redis_handlers()
        self._disarm_redis_cold_start_recovery()
        self.logger.info("Redis recovered after a cold start; handlers connected")

    async def _initialize_redis_handler(
        self, redis_handler: "RedisHandlerProtocol"
    ) -> None:
        from guard_core.handlers.redis_handler import RedisManager

        if (
            isinstance(redis_handler, RedisManager)
            and type(redis_handler).initialize is RedisManager.initialize
        ):
            await redis_handler.initialize()
            return
        # A handler with its own initialize (a subclass that calls super(), or a
        # duck-typed one) has its gate inside or none at all: entering the manager's
        # gate from here would refuse the super() call. Recovery paces it with its own,
        # and runs the attempt off the request path: whoever wins the window starts
        # it, every caller is refused at once, and the next request binds the result.
        gate, attempts = self._recovery_own_gate, self._recovery_attempts
        if gate is None or attempts is None or not gate.enter():
            raise GuardRedisError(503, "Redis connection failed")
        try:
            stop_before_redis_closes(redis_handler, attempts.stop)
            attempts.spawn(lambda: self._attempt_custom_initialize(redis_handler, gate))
        except BaseException:
            # No attempt will ever release the claim: do it here.
            gate.leave(False)
            raise
        raise GuardRedisError(503, "Redis connection failed")

    async def _attempt_custom_initialize(
        self, redis_handler: "RedisHandlerProtocol", gate: RedisReconnectGate
    ) -> None:
        connected = False
        try:
            with in_app_scope(app_scope_of(self.config)):
                try:
                    await redis_handler.initialize()
                    # Connected is read from state: an initialize that logs and
                    # returns on a failure must keep the backoff.
                    connected = self._redis_handler_holds_a_client(redis_handler)
                except GuardRedisError:
                    pass
                except Exception as e:
                    self.logger.warning(
                        "Redis recovery after a cold start failed: %s",
                        e,
                        exc_info=True,
                    )
        finally:
            gate.leave(connected)

    @staticmethod
    def _redis_handler_holds_a_client(redis_handler: "RedisHandlerProtocol") -> bool:
        is_connected = getattr(redis_handler, "is_connected", None)
        if is_connected is not None:
            answer = is_connected()
            if inspect.iscoroutine(answer):
                # Never awaited: an async is_connected reads as not connected.
                answer.close()
                return False
            # Any other answer counts by its truth value (a bool, 1, a client).
            return bool(answer)
        return getattr(redis_handler, "_redis", None) is not None
