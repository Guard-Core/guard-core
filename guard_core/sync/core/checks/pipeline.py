import logging
import threading
import time
from collections.abc import Callable

from guard_core._parked_records import RELEASE_EPOCH_RECORD
from guard_core.exceptions import GuardRedisError, MisconfigurationError
from guard_core.models import SyncSecurityConfig
from guard_core.protocols.response_protocol import GuardResponse
from guard_core.sync._utils.app_scope import (
    AppScope,
    _current_app_scope,
    existing_app_scope_of,
)
from guard_core.sync._utils.block_events import fire_block_hook
from guard_core.sync._utils.request_logging import redact_header_value_for_display
from guard_core.sync.core.checks._ban_flow import BanFlow
from guard_core.sync.core.checks._pending_ban import PendingBan, resolve_pending_ban
from guard_core.sync.core.checks._usage_rules_step import (
    enforce_usage_rules,
    warn_at_startup_if_throttle_cannot_refuse,
)
from guard_core.sync.core.checks.base import SecurityCheck
from guard_core.sync.handlers._redis_attempt import ConnectionLocks
from guard_core.sync.handlers._redis_reconnect_gate import (
    REDIS_RECONNECT_WINDOW_SECONDS,
)
from guard_core.sync.protocols.request_protocol import SyncGuardRequest

REDIS_OUTAGE_RETRY_AFTER = REDIS_RECONNECT_WINDOW_SECONDS


def _blocker_of(check: SecurityCheck, state: object) -> SecurityCheck:
    flow = getattr(state, "guard_ban_flow", None)
    blocker = flow.banned_by if isinstance(flow, BanFlow) else None
    return blocker if isinstance(blocker, SecurityCheck) else check


def _pending_of(state: object) -> PendingBan | None:
    flow = getattr(state, "guard_ban_flow", None)
    return flow.pending if isinstance(flow, BanFlow) else None


def _owner_of(error: Exception, check: SecurityCheck) -> SecurityCheck:
    return getattr(error, "guard_check", None) or check


class SecurityCheckPipeline:
    def __init__(
        self,
        checks: list[SecurityCheck],
        muted_check_logs: frozenset[str] | None = None,
        *,
        config: SyncSecurityConfig | None = None,
        rebuild_checks: Callable[[], list[SecurityCheck]] | None = None,
        watched_container_fields: tuple[str, ...] | None = None,
        route_config_revision: Callable[[], int | None] | None = None,
        reinitialize_app: Callable[[], None] | None = None,
    ) -> None:
        self.checks = checks
        self.muted_check_logs = muted_check_logs or frozenset()
        self.logger = logging.getLogger(__name__)
        self._config = config
        self._rebuild_checks = rebuild_checks
        self._watched_container_fields = watched_container_fields or ()
        self._route_config_revision = route_config_revision
        self._rebuild_lock = threading.Lock()
        self._reinitialize_app = reinitialize_app
        self._reinitialize_locks = ConnectionLocks()
        self._built_release_epoch = self._release_epoch_of(config)
        self._initialized_release_epoch = self._built_release_epoch
        self._check_edits: list[
            Callable[[list[SecurityCheck]], list[SecurityCheck]]
        ] = []
        self._app_scope: AppScope | None = None
        self._built_revision = config.revision if config is not None else None
        self._built_signature = (
            self._container_signature(config) if config is not None else ()
        )
        self._built_route_config_revision = self._current_route_config_revision()
        warn_at_startup_if_throttle_cannot_refuse(checks)

    def _container_signature(self, config: SyncSecurityConfig) -> tuple[int, ...]:
        # None counts as size 0; read on every request, so no helper call.
        return tuple(
            len(getattr(config, field) or ())
            for field in self._watched_container_fields
        )

    def _current_route_config_revision(self) -> int | None:
        if self._route_config_revision is None:
            return None
        return self._route_config_revision()

    @staticmethod
    def _release_epoch_of(config: SyncSecurityConfig | None) -> int:
        return (
            0 if config is None else int(config.__dict__.get(RELEASE_EPOCH_RECORD, 0))
        )

    def _is_stale(self, config: SyncSecurityConfig) -> bool:
        if config.__dict__.get(RELEASE_EPOCH_RECORD, 0) != self._built_release_epoch:
            return True
        if config.revision != self._built_revision:
            return True
        if self._container_signature(config) != self._built_signature:
            return True
        return (
            self._current_route_config_revision() != self._built_route_config_revision
        )

    def _rebuild_if_stale(self) -> None:
        config = self._config
        if config is None or self._rebuild_checks is None:
            return
        if not self._is_stale(config):
            return
        release_epoch = self._release_epoch_of(config)
        revision = config.revision
        signature = self._container_signature(config)
        route_config_revision = self._current_route_config_revision()
        muted_check_logs = config.muted_check_logs
        edits_seen = len(self._check_edits)
        checks = self._replay_check_edits(self._rebuild_checks(), edits_seen)
        with self._rebuild_lock:
            checks = self._replay_check_edits(checks, start=edits_seen)
            self.checks = checks
            self.muted_check_logs = muted_check_logs
            self._built_revision = revision
            self._built_signature = signature
            self._built_route_config_revision = route_config_revision
            self._built_release_epoch = release_epoch

    def _replay_check_edits(
        self, checks: list[SecurityCheck], stop: int | None = None, start: int = 0
    ) -> list[SecurityCheck]:
        """The checks a caller added, inserted or removed by hand stay in force across
        a rebuild: replay each edit, in order, on the freshly built list. A rebuild
        replays the first ``stop`` edits outside the lock and, inside it, every edit
        recorded since, so an edit made while the rebuild ran is never lost."""
        for edit in tuple(self._check_edits[start:stop]):
            checks = edit(checks)
        return checks

    def _log_extra(self, check: SecurityCheck, request: SyncGuardRequest) -> dict:
        return {
            "check": check.check_name,
            "path": request.url_path,
            "method": request.method,
        }

    def _handle_check_error(
        self, check: SecurityCheck, request: SyncGuardRequest, error: Exception
    ) -> GuardResponse | None:
        if isinstance(error, MisconfigurationError):
            # A refused misconfiguration reaches the host framework, whatever
            # passive_mode or fail_secure say: it is the app's own mistake, not a
            # check failure.
            raise error

        muted = check.check_name in self.muted_check_logs

        if isinstance(error, GuardRedisError) and check.config.redis_fail_open:
            if not muted:
                self.logger.warning(
                    f"Skipping check {check.check_name}: Redis "
                    f"unavailable, failing open (redis_fail_open=True)",
                    extra=self._log_extra(check, request),
                )
            return None

        if not muted:
            safe_message = redact_header_value_for_display(
                str(error),
                check.config.log_sensitive_params,
                check.config.log_sensitive_body_fields,
                check.config.log_sensitive_headers,
            )
            self.logger.error(
                f"Error in security check {check.check_name} "
                f"({type(error).__name__}): {safe_message}",
                extra=self._log_extra(check, request),
            )

        if check.config.passive_mode:
            return None

        if check.config.fail_secure:
            if not muted:
                self.logger.warning(
                    f"Blocking request due to check error "
                    f"in fail-secure mode: {check.check_name}"
                )
            return self._fail_secure_response(check, error)

        return None

    def _fail_secure_response(
        self, check: SecurityCheck, error: Exception
    ) -> GuardResponse:
        if not isinstance(error, GuardRedisError):
            return check.create_error_response(
                status_code=500,
                default_message="Security check failed",
            )
        response = check.create_error_response(
            status_code=error.status_code,
            default_message="Security check failed",
        )
        response.headers["Retry-After"] = str(REDIS_OUTAGE_RETRY_AFTER)
        return response

    def _fire_block_hook(
        self, check: SecurityCheck, request: SyncGuardRequest, response: GuardResponse
    ) -> None:
        stash = getattr(request.state, "_guard_block_stash", None) or {}
        fire_block_hook(
            check.config.on_block,
            request,
            check.check_name,
            stash.get("reason", ""),
            stash.get("trigger_info", ""),
            False,
            response.status_code,
            check.config.log_sensitive_params,
            check.config.log_sensitive_body_fields,
            check.config.log_sensitive_headers,
        )

    def _blocked(
        self,
        check: SecurityCheck,
        request: SyncGuardRequest,
        response: GuardResponse,
        state: object,
    ) -> GuardResponse:
        blocker = _blocker_of(check, state)
        if blocker.check_name not in self.muted_check_logs and self.logger.isEnabledFor(
            logging.DEBUG
        ):
            self.logger.debug(
                f"Request blocked by {blocker.check_name}",
                extra=self._log_extra(blocker, request),
            )
        if blocker.config.on_block is not None:
            self._fire_block_hook(blocker, request, response)
        return response

    def _resolve_pending_ban(self, request: SyncGuardRequest) -> GuardResponse | None:
        pending = _pending_of(request.state)
        if pending is None:
            return None
        response = resolve_pending_ban(request)
        if response is not None:
            self._fire_block_hook(
                _blocker_of(pending.check, request.state), request, response
            )
        return response

    def _handle_rebuild_error(
        self, request: SyncGuardRequest, error: Exception
    ) -> GuardResponse | None:
        self.logger.error(
            f"Error rebuilding security checks: {error}",
            extra={"path": request.url_path, "method": request.method},
            exc_info=True,
        )
        config = self._config
        if config is None or isinstance(error, MisconfigurationError):
            raise error
        if not config.fail_secure:
            return None
        if not self.checks:
            raise error
        self.logger.warning("Blocking request due to rebuild error in fail-secure mode")
        return self._first_real_check().create_error_response(
            status_code=500,
            default_message="Security check failed",
        )

    def _initialize_a_released_app_once(self, config: SyncSecurityConfig) -> None:
        """The app was released: bind and initialize it again, awaited once, before
        the checks are rebuilt. Concurrent first requests wait on one lock, so the
        app initializes once, with one bind and one rule loop."""
        reinitialize = self._reinitialize_app
        if reinitialize is None:
            return
        with self._reinitialize_locks.here():
            epoch = self._release_epoch_of(config)
            if epoch == self._initialized_release_epoch:
                return
            reinitialize()
            self._initialized_release_epoch = epoch

    def _rebuild_response(self, request: SyncGuardRequest) -> GuardResponse | None:
        try:
            config = self._config
            if (
                config is not None
                and config.__dict__.get(RELEASE_EPOCH_RECORD, 0)
                != self._initialized_release_epoch
            ):
                self._initialize_a_released_app_once(config)
            self._rebuild_if_stale()
        except Exception as e:
            return self._handle_rebuild_error(request, e)
        return None

    def _applicable_checks(self, state: object) -> list[SecurityCheck]:
        if getattr(state, "guard_exclusion_scoped", False) is not True:
            return self.checks
        return [check for check in self.checks if check.enforced_on_excluded_paths]

    def _resolve_app_scope(self) -> AppScope | None:
        config = self._config
        if config is None and self.checks:
            config = self._first_real_check().config
        self._app_scope = None if config is None else existing_app_scope_of(config)
        return self._app_scope

    def _scope_in_force(self) -> AppScope | None:
        """This app's scope, else the one already held (an outer app's scope is
        never replaced by None)."""
        return self._app_scope or self._resolve_app_scope() or _current_app_scope.get()

    def execute(self, request: SyncGuardRequest) -> GuardResponse | None:
        token = _current_app_scope.set(self._scope_in_force())
        try:
            response = self._rebuild_response(request)
            if response is not None:
                return response

            state = request.state
            state._guard_pipeline_start = time.monotonic()

            pending_open = False
            for check in self._applicable_checks(state):
                try:
                    if pending_open and not check.defers_ban_read:
                        banned = self._resolve_pending_ban_or_handle_error(request)
                        if banned is not None:
                            return banned
                        pending_open = False
                    response = check.check(request)
                    if response is not None:
                        return self._blocked(check, request, response, state)
                    if check.leaves_ban_pending:
                        pending_open = _pending_of(state) is not None

                except Exception as e:
                    error_response = self._handle_check_error(
                        _owner_of(e, check), request, e
                    )
                    if error_response is not None:
                        return error_response

            return self._finish(request)
        finally:
            _current_app_scope.reset(token)

    def _resolve_pending_ban_or_handle_error(
        self, request: SyncGuardRequest
    ) -> GuardResponse | None:
        try:
            return self._resolve_pending_ban(request)
        except Exception as e:
            return self._handle_check_error(self._first_real_check(), request, e)

    def _finish(self, request: SyncGuardRequest) -> GuardResponse | None:
        try:
            banned = self._resolve_pending_ban(request)
        except Exception as e:
            banned = self._handle_check_error(self._first_real_check(), request, e)
        if banned is not None:
            return banned
        return enforce_usage_rules(
            self.checks, request, request.state, self._handle_check_error
        )

    @property
    def needs_route_identity(self) -> bool:
        return any(check.needs_route_identity for check in self.checks)

    def _edit_checks(
        self, edit: Callable[[list[SecurityCheck]], list[SecurityCheck]]
    ) -> None:
        # Copy on write: a request walking the old list never sees it change.
        self._check_edits.append(edit)
        self.checks = edit(self.checks)

    def add_check(self, check: SecurityCheck) -> None:
        with self._rebuild_lock:
            self._edit_checks(lambda checks: [*checks, check])

    def insert_check(self, index: int, check: SecurityCheck) -> None:
        with self._rebuild_lock:
            self._edit_checks(lambda checks: [*checks[:index], check, *checks[index:]])

    def remove_check(self, check_name: str) -> bool:
        with self._rebuild_lock:
            if all(check.check_name != check_name for check in self.checks):
                return False
            self._edit_checks(
                lambda checks: [c for c in checks if c.check_name != check_name]
            )
            return True

    def _first_real_check(self) -> SecurityCheck:
        """The check that stands for the pipeline in an error or a refusal: the first
        one the engine did not insert itself."""
        for check in self.checks:
            if not check.is_internal:
                return check
        return self.checks[0]

    def get_check_names(self) -> list[str]:
        return [check.check_name for check in self.checks]

    def __len__(self) -> int:
        return len(self.checks)

    def __repr__(self) -> str:
        check_names = ", ".join(self.get_check_names())
        return f"SecurityCheckPipeline({len(self.checks)} checks: {check_names})"
