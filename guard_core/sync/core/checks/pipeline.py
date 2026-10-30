import logging
import threading
import time
from collections.abc import Callable

from guard_core.exceptions import GuardRedisError
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
from guard_core.sync.protocols.request_protocol import SyncGuardRequest

REDIS_OUTAGE_RETRY_AFTER = 5


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
    ) -> None:
        self.checks = checks
        self.muted_check_logs = muted_check_logs or frozenset()
        self.logger = logging.getLogger(__name__)
        self._config = config
        self._rebuild_checks = rebuild_checks
        self._watched_container_fields = watched_container_fields or ()
        self._route_config_revision = route_config_revision
        self._rebuild_lock = threading.Lock()
        self._check_edits: list[tuple[str, int, SecurityCheck | str]] = []
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

    def _is_stale(self, config: SyncSecurityConfig) -> bool:
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
        revision = config.revision
        signature = self._container_signature(config)
        route_config_revision = self._current_route_config_revision()
        muted_check_logs = config.muted_check_logs
        checks = self._replay_check_edits(self._rebuild_checks())
        with self._rebuild_lock:
            self.checks = checks
            self.muted_check_logs = muted_check_logs
            self._built_revision = revision
            self._built_signature = signature
            self._built_route_config_revision = route_config_revision

    def _replay_check_edits(self, checks: list[SecurityCheck]) -> list[SecurityCheck]:
        """The checks a caller added, inserted or removed by hand stay in force across
        a rebuild: replay each edit, in order, on the freshly built list."""
        for action, index, subject in tuple(self._check_edits):
            if action == "remove":
                checks = [c for c in checks if c.check_name != subject]
            elif isinstance(subject, SecurityCheck) and action == "append":
                checks.append(subject)
            elif isinstance(subject, SecurityCheck):
                checks.insert(index, subject)
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
        flow = getattr(state, "guard_ban_flow", None)
        blocker = flow.banned_by if isinstance(flow, BanFlow) else None
        if not isinstance(blocker, SecurityCheck):
            blocker = check
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
            self._fire_block_hook(pending.check, request, response)
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
        if config is None:
            raise error
        if not config.fail_secure:
            return None
        if not self.checks:
            raise error
        self.logger.warning("Blocking request due to rebuild error in fail-secure mode")
        return self.checks[0].create_error_response(
            status_code=500,
            default_message="Security check failed",
        )

    def _rebuild_response(self, request: SyncGuardRequest) -> GuardResponse | None:
        try:
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
            config = self.checks[0].config
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
            return self._handle_check_error(self.checks[0], request, e)

    def _finish(self, request: SyncGuardRequest) -> GuardResponse | None:
        try:
            banned = self._resolve_pending_ban(request)
        except Exception as e:
            banned = self._handle_check_error(self.checks[0], request, e)
        if banned is not None:
            return banned
        return enforce_usage_rules(
            self.checks, request, request.state, self._handle_check_error
        )

    @property
    def needs_route_identity(self) -> bool:
        return any(check.needs_route_identity for check in self.checks)

    def add_check(self, check: SecurityCheck) -> None:
        self._check_edits.append(("append", 0, check))
        self.checks.append(check)

    def insert_check(self, index: int, check: SecurityCheck) -> None:
        self._check_edits.append(("insert", index, check))
        self.checks.insert(index, check)

    def remove_check(self, check_name: str) -> bool:
        for i, check in enumerate(self.checks):
            if check.check_name == check_name:
                self._check_edits.append(("remove", i, check_name))
                self.checks.pop(i)
                return True
        return False

    def get_check_names(self) -> list[str]:
        return [check.check_name for check in self.checks]

    def __len__(self) -> int:
        return len(self.checks)

    def __repr__(self) -> str:
        check_names = ", ".join(self.get_check_names())
        return f"SecurityCheckPipeline({len(self.checks)} checks: {check_names})"
