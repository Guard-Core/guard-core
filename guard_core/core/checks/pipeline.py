import logging
import threading
import time
from collections.abc import Callable, Sized
from typing import cast

from guard_core._utils.block_events import fire_block_hook
from guard_core._utils.request_logging import redact_header_value_for_display
from guard_core.core.checks.base import SecurityCheck
from guard_core.exceptions import GuardRedisError
from guard_core.models import SecurityConfig
from guard_core.protocols.request_protocol import GuardRequest
from guard_core.protocols.response_protocol import GuardResponse


class SecurityCheckPipeline:
    def __init__(
        self,
        checks: list[SecurityCheck],
        muted_check_logs: frozenset[str] | None = None,
        *,
        config: SecurityConfig | None = None,
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
        self._built_revision = config.revision if config is not None else None
        self._built_signature = (
            self._container_signature(config) if config is not None else ()
        )
        self._built_route_config_revision = self._current_route_config_revision()

    @staticmethod
    def _container_size(value: Sized | None) -> int:
        return 0 if value is None else len(value)

    def _container_signature(self, config: SecurityConfig) -> tuple[int, ...]:
        return tuple(
            self._container_size(getattr(config, field))
            for field in self._watched_container_fields
        )

    def _current_route_config_revision(self) -> int | None:
        if self._route_config_revision is None:
            return None
        return self._route_config_revision()

    def _is_stale(self, config: SecurityConfig) -> bool:
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
        checks = self._rebuild_checks()
        with self._rebuild_lock:
            self.checks = checks
            self.muted_check_logs = muted_check_logs
            self._built_revision = revision
            self._built_signature = signature
            self._built_route_config_revision = route_config_revision

    def _log_extra(self, check: SecurityCheck, request: GuardRequest) -> dict:
        return {
            "check": check.check_name,
            "path": request.url_path,
            "method": request.method,
        }

    async def _handle_check_error(
        self, check: SecurityCheck, request: GuardRequest, error: Exception
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
            return await check.create_error_response(
                status_code=500,
                default_message="Security check failed",
            )

        return None

    async def _fire_block_hook(
        self, check: SecurityCheck, request: GuardRequest, response: GuardResponse
    ) -> None:
        stash = getattr(request.state, "_guard_block_stash", None) or {}
        await fire_block_hook(
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

    async def _handle_rebuild_error(
        self, request: GuardRequest, error: Exception
    ) -> GuardResponse | None:
        self.logger.error(
            f"Error rebuilding security checks: {error}",
            extra={"path": request.url_path, "method": request.method},
            exc_info=True,
        )
        config = cast(SecurityConfig, self._config)
        if not config.fail_secure:
            return None
        if not self.checks:
            raise error
        self.logger.warning("Blocking request due to rebuild error in fail-secure mode")
        return await self.checks[0].create_error_response(
            status_code=500,
            default_message="Security check failed",
        )

    async def execute(self, request: GuardRequest) -> GuardResponse | None:
        try:
            self._rebuild_if_stale()
        except Exception as e:
            response = await self._handle_rebuild_error(request, e)
            if response is not None:
                return response

        request.state._guard_pipeline_start = time.monotonic()
        exclusion_scoped = (
            getattr(request.state, "guard_exclusion_scoped", False) is True
        )

        for check in self.checks:
            if exclusion_scoped and not check.enforced_on_excluded_paths:
                continue
            try:
                response = await check.check(request)
                if response is not None:
                    if check.check_name not in self.muted_check_logs:
                        self.logger.debug(
                            f"Request blocked by {check.check_name}",
                            extra=self._log_extra(check, request),
                        )
                    await self._fire_block_hook(check, request, response)
                    return response

            except Exception as e:
                error_response = await self._handle_check_error(check, request, e)
                if error_response is not None:
                    return error_response

        return None

    @property
    def needs_route_identity(self) -> bool:
        return any(check.needs_route_identity for check in self.checks)

    def add_check(self, check: SecurityCheck) -> None:
        self.checks.append(check)

    def insert_check(self, index: int, check: SecurityCheck) -> None:
        self.checks.insert(index, check)

    def remove_check(self, check_name: str) -> bool:
        for i, check in enumerate(self.checks):
            if check.check_name == check_name:
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
