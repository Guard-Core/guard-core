import logging
from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING, Any

from guard_core.models import SecurityConfig
from guard_core.utils import _log_at_level

if TYPE_CHECKING:
    from guard_core.handlers.behavior_handler import BehaviorRule


class BehaviorActionDispatchMixin:
    config: SecurityConfig
    logger: logging.Logger

    def _log_passive_mode_action(
        self, rule: "BehaviorRule", client_ip: str, details: str
    ) -> None:
        prefix = "[PASSIVE MODE] "

        if rule.action == "alert":
            self.logger.critical(f"{prefix}ALERT - Behavioral anomaly: {details}")
            return

        level = self.config.log_suspicious_level
        if level is None:
            return

        if rule.action == "ban":
            _log_at_level(
                self.logger,
                level,
                f"{prefix}Would ban IP {client_ip} for behavioral violation: {details}",
            )
        elif rule.action == "log":
            _log_at_level(
                self.logger, level, f"{prefix}Behavioral anomaly detected: {details}"
            )
        elif rule.action == "throttle":
            _log_at_level(
                self.logger, level, f"{prefix}Would throttle IP {client_ip}: {details}"
            )

    async def _execute_ban_action(
        self,
        client_ip: str,
        details: str,
        rule: "BehaviorRule | None" = None,
    ) -> str:
        if not self.config.enable_ip_banning:
            return "tracked"

        from guard_core.handlers.ipban_handler import ip_ban_manager

        duration = (
            rule.ban_duration
            if rule is not None and rule.ban_duration is not None
            else 3600
        )
        applied = await ip_ban_manager.ban_ip(
            client_ip, duration, "behavioral_violation"
        )
        if not applied:
            return "tracked"
        level = self.config.log_suspicious_level
        if level is not None:
            _log_at_level(
                self.logger,
                level,
                f"IP {client_ip} banned for behavioral violation: {details}",
            )
        return "ban"

    async def _run_custom_action(
        self,
        rule: "BehaviorRule",
        custom_action: Callable[..., Awaitable[Any]],
        client_ip: str,
        endpoint_id: str,
        details: str,
    ) -> str:
        try:
            await custom_action(client_ip, endpoint_id, details)
        except Exception as exc:
            self.logger.error(
                "Behavioral custom_action raised %s for %s on %s",
                exc,
                client_ip,
                endpoint_id,
                exc_info=True,
            )
            return "tracked"
        return rule.action

    async def _execute_active_mode_action(
        self, rule: "BehaviorRule", client_ip: str, endpoint_id: str, details: str
    ) -> str:
        if rule.custom_action:
            return await self._run_custom_action(
                rule, rule.custom_action, client_ip, endpoint_id, details
            )

        if rule.action == "ban":
            return await self._execute_ban_action(client_ip, details, rule)

        if rule.action == "alert":
            self.logger.critical(f"ALERT - Behavioral anomaly: {details}")
            return rule.action

        level = self.config.log_suspicious_level
        if level is None:
            return rule.action

        if rule.action == "log":
            _log_at_level(self.logger, level, f"Behavioral anomaly detected: {details}")
        elif rule.action == "throttle":
            _log_at_level(self.logger, level, f"Throttling IP {client_ip}: {details}")
        return rule.action

    async def apply_action(
        self, rule: "BehaviorRule", client_ip: str, endpoint_id: str, details: str
    ) -> str:
        if self.config.passive_mode:
            self._log_passive_mode_action(rule, client_ip, details)
            return "logged_only"
        return await self._execute_active_mode_action(
            rule, client_ip, endpoint_id, details
        )
