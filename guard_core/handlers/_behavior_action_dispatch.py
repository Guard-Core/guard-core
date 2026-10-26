import logging
from collections.abc import Awaitable, Callable
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from guard_core.handlers._behavior_throttle import behavior_client_identity
from guard_core.models import SecurityConfig
from guard_core.utils import _log_at_level

if TYPE_CHECKING:
    from guard_core.handlers.behavior_handler import BehaviorRule
    from guard_core.protocols.agent_protocol import AgentHandlerProtocol


_BEHAVIOR_HANDLER_NAME = "behavior"


class BehaviorActionDispatchMixin:
    config: SecurityConfig
    logger: logging.Logger
    agent_handler: "AgentHandlerProtocol | None"

    def _observe_only_log_prefix(self) -> str:
        return "[PASSIVE MODE] " if self.config.passive_mode else ""

    def _log_passive_mode_action(
        self,
        rule: "BehaviorRule",
        client_ip: str,
        details: str,
        prefix: str = "[PASSIVE MODE] ",
    ) -> None:
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

        from guard_core.handlers.ipban_handler import ip_ban_manager_for

        duration = (
            rule.ban_duration
            if rule is not None and rule.ban_duration is not None
            else 3600
        )
        identity = behavior_client_identity(self.config, client_ip)
        applied = await ip_ban_manager_for(self.config)._ban_ip_escalating(
            identity, duration, "behavioral_violation", grouped="/" in identity
        )
        if not applied:
            return "tracked"
        level = self.config.log_suspicious_level
        if level is not None:
            _log_at_level(
                self.logger,
                level,
                f"IP {client_ip} banned for {applied} seconds for behavioral "
                f"violation: {details}",
            )
        return "ban"

    async def _run_custom_action(
        self,
        rule: "BehaviorRule",
        custom_action: Callable[[str, str, str], Awaitable[object]],
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
        self,
        rule: "BehaviorRule",
        client_ip: str,
        endpoint_id: str,
        details: str,
        *,
        observe_only: bool = False,
        **event_metadata: object,
    ) -> str:
        if self.config.passive_mode or observe_only:
            action_taken = "logged_only"
            self._log_passive_mode_action(
                rule, client_ip, details, self._observe_only_log_prefix()
            )
        else:
            action_taken = await self._execute_active_mode_action(
                rule, client_ip, endpoint_id, details
            )

        if self.agent_handler and self.config.agent_enable_events:
            from guard_core.core.events.event_types import EVENT_BEHAVIOR_VIOLATION

            await self._send_behavior_event(
                event_type=EVENT_BEHAVIOR_VIOLATION,
                ip_address=client_ip,
                action_taken=action_taken,
                reason=f"Behavioral rule violated: {details}",
                endpoint=endpoint_id,
                rule_type=rule.rule_type,
                threshold=rule.threshold,
                window=rule.window,
                **event_metadata,
            )
        return action_taken

    async def _send_behavior_event(
        self,
        event_type: str,
        ip_address: str,
        action_taken: str,
        reason: str,
        **kwargs: object,
    ) -> None:
        if not self.agent_handler:
            return

        try:
            from guard_core._pydantic_plugin_mute import get_telemetry_model

            SecurityEvent = get_telemetry_model("SecurityEvent")

            event = SecurityEvent(
                timestamp=datetime.now(timezone.utc),
                event_type=event_type,
                ip_address=ip_address,
                action_taken=action_taken,
                reason=reason,
                rule_type=kwargs.get("rule_type"),
                handler_name=_BEHAVIOR_HANDLER_NAME,
                metadata=kwargs,
            )
            await self.agent_handler.send_event(event)
        except Exception as e:
            self.logger.error(f"Failed to send behavior event to agent: {e}")
