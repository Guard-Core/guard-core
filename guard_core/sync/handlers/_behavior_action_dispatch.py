import logging
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

from guard_core.models import SecurityConfig
from guard_core.sync.utils import _log_at_level

if TYPE_CHECKING:
    from guard_core.sync.handlers.behavior_handler import BehaviorRule


_BEHAVIOR_HANDLER_NAME = "behavior"


class BehaviorActionDispatchMixin:
    config: SecurityConfig
    logger: logging.Logger
    agent_handler: Any

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

    def _execute_ban_action(
        self,
        client_ip: str,
        details: str,
        rule: "BehaviorRule | None" = None,
    ) -> str:
        if not self.config.enable_ip_banning:
            return "tracked"

        from guard_core.sync.handlers.ipban_handler import ip_ban_manager

        duration = (
            rule.ban_duration
            if rule is not None and rule.ban_duration is not None
            else 3600
        )
        applied = ip_ban_manager.ban_ip(client_ip, duration, "behavioral_violation")
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

    def _execute_active_mode_action(
        self, rule: "BehaviorRule", client_ip: str, endpoint_id: str, details: str
    ) -> str:
        if rule.custom_action:
            rule.custom_action(client_ip, endpoint_id, details)
            return rule.action

        if rule.action == "ban":
            return self._execute_ban_action(client_ip, details, rule)

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

    def apply_action(
        self, rule: "BehaviorRule", client_ip: str, endpoint_id: str, details: str
    ) -> None:
        if self.config.passive_mode:
            action_taken = "logged_only"
            self._log_passive_mode_action(rule, client_ip, details)
        else:
            action_taken = self._execute_active_mode_action(
                rule, client_ip, endpoint_id, details
            )

        if self.agent_handler:
            from guard_core.sync.core.events.event_types import EVENT_BEHAVIOR_VIOLATION

            self._send_behavior_event(
                event_type=EVENT_BEHAVIOR_VIOLATION,
                ip_address=client_ip,
                action_taken=action_taken,
                reason=f"Behavioral rule violated: {details}",
                endpoint=endpoint_id,
                rule_type=rule.rule_type,
                threshold=rule.threshold,
                window=rule.window,
            )

    def _send_behavior_event(
        self,
        event_type: str,
        ip_address: str,
        action_taken: str,
        reason: str,
        **kwargs: Any,
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
            self.agent_handler.send_event(event)
        except Exception as e:
            self.logger.error(f"Failed to send behavior event to agent: {e}")
