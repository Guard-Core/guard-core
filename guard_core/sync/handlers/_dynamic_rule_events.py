import logging
from datetime import datetime, timezone

from guard_core.models import DynamicRules
from guard_core.sync.protocols.agent_protocol import SyncAgentHandlerProtocol

_DYNAMIC_RULES_HANDLER_NAME = "dynamic_rules"


class DynamicRuleEventSenderMixin:
    agent_handler: SyncAgentHandlerProtocol | None
    current_rules: DynamicRules | None
    logger: logging.Logger

    def _send_rule_received_event(self, rules: DynamicRules) -> None:
        from guard_core.sync.core.events.event_types import EVENT_DYNAMIC_RULE_UPDATED

        if not self.agent_handler:
            return

        try:
            from guard_core._pydantic_plugin_mute import get_telemetry_model

            SecurityEvent = get_telemetry_model("SecurityEvent")

            reason = f"Received updated rules {rules.rule_id} v{rules.version}"

            event = SecurityEvent(
                timestamp=datetime.now(timezone.utc),
                event_type=EVENT_DYNAMIC_RULE_UPDATED,
                ip_address="system",
                action_taken="rules_received",
                reason=reason,
                handler_name=_DYNAMIC_RULES_HANDLER_NAME,
                metadata={
                    "rule_id": rules.rule_id,
                    "version": rules.version,
                    "previous_version": self.current_rules.version
                    if self.current_rules
                    else 0,
                },
            )
            self.agent_handler.send_event(event)
        except Exception as e:
            self.logger.error(f"Failed to send rule updated event: {e}")

    def _send_rule_applied_event(
        self, rules: DynamicRules, skipped: list[str] | None = None
    ) -> None:
        from guard_core.sync.core.events.event_types import EVENT_DYNAMIC_RULE_APPLIED

        if not self.agent_handler:
            return

        try:
            from guard_core._pydantic_plugin_mute import get_telemetry_model

            SecurityEvent = get_telemetry_model("SecurityEvent")

            event = SecurityEvent(
                timestamp=datetime.now(timezone.utc),
                event_type=EVENT_DYNAMIC_RULE_APPLIED,
                ip_address="system",
                action_taken="rules_updated",
                reason=f"Applied dynamic rules {rules.rule_id} v{rules.version}",
                handler_name=_DYNAMIC_RULES_HANDLER_NAME,
                metadata={
                    "rule_id": rules.rule_id,
                    "version": rules.version,
                    "ip_bans": len(rules.ip_blacklist),
                    "country_blocks": len(rules.blocked_countries),
                    "emergency_mode": rules.emergency_mode,
                    "skipped": list(skipped or []),
                },
            )
            self.agent_handler.send_event(event)
        except Exception as e:
            self.logger.error(f"Failed to send rule applied event: {e}")

    def _send_rule_rejected_event(
        self, rules: DynamicRules, problems: list[str]
    ) -> None:
        from guard_core.sync.core.events.event_types import EVENT_DYNAMIC_RULE_UPDATED

        if not self.agent_handler:
            return

        try:
            from guard_core._pydantic_plugin_mute import get_telemetry_model

            SecurityEvent = get_telemetry_model("SecurityEvent")

            event = SecurityEvent(
                timestamp=datetime.now(timezone.utc),
                event_type=EVENT_DYNAMIC_RULE_UPDATED,
                ip_address="system",
                action_taken="rules_rejected",
                reason=f"Rejected malformed dynamic rules {rules.rule_id} "
                f"v{rules.version}",
                handler_name=_DYNAMIC_RULES_HANDLER_NAME,
                metadata={
                    "rule_id": rules.rule_id,
                    "version": rules.version,
                    "rejected": problems,
                },
            )
            self.agent_handler.send_event(event)
        except Exception as e:
            self.logger.error(f"Failed to send rule rejected event: {e}")

    def _send_emergency_event(self, whitelist: list[str]) -> None:
        from guard_core.sync.core.events.event_types import EVENT_EMERGENCY_MODE

        if not self.agent_handler:
            return

        try:
            from guard_core._pydantic_plugin_mute import get_telemetry_model

            SecurityEvent = get_telemetry_model("SecurityEvent")

            event = SecurityEvent(
                timestamp=datetime.now(timezone.utc),
                event_type=EVENT_EMERGENCY_MODE,
                ip_address="system",
                action_taken="emergency_lockdown",
                reason="[EMERGENCY MODE] activated via dynamic rules",
                handler_name=_DYNAMIC_RULES_HANDLER_NAME,
                metadata={
                    "whitelist_count": len(whitelist),
                    "whitelist": whitelist[:10],
                },
            )
            self.agent_handler.send_event(event)
        except Exception as e:
            self.logger.error(f"Failed to send emergency event: {e}")
