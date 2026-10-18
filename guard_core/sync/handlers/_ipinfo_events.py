import logging
from datetime import datetime, timezone
from typing import Any

from guard_core.sync.core.events.event_types import EVENT_COUNTRY_BLOCKED
from guard_core.sync.protocols.agent_protocol import SyncAgentHandlerProtocol

_IPINFO_HANDLER_NAME = "ipinfo"


class IpInfoEventsMixin:
    agent_handler: SyncAgentHandlerProtocol | None
    logger: logging.Logger

    def get_country(self, ip: str) -> str | None: ...

    def _send_geo_event(
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
                handler_name=_IPINFO_HANDLER_NAME,
                metadata=kwargs,
            )
            self.agent_handler.send_event(event)
        except Exception as e:
            self.logger.error(f"Failed to send geo event to agent: {e}")

    def check_country_access(
        self,
        ip: str,
        blocked_countries: list[str],
        whitelist_countries: list[str] | None = None,
    ) -> tuple[bool, str | None]:
        country = self.get_country(ip)

        if not country:
            if whitelist_countries:
                return False, None
            return True, None

        if whitelist_countries and country not in whitelist_countries:
            self._send_geo_event(
                event_type=EVENT_COUNTRY_BLOCKED,
                ip_address=ip,
                action_taken="request_blocked",
                reason=f"Country {country} not in allowed list",
                country=country,
                rule_type="country_whitelist",
            )
            return False, country

        if country in blocked_countries:
            self._send_geo_event(
                event_type=EVENT_COUNTRY_BLOCKED,
                ip_address=ip,
                action_taken="request_blocked",
                reason=f"Country {country} is blocked",
                country=country,
                rule_type="country_blacklist",
            )
            return False, country

        return True, country
