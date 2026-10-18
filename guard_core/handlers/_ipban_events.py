import logging
import time
from datetime import datetime, timezone
from typing import Any

_IP_BAN_HANDLER_NAME = "ip_ban"


class IpBanEventMixin:
    agent_handler: Any = None
    logger: logging.Logger

    async def initialize_agent(self, agent_handler: Any) -> None:
        self.agent_handler = agent_handler

    async def _send_ban_event(self, ip: str, duration: int, reason: str) -> None:
        from guard_core.core.events.event_types import EVENT_IP_BANNED

        try:
            from guard_core._pydantic_plugin_mute import get_telemetry_model

            SecurityEvent = get_telemetry_model("SecurityEvent")

            event = SecurityEvent(
                timestamp=datetime.now(timezone.utc),
                event_type=EVENT_IP_BANNED,
                ip_address=ip,
                action_taken="banned",
                reason=reason,
                handler_name=_IP_BAN_HANDLER_NAME,
                metadata={"duration": duration},
            )
            await self.agent_handler.send_event(event)
        except Exception as e:
            self.logger.error("Failed to send ban event to agent: %s", e)

    async def _send_ban_refused_event(
        self, ip: str, duration: int, reason: str, refusal: str
    ) -> None:
        from guard_core.core.events.event_types import EVENT_IP_BAN_REFUSED

        try:
            from guard_core._pydantic_plugin_mute import get_telemetry_model

            SecurityEvent = get_telemetry_model("SecurityEvent")

            event = SecurityEvent(
                timestamp=datetime.now(timezone.utc),
                event_type=EVENT_IP_BAN_REFUSED,
                ip_address=ip,
                action_taken="ban_refused",
                reason=f"Refused to ban {ip}: {refusal} would self-DoS this deployment",
                handler_name=_IP_BAN_HANDLER_NAME,
                metadata={
                    "duration": duration,
                    "refusal": refusal,
                    "ban_reason": reason,
                },
            )
            await self.agent_handler.send_event(event)
        except Exception as e:
            self.logger.error("Failed to send ban refused event to agent: %s", e)

    async def _send_ban_evicted_event(
        self, ip: str, expiry: float, evictions: int, capacity: int
    ) -> None:
        from guard_core.core.events.event_types import EVENT_IP_BAN_EVICTED

        try:
            from guard_core._pydantic_plugin_mute import get_telemetry_model

            SecurityEvent = get_telemetry_model("SecurityEvent")

            event = SecurityEvent(
                timestamp=datetime.now(timezone.utc),
                event_type=EVENT_IP_BAN_EVICTED,
                ip_address=ip,
                action_taken="ban_evicted",
                reason=(
                    "An unexpired ban was evicted because the in-memory ban store "
                    "is full"
                ),
                handler_name=_IP_BAN_HANDLER_NAME,
                metadata={
                    "remaining_seconds": max(0, int(expiry - time.time())),
                    "evictions": evictions,
                    "capacity": capacity,
                },
            )
            await self.agent_handler.send_event(event)
        except Exception as e:
            self.logger.error("Failed to send ban evicted event to agent: %s", e)

    async def _send_unban_event(self, ip: str, reason: str) -> None:
        from guard_core.core.events.event_types import EVENT_IP_UNBANNED

        try:
            from guard_core._pydantic_plugin_mute import get_telemetry_model

            SecurityEvent = get_telemetry_model("SecurityEvent")

            event = SecurityEvent(
                timestamp=datetime.now(timezone.utc),
                event_type=EVENT_IP_UNBANNED,
                ip_address=ip,
                action_taken="unbanned",
                reason=reason,
                handler_name=_IP_BAN_HANDLER_NAME,
                metadata={"action": "unban"},
            )
            await self.agent_handler.send_event(event)
        except Exception as e:
            self.logger.error("Failed to send unban event to agent: %s", e)
