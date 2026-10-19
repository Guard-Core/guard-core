import logging
import time
from collections.abc import MutableMapping
from datetime import datetime, timezone
from typing import Any

_IP_BAN_HANDLER_NAME = "ip_ban"


class IpBanEventMixin:
    agent_handler: Any = None
    logger: logging.Logger
    banned_ips: MutableMapping[str, float]
    evicted_to_report: list[tuple[str, float, int]]
    MAX_LOCAL_BANS: int

    async def _report_evictions(self) -> None:
        """Send one ip_ban_evicted event for every memory-only ban evicted since
        the last report. Called after every insert that can evict: a ban written
        by _store_ban and a Redis hit cached by the lookup."""
        pending, self.evicted_to_report = self.evicted_to_report, []
        capacity = getattr(self.banned_ips, "maxsize", self.MAX_LOCAL_BANS)
        for identity, expiry, evictions in pending:
            await self._send_ban_evicted_event(identity, expiry, evictions, capacity)

    async def initialize_agent(self, agent_handler: Any) -> None:
        self.agent_handler = agent_handler

    async def _send_ban_event(
        self,
        ip: str,
        duration: int,
        reason: str,
        recidive_count: int | None = None,
    ) -> None:
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
                metadata=(
                    {"duration": duration}
                    if recidive_count is None
                    else {"duration": duration, "recidive_count": recidive_count}
                ),
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
