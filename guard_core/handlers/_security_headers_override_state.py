import logging
import time
from typing import Any

from cachetools import TTLCache

from guard_core._security_headers_override import (
    OVERRIDE_PULL_INTERVAL_SECONDS,
    PROCESS_OVERRIDE,
    OverrideRecord,
    config_fingerprint,
    now_monotonic,
    override_display,
    override_event_metadata,
)
from guard_core._utils.logging_utils import _sanitize_for_log
from guard_core._utils.request_logging import (
    _redact_sensitive_headers,
    redact_endpoint_for_display,
)
from guard_core.models import SecurityConfig

_OVERRIDE_NAMESPACE = "security_headers"


def _redacted(keys: dict[str, Any]) -> dict[str, str]:
    return _redact_sensitive_headers(override_display(keys), None)


def _safe(value: Any) -> str:
    return _sanitize_for_log(str(value))


class SecurityHeadersOverrideMixin:
    _instance: Any
    headers_cache: TTLCache
    redis_handler: Any
    agent_handler: Any
    logger: logging.Logger

    _override: OverrideRecord
    _override_epoch: int
    _override_saved_at: float
    _override_announced_at: float
    _override_in_redis: bool
    _override_next_pull: float
    _override_save_retry_at: float
    _startup_hash: str | None

    def _initialize_override_state(self) -> None:
        self._override = OverrideRecord(0.0, {})
        self._override_epoch = PROCESS_OVERRIDE.reset_epoch
        self._override_saved_at = 0.0
        self._override_announced_at = 0.0
        self._override_in_redis = False
        self._override_next_pull = 0.0
        self._override_save_retry_at = 0.0
        self._startup_hash = None

    def _is_global_manager(self) -> bool:
        return bool(type(self)._instance is self)

    def _current_override(self) -> OverrideRecord:
        if PROCESS_OVERRIDE.reset_epoch != self._override_epoch:
            self._override_epoch = PROCESS_OVERRIDE.reset_epoch
            self._override = OverrideRecord(self._override_saved_at + 1e-6, {})
        process = PROCESS_OVERRIDE.record
        if process.ordered_at() > self._override.ordered_at():
            self._override = process
        return self._override

    def _next_set_at(self) -> float:
        return max(time.time(), self._current_override().ordered_at() + 1e-6)

    def _record_override_from_call(self, passed: dict[str, Any]) -> None:
        if not self._is_global_manager():
            return
        previous = dict(self._current_override().keys)
        if previous == passed:
            return
        dropped = {key: value for key, value in previous.items() if key not in passed}
        shown, shown_dropped = _redacted(passed), _redacted(dropped)
        record = OverrideRecord(
            self._next_set_at(),
            passed,
            override_event_metadata(passed, dropped, shown, shown_dropped),
        )
        PROCESS_OVERRIDE.record = record
        self._override = record
        self._log_override_change(passed, dropped, shown, shown_dropped)

    def _log_override_change(
        self,
        passed: dict[str, Any],
        dropped: dict[str, Any],
        shown: dict[str, str],
        shown_dropped: dict[str, str],
    ) -> None:
        if dropped:
            self.logger.warning(
                "Security headers override changed by configure(): "
                "dropped keys: %s; dropped values: %s; "
                "override now sets: %s; values: %s",
                ", ".join(sorted(dropped)),
                _safe(shown_dropped),
                ", ".join(sorted(passed)) or "nothing",
                _safe(shown),
            )
        else:
            self.logger.info(
                "Security headers override set by configure(): keys: %s; values: %s",
                ", ".join(sorted(passed)),
                _safe(shown),
            )

    def _reset_override(self) -> None:
        if self._is_global_manager():
            PROCESS_OVERRIDE.reset_epoch += 1
            PROCESS_OVERRIDE.record = OverrideRecord(0.0, {})
        self._override_epoch = PROCESS_OVERRIDE.reset_epoch
        self._override = OverrideRecord(self._override.ordered_at() + 1e-6, {})
        self._override_saved_at = self._override.set_at
        self._override_in_redis = False
        self._override_next_pull = 0.0
        self._startup_hash = None

    def _override_key(self) -> str:
        return f"override:{self._startup_hash}"

    async def _sync_override(self, config: SecurityConfig) -> None:
        if self.redis_handler is not None and self._startup_hash is None:
            self._startup_hash = config_fingerprint(config)
        current = self._current_override()
        if current.event and current.set_at > self._override_announced_at:
            self._override_announced_at = current.set_at
            await self._send_override_event(current)
        if self.redis_handler is not None:
            await self._sync_override_with_redis(current)

    async def _sync_override_with_redis(self, current: OverrideRecord) -> None:
        now = now_monotonic()
        if current.set_at > self._override_saved_at:
            if current.keys or self._override_in_redis:
                if now >= self._override_save_retry_at:
                    await self._save_override(current, now)
                return
            self._override_saved_at = current.set_at
        if now >= self._override_next_pull:
            await self._pull_override(now)

    async def _save_override(self, record: OverrideRecord, now: float) -> None:
        try:
            if record.keys:
                await self.redis_handler.set_key(
                    _OVERRIDE_NAMESPACE, self._override_key(), record.to_json()
                )
            else:
                async with self.redis_handler.get_connection() as conn:
                    await conn.delete(
                        f"{self.redis_handler.config.redis_prefix}"
                        f"{_OVERRIDE_NAMESPACE}:{self._override_key()}"
                    )
        except Exception as e:
            self._override_save_retry_at = now + OVERRIDE_PULL_INTERVAL_SECONDS
            self.logger.warning(
                "Failed to save the security headers override: %s", _safe(e)
            )
            return
        self._override_saved_at = record.set_at
        self._override_in_redis = bool(record.keys)

    async def _pull_override(self, now: float) -> None:
        self._override_next_pull = now + OVERRIDE_PULL_INTERVAL_SECONDS
        try:
            raw = await self.redis_handler.get_key(
                _OVERRIDE_NAMESPACE, self._override_key()
            )
        except Exception as e:
            self.logger.warning(
                "Failed to pull the security headers override, keeping the last "
                "applied one: %s",
                _safe(e),
            )
            return
        if raw is None:
            self._adopt_cleared_override()
            return
        try:
            record = OverrideRecord.from_json(raw)
        except (ValueError, KeyError, TypeError) as e:
            self.logger.warning(
                "Ignoring an unreadable security headers override in Redis: %s",
                _safe(e),
            )
            return
        self._override_in_redis = True
        if record.ordered_at() > self._current_override().ordered_at():
            self._override = record
            self._override_saved_at = record.set_at
            self.logger.info(
                "Security headers override pulled from Redis: keys: %s; values: %s",
                ", ".join(sorted(record.keys)) or "nothing",
                _safe(_redacted(dict(record.keys))),
            )

    def _adopt_cleared_override(self) -> None:
        if not self._override_in_redis:
            return
        self._override_in_redis = False
        cleared = OverrideRecord(self._next_set_at(), {})
        self._override = cleared
        self._override_saved_at = cleared.set_at
        self.logger.info("Security headers override cleared in Redis")

    async def _send_override_event(self, record: OverrideRecord) -> None:
        if not self.agent_handler:
            return
        from guard_core.core.events.event_types import EVENT_SECURITY_HEADERS_APPLIED

        try:
            from datetime import datetime, timezone

            from guard_core._pydantic_plugin_mute import get_telemetry_model

            SecurityEvent = get_telemetry_model("SecurityEvent")
            event = SecurityEvent(
                timestamp=datetime.now(timezone.utc),
                event_type=EVENT_SECURITY_HEADERS_APPLIED,
                action_taken="override_cleared"
                if not record.keys
                else "override_changed",
                handler_name="security_headers",
                metadata=dict(record.event or {}),
            )
            await self.agent_handler.send_event(event)
        except Exception as e:
            self.logger.debug(
                "Failed to send the override event to agent: %s",
                redact_endpoint_for_display(str(e), None),
            )
