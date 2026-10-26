import logging
from collections.abc import Mapping, Sequence

from cachetools import TTLCache

from guard_core import _security_headers_override as clocks
from guard_core._redis_enablement import redis_is_configured
from guard_core._security_headers_override import (
    CORS_EVENTED,
    CORS_LOGGED,
    OVERRIDE_PULL_INTERVAL_SECONDS,
    PROCESS_OVERRIDE,
    PULLED_OVERRIDES,
    CorsParams,
    OverrideRecord,
    config_fingerprint,
    corrected_wall_now,
    cors_params_of,
    cors_widens,
    first_time,
    merge_cors,
    now_monotonic,
    override_display,
    override_event_metadata,
)
from guard_core._utils.config_registry import REDIS_HANDLERS
from guard_core._utils.logging_utils import _sanitize_for_log
from guard_core._utils.request_logging import (
    _redact_sensitive_headers,
    redact_endpoint_for_display,
)
from guard_core.handlers._security_headers_persistence_calls import (
    SecurityHeadersPersistenceCalls,
)
from guard_core.models import SecurityConfig
from guard_core.protocols.agent_protocol import AgentHandlerProtocol
from guard_core.protocols.redis_protocol import RedisHandlerProtocol

_OVERRIDE_NAMESPACE = "security_headers"
_OWN_STATE_KEYS = ("csp_config", "hsts_config", "custom_headers")


def _redacted(keys: Mapping[str, object]) -> dict[str, str]:
    return _redact_sensitive_headers(override_display(keys), None)


def _safe(value: object) -> str:
    return _sanitize_for_log(str(value))


class SecurityHeadersOverrideMixin(SecurityHeadersPersistenceCalls):
    # the process-wide manager, read here for its own-state flag and its Redis handler
    _instance: "SecurityHeadersOverrideMixin | None"
    headers_cache: TTLCache
    redis_handler: RedisHandlerProtocol | None
    agent_handler: AgentHandlerProtocol | None
    logger: logging.Logger

    _override: OverrideRecord
    _override_epoch: int
    _override_saved_at: float
    _override_announced_at: float
    _override_in_redis: bool
    _override_next_pull: float
    _override_save_retry_at: float
    _startup_hash: str | None
    _redis_initialized: bool
    _override_next_lookup: float
    _reader_hash: tuple[int, str] | None
    _own_state_dirty: bool

    def _initialize_override_state(self) -> None:
        self._override = OverrideRecord(0.0, {})
        self._override_epoch = PROCESS_OVERRIDE.reset_epoch
        self._override_saved_at = 0.0
        self._override_announced_at = 0.0
        self._override_in_redis = False
        self._override_next_pull = 0.0
        self._override_save_retry_at = 0.0
        self._startup_hash = None
        self._redis_initialized = False
        self._override_next_lookup = 0.0
        self._reader_hash = None
        self._own_state_dirty = False

    def _is_global_manager(self) -> bool:
        return bool(type(self)._instance is self)

    def resolve_override(self) -> OverrideRecord:
        if PROCESS_OVERRIDE.reset_epoch != self._override_epoch:
            self._override_epoch = PROCESS_OVERRIDE.reset_epoch
            self._override = OverrideRecord(self._override_saved_at + 1e-6, {})
        process = PROCESS_OVERRIDE.record
        if process.set_at > 0.0 and process.ordered_at() > self._override.ordered_at():
            self._override = process
        return self._override

    _current_override = resolve_override

    def override_for_reader(
        self, config: SecurityConfig, current: OverrideRecord | None = None
    ) -> OverrideRecord:
        if current is None:
            current = self.resolve_override()
        if not PULLED_OVERRIDES:
            return current
        if self._reader_hash is None or self._reader_hash[0] != id(config):
            self._reader_hash = (id(config), config_fingerprint(config))
        pulled = PULLED_OVERRIDES.get(self._reader_hash[1])
        if pulled is not None and pulled.ordered_at() > current.ordered_at():
            return pulled
        return current

    def cors_params_for(
        self, config: SecurityConfig, current: OverrideRecord | None = None
    ) -> CorsParams:
        base = cors_params_of(config)
        override = self.override_for_reader(config, current)
        merged, reason = merge_cors(base, override.keys)
        if (merged is not base or reason) and first_time(
            CORS_LOGGED, (id(config), override.set_at)
        ):
            self._log_cors_override(base, merged, reason)
        return merged

    def _log_cors_override(
        self, base: CorsParams, merged: CorsParams, reason: str | None
    ) -> None:
        if reason is not None and merged is not base:
            self.logger.warning("CORS override fields refused for this app: %s", reason)
        elif reason is not None:
            self.logger.warning(
                "CORS override refused for this app, it keeps its own CORS: %s", reason
            )
        elif cors_widens(base, merged):
            self.logger.warning(
                "CORS override widens the CORS of this app: enabled=%s, origins=%s, "
                "credentials=%s%s",
                merged.enabled,
                ", ".join(merged.origins) or "none",
                merged.credentials,
                "; the app was built without CORS and may run its own CORS layer"
                if not base.enabled
                else "",
            )
        else:
            self.logger.info("CORS override narrows or keeps the CORS of this app")

    async def send_cors_override_event(
        self, config: SecurityConfig, current: OverrideRecord | None = None
    ) -> None:
        if not self.agent_handler:
            return
        override = self.override_for_reader(config, current)
        if not override.keys:
            return
        merged, reason = merge_cors(cors_params_of(config), override.keys)
        if reason is None or not first_time(
            CORS_EVENTED, (id(config), override.set_at)
        ):
            return
        await self._send_override_event_for(
            "cors_override_refused",
            {"reason": reason, "override_keys": sorted(override.keys)},
        )

    def _next_set_at(self) -> float:
        return max(corrected_wall_now(), self._current_override().ordered_at() + 1e-6)

    def _record_override_from_call(self, passed: dict[str, object]) -> None:
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
        passed: dict[str, object],
        dropped: dict[str, object],
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
            PULLED_OVERRIDES.clear()
        elif self._startup_hash is not None:
            PULLED_OVERRIDES.pop(self._startup_hash, None)
        self._override_epoch = PROCESS_OVERRIDE.reset_epoch
        self._override = OverrideRecord(self._override.ordered_at() + 1e-6, {})
        self._override_saved_at = self._override.set_at
        self._override_in_redis = False
        self._override_next_pull = 0.0
        self._startup_hash = None
        self._redis_initialized = False
        self._override_next_lookup = 0.0
        self._own_state_dirty = False

    def _override_key(self) -> str:
        return f"override:{self._startup_hash}"

    async def _sync_override(
        self, config: SecurityConfig, current: OverrideRecord
    ) -> OverrideRecord:
        if current.event and current.set_at > self._override_announced_at:
            self._override_announced_at = current.set_at
            await self._send_override_event(current)
        if self.redis_handler is None:
            self._find_registered_redis_handler(config)
        if self.redis_handler is None:
            return current
        if not self._redis_initialized:
            await self.initialize_redis(self.redis_handler, config)
        else:
            await self._sync_override_with_redis(current)
        return current if self._override is current else self._current_override()

    def _find_registered_redis_handler(self, config: SecurityConfig) -> None:
        # Released adapters build the response context without their Redis handler;
        # the handler initializer registered it under the config, found at the pull
        # boundary only.
        if not redis_is_configured(config):
            return
        now = now_monotonic()
        if now < self._override_next_lookup:
            return
        self._override_next_lookup = now + OVERRIDE_PULL_INTERVAL_SECONDS
        # the registry holds handlers of any kind; only one that speaks the Redis
        # protocol is used
        registered = REDIS_HANDLERS.lookup(config)
        self.redis_handler = (
            registered if isinstance(registered, RedisHandlerProtocol) else None
        )

    async def _flush_own_state(self) -> None:
        manager = type(self)._instance
        if manager is None or manager is self or not manager._own_state_dirty:
            return
        shared = self._global_sharing_state()
        if shared is not None:
            shared._own_state_dirty = False
            await shared._cache_configuration(own_state=True)

    async def _sync_override_with_redis(self, current: OverrideRecord) -> None:
        await self._flush_own_state()
        if current.set_at > self._override_saved_at:
            saving = bool(current.keys) or self._override_in_redis
            await self._cache_configuration(own_state=False)
            if saving:
                return
        if now_monotonic() >= self._override_next_pull:
            await self._load_cached_config(own_state=False)

    async def _save_override_record(self) -> None:
        record = self._current_override()
        if record.set_at <= self._override_saved_at:
            return
        if not record.keys and not self._override_in_redis:
            self._override_saved_at = record.set_at
            return
        now = now_monotonic()
        if now < self._override_save_retry_at:
            return
        # _cache_configuration only saves with a handler; none means nothing to save to
        redis_handler = self.redis_handler
        if redis_handler is None:
            return
        try:
            if record.keys:
                await redis_handler.set_key(
                    _OVERRIDE_NAMESPACE, self._override_key(), record.to_json()
                )
            else:
                async with redis_handler.get_connection() as conn:
                    await conn.delete(
                        f"{redis_handler.config.redis_prefix}"
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

    def _global_sharing_state(self) -> "SecurityHeadersOverrideMixin | None":
        # The process-wide manager, when it is attached to the same Redis and config
        # as this app's manager: its own csp, hsts and custom headers ride this pull.
        manager = type(self)._instance
        if (
            manager is None
            or manager is self
            or manager.redis_handler is None
            or manager._startup_hash != self._startup_hash
        ):
            return None
        return manager

    async def _read_override_and_clock(
        self, redis_handler: RedisHandlerProtocol
    ) -> str | bytes | None:
        # GET and TIME in one round trip: the offset to Redis time costs no extra trip.
        prefix = redis_handler.config.redis_prefix
        shared = self._global_sharing_state()
        before = clocks.wall_now()
        async with redis_handler.get_connection() as conn:
            pipe = conn.pipeline(transaction=False)
            pipe.get(f"{prefix}{_OVERRIDE_NAMESPACE}:{self._override_key()}")
            pipe.time()
            if shared is not None:
                for name in _OWN_STATE_KEYS:
                    pipe.get(f"{prefix}{_OVERRIDE_NAMESPACE}:{name}")
            # the pipeline replies are untyped; the override key holds JSON text
            raw: str | bytes | None
            raw, (seconds, microseconds), *own = await pipe.execute()
        after = clocks.wall_now()
        PROCESS_OVERRIDE.clock_offset = (
            seconds + microseconds / 1_000_000 - (before + after) / 2
        )
        if shared is not None:
            self._apply_shared_own_state(shared, own)
        return raw

    # one raw cached value per own-state key (csp, hsts, custom), None when absent
    def _apply_shared_own_state(
        self, shared: "SecurityHeadersOverrideMixin", own: Sequence[str | bytes | None]
    ) -> None:
        try:
            shared._apply_own_state(*own)
        except Exception as e:
            self.logger.warning(
                "Ignoring unreadable cached header config in Redis: %s", _safe(e)
            )

    async def _pull_override(self) -> None:
        self._override_next_pull = now_monotonic() + OVERRIDE_PULL_INTERVAL_SECONDS
        # _load_cached_config only pulls with a handler; none means nothing to pull from
        redis_handler = self.redis_handler
        if redis_handler is None:
            return
        try:
            raw = await self._read_override_and_clock(redis_handler)
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
            PULLED_OVERRIDES[str(self._startup_hash)] = record
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
        PULLED_OVERRIDES[str(self._startup_hash)] = cleared
        self.logger.info("Security headers override cleared in Redis")

    async def _send_override_event(self, record: OverrideRecord) -> None:
        await self._send_override_event_for(
            "override_cleared" if not record.keys else "override_changed",
            dict(record.event or {}),
        )

    async def _send_override_event_for(
        self, action: str, metadata: Mapping[str, object]
    ) -> None:
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
                action_taken=action,
                handler_name="security_headers",
                metadata=metadata,
            )
            await self.agent_handler.send_event(event)
        except Exception as e:
            self.logger.debug(
                "Failed to send the override event to agent: %s",
                redact_endpoint_for_display(str(e), None),
            )
