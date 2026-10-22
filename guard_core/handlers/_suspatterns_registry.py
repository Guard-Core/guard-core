import asyncio
import functools
import json
import logging
import re
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any

from guard_core._utils.detection_scan import _redact_pattern_source
from guard_core.detection_engine import PatternCompiler, PerformanceMonitor
from guard_core.handlers._suspatterns_lazy_rows import _SusPatternsLazyRowsMixin
from guard_core.handlers._suspatterns_sources import (
    _CTX_ALL,
    _DEFAULT_MAX_BODY_INSPECT_BYTES,
)

logger = logging.getLogger("guard_core.handlers.suspatterns")

_SUS_PATTERNS_HANDLER_NAME = "sus_patterns"


_LEGACY_CUSTOM_KEY = ("patterns", "custom")
_LISTED_CUSTOM_KEY = ("patterns", "custom_list")


def _stored_custom_pattern_writes(
    patterns: Any,
) -> list[tuple[str, str, Any, int | None]]:
    ordered = sorted(patterns)
    return [
        (*_LEGACY_CUSTOM_KEY, ",".join(ordered), None),
        (*_LISTED_CUSTOM_KEY, json.dumps(ordered), None),
    ]


def _decode_listed_custom_patterns(stored: Any) -> list[str] | None:
    try:
        decoded = json.loads(stored)
    except (TypeError, ValueError):
        return None
    if isinstance(decoded, list) and all(isinstance(item, str) for item in decoded):
        return decoded
    return None


def _fragments(joined: str) -> set[str]:
    return set(joined.split(",")) if joined else set()


def _reconciled_custom_patterns(legacy: Any, listed: Any) -> list[str]:
    legacy_text = legacy or ""
    decoded = _decode_listed_custom_patterns(listed) if listed is not None else None
    if decoded is not None and _fragments(",".join(decoded)) == _fragments(legacy_text):
        return decoded
    if listed is not None:
        logger.warning(
            "patterns:custom_list is not what patterns:custom splits into "
            "(an engine that predates the list key wrote the legacy key last, "
            "or the list is not a JSON list of strings); using patterns:custom"
        )
    return legacy_text.split(",") if legacy_text else []


class _SusPatternsRegistryMixin(_SusPatternsLazyRowsMixin):
    _instance: Any = None
    _config: Any = None
    patterns: list[str]
    custom_patterns: set[str]
    compiled_custom_patterns: set[tuple[re.Pattern, frozenset[str], str]]
    redis_handler: Any = None
    agent_handler: Any = None
    _compiler: PatternCompiler | None
    _performance_monitor: PerformanceMonitor | None

    @property
    def _events_agent_handler(self) -> Any:
        if not getattr(self._config, "agent_enable_events", True):
            return None
        return self.agent_handler

    async def _send_pattern_event(
        self,
        event_type: str,
        ip_address: str,
        action_taken: str,
        reason: str,
        pattern_matched: str | None = None,
        endpoint: str | None = None,
        consumer_fields: Callable[[], dict[str, Any]] | None = None,
        **kwargs: Any,
    ) -> None:
        agent_handler = self._events_agent_handler
        if not agent_handler or event_type in getattr(
            self._config, "muted_event_types", ()
        ):
            return

        try:
            from guard_core._pydantic_plugin_mute import get_telemetry_model

            SecurityEvent = get_telemetry_model("SecurityEvent")

            if consumer_fields is not None:
                built = consumer_fields()
                endpoint = built.pop("endpoint", endpoint)
                kwargs.update(built)

            event = SecurityEvent(
                timestamp=datetime.now(timezone.utc),
                event_type=event_type,
                ip_address=ip_address,
                action_taken=action_taken,
                reason=reason,
                pattern_matched=pattern_matched,
                endpoint=endpoint,
                handler_name=_SUS_PATTERNS_HANDLER_NAME,
                metadata=kwargs,
            )
            await agent_handler.send_event(event)
        except Exception as e:
            logger.error(f"Failed to send pattern event to agent: {e}")

    async def initialize_redis(self, redis_handler: Any) -> None:
        self.redis_handler = redis_handler
        if not self.redis_handler:
            return
        try:
            legacy, listed = await self.redis_handler.get_many(
                [_LEGACY_CUSTOM_KEY, _LISTED_CUSTOM_KEY]
            )
            for pattern in _reconciled_custom_patterns(legacy, listed):
                if pattern not in self.custom_patterns:
                    restored = await self.add_pattern(pattern, custom=True)
                    if not restored:
                        logger.warning(
                            f"Skipped restoring persisted pattern: "
                            f"{_redact_pattern_source(pattern)[:50]}..."
                        )
        except Exception as e:
            logger.warning("Custom pattern restore skipped: %s", e)

    @classmethod
    async def add_pattern(cls, pattern: str, custom: bool = False) -> bool:
        instance = cls()

        compiler = instance._compiler or PatternCompiler()
        max_content_length = getattr(
            instance._config,
            "detection_max_body_inspect_bytes",
            _DEFAULT_MAX_BODY_INSPECT_BYTES,
        )
        validate_with_cap = functools.partial(
            compiler.validate_pattern_safety, max_content_length=max_content_length
        )
        is_safe, reason = await asyncio.to_thread(validate_with_cap, pattern)
        if not is_safe:
            logger.warning(
                f"Rejected unsafe pattern ({reason}): "
                f"{_redact_pattern_source(pattern)[:50]}..."
            )
            return False

        compiled_pattern = re.compile(pattern, re.IGNORECASE | re.MULTILINE)
        compiled_tuple = (compiled_pattern, _CTX_ALL, "custom")
        if custom:
            instance.compiled_custom_patterns.add(compiled_tuple)
            instance.custom_patterns.add(pattern)

            if instance.redis_handler:
                await instance.redis_handler.write_atomically(
                    sets=_stored_custom_pattern_writes(instance.custom_patterns)
                )
        else:
            instance.compiled_patterns.append(compiled_tuple)
            instance.patterns.append(pattern)

        if instance._compiler:
            await instance._compiler.clear_cache()

        if instance.agent_handler:
            from guard_core.core.events.event_types import EVENT_PATTERN_ADDED

            details = f"{'Custom' if custom else 'Default'} pattern added"
            await instance._send_pattern_event(
                event_type=EVENT_PATTERN_ADDED,
                ip_address="system",
                action_taken="pattern_added",
                reason=f"{details} to detection system",
                pattern=_redact_pattern_source(pattern),
                pattern_type="custom" if custom else "default",
                total_patterns=len(instance.custom_patterns)
                if custom
                else len(instance.patterns),
            )

        return True

    async def _remove_custom_pattern(self, pattern: str) -> bool:
        if pattern not in self.custom_patterns:
            return False

        self.custom_patterns.discard(pattern)

        self.compiled_custom_patterns = {
            (p, ctx, cat)
            for p, ctx, cat in self.compiled_custom_patterns
            if p.pattern != pattern
        }

        if self.redis_handler:
            await self.redis_handler.write_atomically(
                sets=_stored_custom_pattern_writes(self.custom_patterns)
            )

        return True

    async def _remove_default_pattern(self, pattern: str) -> bool:
        if pattern not in self.patterns:
            return False

        index = self.patterns.index(pattern)
        self.patterns.pop(index)

        if 0 <= index < len(self.compiled_patterns):
            self.compiled_patterns.pop(index)
            return True

        return False

    async def _clear_pattern_caches(self, pattern: str) -> None:
        if self._compiler:
            await self._compiler.clear_cache()
        if self._performance_monitor:
            await self._performance_monitor.remove_pattern_stats(pattern)

    async def _send_pattern_removal_event(
        self, pattern: str, custom: bool, total_patterns: int
    ) -> None:
        if not self.agent_handler:
            return

        from guard_core.core.events.event_types import EVENT_PATTERN_REMOVED

        details = f"{'Custom' if custom else 'Default'} pattern removed"
        await self._send_pattern_event(
            event_type=EVENT_PATTERN_REMOVED,
            ip_address="system",
            action_taken="pattern_removed",
            reason=f"{details} from detection system",
            pattern=_redact_pattern_source(pattern),
            pattern_type="custom" if custom else "default",
            total_patterns=total_patterns,
        )

    @classmethod
    async def remove_pattern(cls, pattern: str, custom: bool = False) -> bool:
        instance = cls()

        if custom:
            pattern_removed = await instance._remove_custom_pattern(pattern)
        else:
            pattern_removed = await instance._remove_default_pattern(pattern)

        if pattern_removed:
            await instance._clear_pattern_caches(pattern)

        if pattern_removed:
            total_patterns = (
                len(instance.custom_patterns) if custom else len(instance.patterns)
            )
            await instance._send_pattern_removal_event(pattern, custom, total_patterns)

        return pattern_removed

    @classmethod
    async def get_default_patterns(cls) -> list[str]:
        instance = cls()
        return instance.patterns.copy()

    @classmethod
    async def get_custom_patterns(cls) -> list[str]:
        instance = cls()
        return list(instance.custom_patterns)

    @classmethod
    async def get_all_patterns(cls) -> list[str]:
        instance = cls()
        return instance.patterns + list(instance.custom_patterns)

    @classmethod
    async def get_default_compiled_patterns(
        cls,
    ) -> list[tuple[re.Pattern, frozenset[str], str]]:
        instance = cls()
        return instance.compiled_patterns.copy()

    @classmethod
    async def get_custom_compiled_patterns(
        cls,
    ) -> list[tuple[re.Pattern, frozenset[str], str]]:
        instance = cls()
        return list(instance.compiled_custom_patterns)

    @classmethod
    async def get_all_compiled_patterns(
        cls,
    ) -> list[tuple[re.Pattern, frozenset[str], str]]:
        instance = cls()
        return instance.compiled_patterns + list(instance.compiled_custom_patterns)

    @classmethod
    async def reset(cls) -> None:
        if cls._instance is not None:
            cls._instance.custom_patterns.clear()
            cls._instance.compiled_custom_patterns.clear()

            cls._instance.redis_handler = None
            cls._instance.agent_handler = None

            if hasattr(cls._instance, "_compiler") and cls._instance._compiler:
                await cls._instance._compiler.clear_cache()

            if (
                hasattr(cls._instance, "_performance_monitor")
                and cls._instance._performance_monitor
            ):
                await cls._instance._performance_monitor.clear_stats()

            cls._config = None
