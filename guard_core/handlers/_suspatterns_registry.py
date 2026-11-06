import asyncio
import functools
import json
import logging
import re
import types
from collections.abc import Awaitable, Callable, Iterable
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Concatenate, Generic, ParamSpec, TypeVar

from guard_core._utils.app_scope import forget_config
from guard_core._utils.detection_scan import _redact_pattern_source
from guard_core.detection_engine import PatternCompiler, PerformanceMonitor
from guard_core.handlers._suspatterns_lazy_rows import _SusPatternsLazyRowsMixin
from guard_core.handlers._suspatterns_sources import (
    _CTX_ALL,
    _scan_window_bytes,
)

if TYPE_CHECKING:
    from guard_core.models import SecurityConfig
    from guard_core.protocols.agent_protocol import AgentHandlerProtocol
    from guard_core.protocols.redis_protocol import RedisHandlerProtocol

logger = logging.getLogger("guard_core.handlers.suspatterns")

_P = ParamSpec("_P")
_R = TypeVar("_R")


class _OnManagerOrDefault(Generic[_P, _R]):
    """A method that acts on the manager it is called on, and on the default
    manager (``cls()``) when called on the class, as the classmethods it replaces
    did, so a per-app manager keeps its own patterns."""

    def __init__(
        self,
        method: Callable[Concatenate["_SusPatternsRegistryMixin", _P], Awaitable[_R]],
    ) -> None:
        self._method = method

    def __get__(
        self, manager: "_SusPatternsRegistryMixin | None", owner: type
    ) -> Callable[_P, Awaitable[_R]]:
        return types.MethodType(self._method, owner() if manager is None else manager)


_SUS_PATTERNS_HANDLER_NAME = "sus_patterns"


_LEGACY_CUSTOM_KEY = ("patterns", "custom")
_LISTED_CUSTOM_KEY = ("patterns", "custom_list")


def _stored_custom_pattern_writes(
    patterns: Iterable[str],
) -> list[tuple[str, str, str, int | None]]:
    ordered = sorted(patterns)
    return [
        (*_LEGACY_CUSTOM_KEY, ",".join(ordered), None),
        (*_LISTED_CUSTOM_KEY, json.dumps(ordered), None),
    ]


def _decode_listed_custom_patterns(stored: str | bytes | bytearray) -> list[str] | None:
    try:
        decoded = json.loads(stored)
    except (TypeError, ValueError):
        return None
    if isinstance(decoded, list) and all(isinstance(item, str) for item in decoded):
        return decoded
    return None


def _fragments(joined: str) -> set[str]:
    return set(joined.split(",")) if joined else set()


def _reconciled_custom_patterns(
    legacy: str | None, listed: str | bytes | bytearray | None
) -> list[str]:
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
    _instance: "_SusPatternsRegistryMixin | None" = None
    _config: "SecurityConfig | None" = None
    patterns: list[str]
    custom_patterns: set[str]
    compiled_patterns: list[tuple[re.Pattern, frozenset[str], str]]
    compiled_custom_patterns: set[tuple[re.Pattern, frozenset[str], str]]
    redis_handler: "RedisHandlerProtocol | None" = None
    agent_handler: "AgentHandlerProtocol | None" = None
    _compiler: PatternCompiler | None
    _performance_monitor: PerformanceMonitor | None
    _sensitive_headers_union: frozenset[str]
    _sensitive_params_union: frozenset[str]
    _sensitive_body_fields_union: frozenset[str]

    @property
    def _events_agent_handler(self) -> "AgentHandlerProtocol | None":
        if not getattr(self._scan_config(), "agent_enable_events", True):
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
        consumer_fields: Callable[[], dict[str, object]] | None = None,
        **kwargs: object,
    ) -> None:
        agent_handler = self._events_agent_handler
        if not agent_handler or event_type in getattr(
            self._scan_config(), "muted_event_types", ()
        ):
            return

        try:
            from guard_core._pydantic_plugin_mute import get_telemetry_model

            SecurityEvent = get_telemetry_model("SecurityEvent")

            event_endpoint: object = endpoint
            route_fields: dict[str, object] = {}
            if consumer_fields is not None:
                built = consumer_fields()
                event_endpoint = built.pop("endpoint", endpoint)
                if "route_template" in built:
                    route_fields["route_template"] = built.pop("route_template")
                kwargs.update(built)

            event = SecurityEvent(
                timestamp=datetime.now(timezone.utc),
                event_type=event_type,
                ip_address=ip_address,
                action_taken=action_taken,
                reason=reason,
                pattern_matched=pattern_matched,
                endpoint=event_endpoint,
                handler_name=_SUS_PATTERNS_HANDLER_NAME,
                metadata=kwargs,
                **route_fields,
            )
            await agent_handler.send_event(event)
        except Exception as e:
            logger.error(f"Failed to send pattern event to agent: {e}")

    async def initialize_redis(
        self, redis_handler: "RedisHandlerProtocol | None"
    ) -> None:
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
                            f"{_redact_pattern_source(pattern, self)[:50]}..."
                        )
        except Exception as e:
            logger.warning("Custom pattern restore skipped: %s", e)

    @_OnManagerOrDefault
    async def add_pattern(self, pattern: str, custom: bool = False) -> bool:

        compiler = self._compiler or PatternCompiler(redaction_names=self)
        max_content_length = _scan_window_bytes(self._scan_config())
        validate_with_cap = functools.partial(
            compiler.validate_pattern_safety, max_content_length=max_content_length
        )
        is_safe, reason = await asyncio.to_thread(validate_with_cap, pattern)
        if not is_safe:
            logger.warning(
                f"Rejected unsafe pattern ({reason}): "
                f"{_redact_pattern_source(pattern, self)[:50]}..."
            )
            return False

        compiled_pattern = await compiler.compile_pattern(pattern)
        compiled_tuple = (compiled_pattern, _CTX_ALL, "custom")
        if custom:
            self.compiled_custom_patterns.add(compiled_tuple)
            self.custom_patterns.add(pattern)

            if self.redis_handler:
                await self.redis_handler.write_atomically(
                    sets=_stored_custom_pattern_writes(self.custom_patterns)
                )
        else:
            self.compiled_patterns.append(compiled_tuple)
            self.patterns.append(pattern)

        if self._compiler:
            await self._compiler.clear_cache()

        if self.agent_handler:
            from guard_core.core.events.event_types import EVENT_PATTERN_ADDED

            details = f"{'Custom' if custom else 'Default'} pattern added"
            await self._send_pattern_event(
                event_type=EVENT_PATTERN_ADDED,
                ip_address="system",
                action_taken="pattern_added",
                reason=f"{details} to detection system",
                pattern=_redact_pattern_source(pattern, self),
                pattern_type="custom" if custom else "default",
                total_patterns=len(self.custom_patterns)
                if custom
                else len(self.patterns),
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
            pattern=_redact_pattern_source(pattern, self),
            pattern_type="custom" if custom else "default",
            total_patterns=total_patterns,
        )

    @_OnManagerOrDefault
    async def remove_pattern(self, pattern: str, custom: bool = False) -> bool:

        if custom:
            pattern_removed = await self._remove_custom_pattern(pattern)
        else:
            pattern_removed = await self._remove_default_pattern(pattern)

        if pattern_removed:
            await self._clear_pattern_caches(pattern)

        if pattern_removed:
            total_patterns = len(self.custom_patterns) if custom else len(self.patterns)
            await self._send_pattern_removal_event(pattern, custom, total_patterns)

        return pattern_removed

    @_OnManagerOrDefault
    async def get_default_patterns(self) -> list[str]:
        return self.patterns.copy()

    @_OnManagerOrDefault
    async def get_custom_patterns(self) -> list[str]:
        return list(self.custom_patterns)

    @_OnManagerOrDefault
    async def get_all_patterns(self) -> list[str]:
        return self.patterns + list(self.custom_patterns)

    @_OnManagerOrDefault
    async def get_default_compiled_patterns(
        self,
    ) -> list[tuple[re.Pattern, frozenset[str], str]]:
        return self.compiled_patterns.copy()

    @_OnManagerOrDefault
    async def get_custom_compiled_patterns(
        self,
    ) -> list[tuple[re.Pattern, frozenset[str], str]]:
        return list(self.compiled_custom_patterns)

    @_OnManagerOrDefault
    async def get_all_compiled_patterns(
        self,
    ) -> list[tuple[re.Pattern, frozenset[str], str]]:
        return self._without_disabled_rows(self.compiled_patterns) + list(
            self.compiled_custom_patterns
        )

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

            forget_config(cls._instance, "_config")
