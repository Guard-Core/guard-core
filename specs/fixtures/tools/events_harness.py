"""Events harness for the guard-core conformance corpus (kind "events").

Drives the REAL guard_core event surface in-process and captures the FULL
telemetry envelope of every emitted SecurityEvent, the same way
``pipeline_harness`` drives the check pipeline. Two step kinds:

- pipeline drive: ``{"client_ip": ..., "method": ..., "url_path": ...}`` -
  one request through the real check pipeline (``build_default_pipeline``)
  over a middleware whose ``event_bus`` is the REAL ``SecurityEventBus``
  wired to a capturing agent handler.
- handler call: ``{"call": "<op>", ...}`` - a direct handler call
  (ban_ip, detect, pattern add/remove, anomaly monitor samples, dynamic
  rules update, ...) for events emitted outside the pipeline bus.

The corpus expected value is the ordered flat list of captured event
envelopes for the whole case (all steps, in emission order). An envelope is
the captured event's full field set minus the volatile keys in
``EVENT_DROP_KEYS``. Comparison rule: compare only the keys present in each
expected envelope; a runner that cannot observe a field records its
absence, it does not fail.

Injection seams (documented, deterministic):
- ``config.custom_request_check: "corpus_reject_all"`` maps to a real
  deterministic async check function.
- ``drive.guard_route_unresolved: true`` pre-sets the request-state flag
  the middleware resolver sets when route resolution fails.
- ``call: "cloud_stub"`` pins the cloud handler's lookup answers.
- ``call: "ipban_fault"`` makes ``ban_ip`` raise, exercising the
  ban-escalation failure path.
- ``call: "geo_country_stub"`` / ``call: "geo_download_failure"`` pin the
  GeoIP handler's country answers / download failure.

The harness never touches Redis except for the explicitly redis-backed
scenarios (rate-limit NOSCRIPT reload, redis connection events), which use
the dedicated corpus prefix ``EVENTS_REDIS_PREFIX`` and flush it before and
after each redis-backed case.
"""

from __future__ import annotations

import logging
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, cast

from pipeline_harness import (
    CONFIG_KEYS as PIPELINE_CONFIG_KEYS,
)
from pipeline_harness import (
    DEFAULT_STATE,
    ROUTE_KEYS,
    _HarnessResponseFactory,
    _PipelineRequest,
    _StubGeoHandler,
    _StubResponse,
    _StubRouteResolver,
    create_harness_error_response,
)

from guard_core.core.bypass.context import BypassContext
from guard_core.core.bypass.handler import BypassHandler
from guard_core.core.checks.factory import build_default_pipeline
from guard_core.core.events.middleware_events import SecurityEventBus
from guard_core.core.responses.context import ResponseContext
from guard_core.core.responses.factory import ErrorResponseFactory
from guard_core.core.validation.context import ValidationContext
from guard_core.core.validation.validator import RequestValidator
from guard_core.decorators.base import BaseSecurityDecorator
from guard_core.handlers.behavior_handler import BehaviorRule, BehaviorTracker
from guard_core.handlers.cloud_handler import cloud_handler
from guard_core.handlers.dynamic_rule_handler import DynamicRuleManager
from guard_core.handlers.ipban_handler import ip_ban_manager, reset_global_state
from guard_core.handlers.ipinfo_handler import IPInfoManager
from guard_core.handlers.ratelimit_handler import RateLimitManager
from guard_core.handlers.redis_handler import RedisManager
from guard_core.handlers.security_headers_handler import security_headers_manager
from guard_core.handlers.suspatterns_handler import sus_patterns_handler
from guard_core.models import DynamicRules, SecurityConfig
from guard_core.protocols.response_protocol import GuardResponse

EVENTS_REDIS_PREFIX = "guard_core:corpus_evts:"
EVENTS_REDIS_URL = "redis://localhost:6379/0"
EVENTS_REDIS_ERROR_URL = "redis://localhost:59999/0"

# Volatile envelope fields: identity (uuid4), wall-clock timestamps, and
# every timing-derived measurement. Dropped recursively at capture time and
# documented in the suite comparison note.
EVENT_DROP_KEYS = frozenset(
    {
        "idempotency_key",
        "timestamp",
        "response_time",
        "execution_time",
        "execution_time_ms",
    }
)

EVENTS_CONFIG_KEYS = PIPELINE_CONFIG_KEYS + (
    "agent_api_key",
    "auto_ban_duration",
    "enable_agent",
    "block_cloud_providers",
    "custom_request_check",  # harness marker, not a SecurityConfig field
    "detection_anomaly_threshold",
    "detection_min_samples_for_anomaly",
    "detection_slow_pattern_threshold",
    "emergency_mode",
    "emergency_whitelist",
    "enable_dynamic_rules",
    "enable_redis",
    "redis_prefix",
    "redis_url",
    "enforce_https",
    "exclude_paths",
    "route_resolution_strict",
    "trusted_proxies",
)

EVENTS_ROUTE_KEYS = ROUTE_KEYS + (
    "auth_required",
    "block_cloud_providers",
    "max_request_size",
    "require_https",
)


def _normalize(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: _normalize(item)
            for key, item in value.items()
            if key not in EVENT_DROP_KEYS
        }
    if isinstance(value, list):
        return [_normalize(item) for item in value]
    if isinstance(value, float):
        return round(value, 6)
    return value


def event_envelope(event: Any) -> dict[str, Any]:
    """Full envelope of a captured SecurityEvent minus volatile fields."""
    if hasattr(event, "model_dump"):
        data: dict[str, Any] = event.model_dump(mode="json")
    else:
        # Fault-injected engines emit plain namespace objects built over
        # class attributes (monitor/preprocessor events); collect the
        # non-callable public attribute surface.
        data = {}
        for klass in reversed(type(event).__mro__):
            data.update(
                {
                    key: value
                    for key, value in vars(klass).items()
                    if not key.startswith("_") and not callable(value)
                }
            )
        data.update(
            {
                key: value
                for key, value in vars(event).items()
                if not key.startswith("_")
            }
        )
    result: dict[str, Any] = _normalize(data)
    return result


class CapturingAgentHandler:
    """Agent-handler double that records full event envelopes to a sink."""

    def __init__(self, sink: list[dict[str, Any]]) -> None:
        self._sink = sink

    async def send_event(self, event: Any) -> None:
        self._sink.append(event_envelope(event))


class _CorpusRulesAgent(CapturingAgentHandler):
    """Capturing handler that also serves one fixed dynamic-rules payload."""

    def __init__(self, sink: list[dict[str, Any]], rules: DynamicRules) -> None:
        super().__init__(sink)
        self._rules = rules

    async def get_dynamic_rules(self) -> DynamicRules:
        return self._rules


class _EventsResponseFactory(_HarnessResponseFactory):
    """Harness factory plus the modifier passthrough the real middleware
    exposes (custom-request and bypass paths call apply_modifier)."""

    async def apply_modifier(self, response: GuardResponse) -> GuardResponse:
        return response


_EVENTS_RESPONSE_FACTORY = _EventsResponseFactory()


async def corpus_reject_all(request: Any) -> _StubResponse:
    return _StubResponse(418, "corpus rejected")


_CUSTOM_REQUEST_MARKERS = {"corpus_reject_all": corpus_reject_all}


def _make_events_config(case: dict[str, Any], geo: _StubGeoHandler) -> SecurityConfig:
    overrides: dict[str, Any] = dict(DEFAULT_STATE)
    case_config = dict(case.get("config", {}))
    marker = case_config.get("custom_request_check")
    if marker in _CUSTOM_REQUEST_MARKERS:
        case_config["custom_request_check"] = _CUSTOM_REQUEST_MARKERS[marker]
    overrides.update(
        {key: value for key, value in case_config.items() if key in EVENTS_CONFIG_KEYS}
    )
    if overrides.get("blocked_countries") or overrides.get("whitelist_countries"):
        overrides["geo_ip_handler"] = geo
    if "endpoint_rate_limits" in overrides:
        overrides["endpoint_rate_limits"] = {
            path: tuple(limit_window)
            for path, limit_window in overrides["endpoint_rate_limits"].items()
        }
    return SecurityConfig(**overrides)


_SET_VALUED_ROUTE_KEYS = {
    "bypassed_checks",
    "excluded_detection_headers",
    "excluded_detection_params",
    "excluded_detection_body_fields",
    "block_cloud_providers",
}


def _build_events_route(path: str, overrides: dict[str, Any]) -> Any:
    """Route config from JSON overrides under the events route-key
    allow-list (pipeline ROUTE_KEYS plus the decorator knobs the events
    scenarios need)."""
    from guard_core.decorators.route_config import RouteConfig, RouteConfigRevision

    route_config = RouteConfig(RouteConfigRevision())
    for key, value in overrides.items():
        if key not in EVENTS_ROUTE_KEYS:
            continue
        if key in _SET_VALUED_ROUTE_KEYS:
            value = set(value)
        setattr(route_config, key, value)
    return route_config


class _EventsMiddleware:
    """Minimal middleware surface carrying the real config and the REAL
    SecurityEventBus wired to the capturing agent handler."""

    def __init__(
        self,
        config: SecurityConfig,
        rate_limit_handler: RateLimitManager,
        geo_ip_handler: Any,
        routes: dict[str, Any],
        event_bus: SecurityEventBus,
        agent_handler: CapturingAgentHandler,
    ) -> None:
        self.config = config
        self.logger = logging.getLogger("corpus.events_harness")
        self.rate_limit_handler = rate_limit_handler
        self.geo_ip_handler = geo_ip_handler
        self.event_bus = event_bus
        self.agent_handler = agent_handler
        self.route_resolver = _StubRouteResolver(routes)
        self.suspicious_request_counts: dict[str, dict[str, int]] = {}
        self.last_cloud_ip_refresh = 0

    @property
    def response_factory(self) -> _EventsResponseFactory:
        return _EVENTS_RESPONSE_FACTORY

    @property
    def guard_response_factory(self) -> _EventsResponseFactory:
        return _EVENTS_RESPONSE_FACTORY

    async def create_error_response(
        self, status_code: int, default_message: str
    ) -> _StubResponse:
        return await create_harness_error_response(
            self.config, status_code, default_message
        )

    async def refresh_cloud_ip_ranges(self) -> None:
        return None


def _rule_from_payload(payload: dict[str, Any]) -> BehaviorRule:
    return BehaviorRule(
        rule_type=payload["rule_type"],
        threshold=payload["threshold"],
        window=payload.get("window", 3600),
        pattern=payload.get("pattern"),
        action=payload.get("action", "log"),
    )


def _rules_from_payload(payload: dict[str, Any]) -> DynamicRules:
    return DynamicRules(
        rule_id=payload["rule_id"],
        version=payload["version"],
        timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
        emergency_mode=payload.get("emergency_mode", False),
        emergency_whitelist=payload.get("emergency_whitelist", []),
    )


class _NullMetrics:
    async def collect_request_metrics(self, *args: Any, **kwargs: Any) -> None:
        return None


class EventsCase:
    """One events case: fresh engine state, sequential steps."""

    def __init__(self, case: dict[str, Any]) -> None:
        self.case = case
        self.sink: list[dict[str, Any]] = []
        self.agent = CapturingAgentHandler(self.sink)
        self.geo = _StubGeoHandler(case.get("geo_countries", {}))
        self.config = _make_events_config(case, self.geo)
        self.routes = {
            path: _build_events_route(path, overrides)
            for path, overrides in case.get("routes", {}).items()
        }
        self.event_bus = SecurityEventBus(
            agent_handler=self.agent,
            config=self.config,
            geo_ip_handler=self.geo,
        )
        self.rate_limit_handler = RateLimitManager(self.config)
        self.middleware = _EventsMiddleware(
            self.config,
            self.rate_limit_handler,
            self.geo,
            self.routes,
            self.event_bus,
            self.agent,
        )
        self.pipeline = build_default_pipeline(cast(Any, self.middleware))

    async def prepare(self) -> None:
        await reset_global_state()
        security_headers_manager.headers_cache.clear()
        await self.rate_limit_handler.reset()
        await self.rate_limit_handler.initialize_agent(self.agent)

    async def _drive(self, step: dict[str, Any]) -> None:
        request = _PipelineRequest(step)
        if step.get("guard_route_unresolved"):
            request.state.guard_route_unresolved = True
        if step.get("drop_cached_client_ip"):
            # Make extract_client_ip resolve from the peer/headers chain
            # (the real adapters do not pre-cache state.client_ip).
            del request.state.client_ip
        await self.pipeline.execute(cast(Any, request))

    async def _call(self, step: dict[str, Any]) -> None:
        op = step["call"]
        handler = getattr(self, f"_call_{op}", None)
        if handler is None:
            raise ValueError(f"unknown events harness call {op!r}")
        await handler(step)

    # ---- handler calls (one per event emitted outside the bus) ----

    async def _call_ban_ip(self, step: dict[str, Any]) -> None:
        await ip_ban_manager.initialize_agent(self.agent)
        await ip_ban_manager.ban_ip(
            step["ip"], step.get("duration", 3600), step.get("reason", "corpus_ban")
        )

    async def _call_unban_ip(self, step: dict[str, Any]) -> None:
        await ip_ban_manager.unban_ip(step["ip"])

    async def _call_ipban_fault(self, step: dict[str, Any]) -> None:
        async def _raising_ban(ip: str, duration: int, reason: str) -> bool:
            raise RuntimeError("corpus injected ban failure")

        ip_ban_manager.ban_ip = _raising_ban  # type: ignore[method-assign,assignment]

    async def _call_detect(self, step: dict[str, Any]) -> None:
        await sus_patterns_handler.initialize_agent(self.agent)
        await sus_patterns_handler.detect(
            step["content"], step.get("ip", "203.0.113.7"), step.get("context", "body")
        )

    async def _call_add_pattern(self, step: dict[str, Any]) -> None:
        await sus_patterns_handler.initialize_agent(self.agent)
        sus_patterns_handler.custom_patterns.clear()
        sus_patterns_handler.compiled_custom_patterns.clear()
        added = await sus_patterns_handler.add_pattern(step["pattern"], custom=True)
        if not added:
            raise RuntimeError(f"corpus pattern rejected: {step['pattern']!r}")

    async def _call_remove_pattern(self, step: dict[str, Any]) -> None:
        import re

        await sus_patterns_handler.initialize_agent(self.agent)
        pattern = step["pattern"]
        # Seed the registry directly (no agent wired) so the case pins the
        # removal event alone; totals stay deterministic (1 -> 0).
        sus_patterns_handler.custom_patterns.clear()
        sus_patterns_handler.compiled_custom_patterns.clear()
        sus_patterns_handler.custom_patterns.add(pattern)
        sus_patterns_handler.compiled_custom_patterns.add(
            (re.compile(pattern, re.IGNORECASE), frozenset(), "custom")
        )
        removed = await sus_patterns_handler.remove_pattern(pattern, custom=True)
        if not removed:
            raise RuntimeError(f"corpus pattern not removed: {pattern!r}")

    async def _call_monitor_anomaly(self, step: dict[str, Any]) -> None:
        from guard_core.detection_engine.monitor import PerformanceMonitor

        monitor = PerformanceMonitor(
            anomaly_threshold=step.get("anomaly_threshold", 3.0),
            slow_pattern_threshold=step.get("slow_pattern_threshold", 0.1),
            min_samples_for_anomaly=step.get("min_samples_for_anomaly", 10),
        )
        for sample in step.get("samples", []):
            await monitor.record_metric(
                sample["pattern"],
                sample["execution_time"],
                sample.get("content_length", 128),
                sample.get("matched", False),
                timeout=sample.get("timeout", False),
                agent_handler=self.agent,
            )

    async def _call_monitor_callback_fault(self, step: dict[str, Any]) -> None:
        from guard_core.detection_engine.monitor import PerformanceMonitor

        def _raising_callback(anomaly: dict[str, Any]) -> None:
            raise RuntimeError("corpus injected callback failure")

        monitor = PerformanceMonitor(min_samples_for_anomaly=10)
        monitor.register_anomaly_callback(_raising_callback)
        await monitor.record_metric(
            step["pattern"],
            step.get("execution_time", 0.5),
            128,
            False,
            agent_handler=self.agent,
        )

    async def _call_dynamic_rules(self, step: dict[str, Any]) -> None:
        DynamicRuleManager._instance = None  # noqa: SLF001 - corpus reset
        manager = DynamicRuleManager(self.config)
        rules = _rules_from_payload(step["rules"])
        manager.agent_handler = _CorpusRulesAgent(self.sink, rules)
        try:
            await manager.update_rules()
        finally:
            DynamicRuleManager._instance = None  # noqa: SLF001 - corpus reset

    async def _call_decorator_event(self, step: dict[str, Any]) -> None:
        request = _PipelineRequest(step)
        decorator = BaseSecurityDecorator(self.config)
        await decorator.initialize_agent(self.agent, self.geo)
        sender = getattr(decorator, step["send"])
        await sender(cast(Any, request), **step.get("kwargs", {}))

    async def _call_behavior_action(self, step: dict[str, Any]) -> None:
        tracker = BehaviorTracker(self.config)
        await tracker.initialize_agent(self.agent)
        rule = _rule_from_payload(step["rule"])
        await tracker.apply_action(
            rule,
            step["ip"],
            step.get("endpoint_id", "corpus.endpoint"),
            step.get("details", "Usage threshold exceeded: 1 calls in 60s"),
        )

    async def _call_csp_report(self, step: dict[str, Any]) -> None:
        await security_headers_manager.initialize_agent(self.agent)
        valid = await security_headers_manager.validate_csp_report(step["report"])
        if not valid:
            raise RuntimeError("corpus CSP report was rejected as invalid")

    async def _call_headers_applied(self, step: dict[str, Any]) -> None:
        await security_headers_manager.initialize_agent(self.agent)
        security_headers_manager.headers_cache.clear()
        await security_headers_manager.get_headers(step["path"], config=self.config)

    async def _call_geo_country_stub(self, step: dict[str, Any]) -> None:
        handler = IPInfoManager("corpus-token")
        saved = (handler.get_country, handler.agent_handler)
        handler.agent_handler = self.agent  # type: ignore[assignment]
        country = step.get("country", "CN")
        handler.get_country = lambda ip: country  # type: ignore[method-assign]
        try:
            await handler.check_country_access(
                step["ip"], step.get("blocked_countries", ["CN"])
            )
        finally:
            handler.get_country, handler.agent_handler = saved  # type: ignore[method-assign]

    async def _call_geo_download_failure(self, step: dict[str, Any]) -> None:
        handler = IPInfoManager("corpus-token")
        saved = (
            handler.agent_handler,
            handler.db_path,
            handler.reader,
            handler._initialization_attempted,
        )
        handler.agent_handler = self.agent  # type: ignore[assignment]
        scratch = Path("/tmp/guard_core_corpus_geo_scratch")
        handler.db_path = scratch / "corpus.mmdb"
        handler._initialization_attempted = False
        handler.reader = None

        async def _failing_download() -> None:
            raise RuntimeError("corpus injected download failure")

        original_download = handler._download_database
        handler._download_database = _failing_download  # type: ignore[method-assign]
        try:
            await handler.initialize()
        finally:
            handler._download_database = original_download  # type: ignore[method-assign]
            (
                handler.agent_handler,
                handler.db_path,
                handler.reader,
                handler._initialization_attempted,
            ) = saved
            shutil.rmtree(scratch, ignore_errors=True)

    async def _call_redis_connect(self, step: dict[str, Any]) -> None:
        await _reset_redis_manager()
        config = self.config.model_copy(
            update={
                "enable_redis": True,
                "redis_url": EVENTS_REDIS_URL,
                "redis_prefix": EVENTS_REDIS_PREFIX,
            }
        )
        manager = RedisManager(config)
        await manager.initialize_agent(self.agent)
        try:
            await manager.initialize()
        finally:
            manager._closed = True
            await manager._discard_client()

    async def _call_redis_connect_error(self, step: dict[str, Any]) -> None:
        from guard_core.exceptions import GuardRedisError

        await _reset_redis_manager()
        config = self.config.model_copy(
            update={
                "enable_redis": True,
                "redis_url": EVENTS_REDIS_ERROR_URL,
                "redis_prefix": EVENTS_REDIS_PREFIX,
            }
        )
        manager = RedisManager(config)
        await manager.initialize_agent(self.agent)
        try:
            await manager.initialize()
        except GuardRedisError:
            return
        raise RuntimeError("corpus expected redis connection failure")

    async def _call_rate_limit_script_reload(self, step: dict[str, Any]) -> None:
        await _flush_events_prefix()
        await _reset_redis_manager()
        config = self.config.model_copy(
            update={
                "enable_redis": True,
                "redis_url": EVENTS_REDIS_URL,
                "redis_prefix": EVENTS_REDIS_PREFIX,
                "enable_rate_limiting": True,
            }
        )
        redis_manager = RedisManager(config)
        await redis_manager.initialize()
        manager = RateLimitManager(config)
        await manager.reset()
        await manager.initialize_agent(self.agent)
        manager.redis_handler = redis_manager
        manager.rate_limit_script_sha = "f" * 40
        request = _PipelineRequest(step)
        try:
            await manager.check_rate_limit(
                cast(Any, request),
                step["client_ip"],
                self.middleware.create_error_response,
            )
        finally:
            manager.rate_limit_script_sha = None
            redis_manager._closed = True
            await redis_manager._discard_client()
            await _flush_events_prefix()

    async def _call_bypass(self, step: dict[str, Any]) -> None:
        validator = RequestValidator(
            ValidationContext(
                config=self.config,
                logger=self.middleware.logger,
                event_bus=cast(Any, self.event_bus),
            )
        )
        error_factory = ErrorResponseFactory(
            ResponseContext(
                config=self.config,
                logger=self.middleware.logger,
                metrics_collector=cast(Any, _NullMetrics()),
                agent_handler=None,
                response_factory=cast(Any, _EVENTS_RESPONSE_FACTORY),
            )
        )
        context = BypassContext(
            config=self.config,
            logger=self.middleware.logger,
            event_bus=cast(Any, self.event_bus),
            route_resolver=cast(Any, self.middleware.route_resolver),
            response_factory=cast(Any, error_factory),
            validator=validator,
        )
        handler = BypassHandler(context)

        async def _call_next(request: Any) -> GuardResponse:
            return _StubResponse(200, "passthrough")

        route_config = self.routes.get(step["url_path"])
        request = _PipelineRequest(step)
        await handler.handle_security_bypass(
            cast(Any, request), _call_next, route_config
        )

    async def _call_path_excluded(self, step: dict[str, Any]) -> None:
        validator = RequestValidator(
            ValidationContext(
                config=self.config,
                logger=self.middleware.logger,
                event_bus=cast(Any, self.event_bus),
            )
        )
        request = _PipelineRequest(step)
        excluded = await validator.is_path_excluded(cast(Any, request))
        if not excluded:
            raise RuntimeError("corpus expected path exclusion")


# ---- redis helpers for the redis-backed scenarios ----


async def _flush_events_prefix() -> None:
    import redis.asyncio as aredis

    client = aredis.from_url(EVENTS_REDIS_URL, decode_responses=True)
    try:
        keys = await client.keys(f"{EVENTS_REDIS_PREFIX}*")
        if keys:
            await client.delete(*keys)
    finally:
        await client.aclose()


async def _reset_redis_manager() -> None:
    RedisManager._instance = None  # noqa: SLF001 - corpus reset


async def run_events_case(case: dict[str, Any]) -> list[dict[str, Any]]:
    """Drive the case; returns the ordered flat list of event envelopes."""
    harness = EventsCase(case)
    # The cloud and ban handlers are process-global singletons; pin and
    # restore their patched members around the whole case.
    saved_cloud = {
        attr: getattr(cloud_handler, attr, None)
        for attr in ("agent_handler", "is_cloud_ip", "get_cloud_provider_details")
    }
    try:
        await harness.prepare()
        for step in case.get("drives", []):
            if step.get("call") == "cloud_stub":
                provider = step.get("provider", "aws")
                network = step.get("network", "203.0.113.0/24")
                cloud_handler.agent_handler = harness.agent  # type: ignore[assignment]
                cloud_handler.is_cloud_ip = (  # type: ignore[method-assign]
                    lambda ip, providers, _always=True: _always  # type: ignore[misc,assignment]
                )
                cloud_handler.get_cloud_provider_details = (  # type: ignore[method-assign]
                    lambda ip, providers, _p=provider, _n=network: (_p, _n)  # type: ignore[misc,assignment]
                )
                continue
            if "call" in step:
                await harness._call(step)
            else:
                await harness._drive(step)
    finally:
        for attr, value in saved_cloud.items():
            setattr(cloud_handler, attr, value)
        ip_ban_manager.__dict__.pop("ban_ip", None)
        # Detach every singleton agent handler this case may have wired:
        # a stale handler would append later suite operations (e.g. the
        # redis interop pattern write) into THIS case's expectation list.
        sus_patterns_handler.agent_handler = None
        ip_ban_manager.agent_handler = None
        security_headers_manager.agent_handler = None
        rate_limit_singleton = RateLimitManager._instance
        if rate_limit_singleton is not None:
            rate_limit_singleton.agent_handler = None
    return harness.sink
