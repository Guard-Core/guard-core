"""Reference pipeline harness for the guard-core conformance corpus.

Drives the REAL guard_core check pipeline (``build_default_pipeline``) and the
REAL response factory in-process, over a minimal middleware stub, the same way
``interop/py_participant.py`` does for the cross-engine interop harness. The
corpus expected values are the observations of this harness on the live
engine; a port's conformance runner replays the same case through its own
engine and compares per the rules in ``specs/fixtures/README.md``.

The harness never touches Redis: rate limiting runs on the reference's
in-memory window fallback (``enable_redis=False``), bans live in the
IPBanManager's local TTLCache, and every case starts from a clean global
state (rate-limit singleton reset, ban cache reset, fresh middleware).

Case schema (kind "pipeline"):

    {
      "id": "...",
      "config": {<SecurityConfig overrides, JSON-safe subset>},
      "geo_countries": {"<ip>": "<ISO code>", ...}   # stub geo handler table
      "routes": [ {"path": "/api/x", <RouteConfig overrides>}, ... ],
      "drives": [
        {"client_ip": "...", "method": "GET", "url_path": "/api",
         "headers": {...}, "body": "...", "stage": "pipeline"}
      ],
      "expected": [ <observation>, ... ]   # one per drive, same order
    }

An observation is the harness record of one drive:

    {"status": 403|400|429|null, "body": "Forbidden", "headers": {...},
     "is_exempt": false, "is_whitelisted": false,
     "events": [["ip_blocked", "request_blocked"], ...],
     "on_block": [{"check_name": "ip_security", "status_code": 403, ...}]}

Only the keys the generator recorded are compared; runners MUST ignore
observation keys absent from the expected record (see README comparison
rules).
"""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable, Mapping
from typing import TypeVar, overload

from fixture_types import (
    ConfigCarrier,
    JsonObject,
    PipelineCaseInput,
    RequestStep,
)
from run_fixtures import STAGED_FIELDS

from guard_core.core.behavioral.context import BehavioralContext
from guard_core.core.behavioral.processor import BehavioralProcessor
from guard_core.core.checks.factory import build_default_pipeline
from guard_core.core.checks.implementations import emergency_mode, suspicious_activity
from guard_core.core.events.event_types import (
    EVENT_DECORATOR_VIOLATION,
    EVENT_HTTPS_ENFORCED,
)
from guard_core.core.events.metrics import MetricsCollector
from guard_core.core.events.middleware_events import SecurityEventBus
from guard_core.core.responses import reads_response_body
from guard_core.core.responses.context import ResponseContext
from guard_core.core.responses.factory import ErrorResponseFactory
from guard_core.core.routing.context import RoutingContext
from guard_core.core.routing.resolver import RouteConfigResolver
from guard_core.decorators.route_config import RouteConfig, RouteConfigRevision
from guard_core.exceptions import ResponseBodyUnavailableError
from guard_core.handlers.behavior_handler import BehaviorTracker
from guard_core.handlers.ipban_handler import reset_global_state
from guard_core.handlers.ratelimit_handler import RateLimitManager
from guard_core.models import SecurityConfig
from guard_core.protocols.agent_protocol import AgentHandlerProtocol
from guard_core.protocols.redis_protocol import RedisHandlerProtocol
from guard_core.protocols.request_protocol import GuardRequest
from guard_core.protocols.response_protocol import GuardResponse

_DefaultT = TypeVar("_DefaultT")
_ResponseModifier = Callable[[GuardResponse], Awaitable[GuardResponse]]

# JSON config keys applied verbatim as SecurityConfig constructor kwargs.
# Everything a pipeline case needs is on this allow-list; anything else in
# the case config is harness-level (geo_countries, routes).
CONFIG_KEYS = (
    "whitelist",
    "whitelist_access_only",
    "blacklist",
    "exempt_ips",
    "blocked_user_agents",
    "blocked_countries",
    "whitelist_countries",
    "rate_limit",
    "rate_limit_window",
    "endpoint_rate_limits",
    "passive_mode",
    "enforce_https",
    "custom_error_responses",
    "security_headers",
    "enable_cors",
    "cors_allow_origins",
    "cors_allow_methods",
    "cors_allow_headers",
    "cors_allow_credentials",
    "global_behavior_rules",
    "behavior_scan_response_body",
    "custom_response_modifier_max_body_bytes",
    "enable_rate_limiting",
    "enable_penetration_detection",
    "enable_ip_banning",
    "enable_rate_limit_auto_ban",
    "auto_ban_threshold",
    "excluded_detection_params",
)

ROUTE_KEYS = (
    "rate_limit",
    "rate_limit_window",
    "ip_whitelist",
    "ip_blacklist",
    "blocked_countries",
    "whitelist_countries",
    "blocked_user_agents",
    "bypassed_checks",
    "enable_suspicious_detection",
    "excluded_detection_headers",
    "excluded_detection_params",
    "excluded_detection_body_fields",
    "geo_rate_limits",
    "max_request_size",
    "allowed_content_types",
    "require_https",
)

DEFAULT_STATE = {
    **STAGED_FIELDS,
    # Ban-free, redis-free determinism knobs; a case config may raise
    # auto_ban_threshold but never lower it below this floor in the corpus.
    "enable_rate_limit_auto_ban": False,
    "enable_ip_banning": False,
    "auto_ban_threshold": 1000,
    "log_suspicious_level": "ERROR",
    "log_request_level": "ERROR",
}


class _StubResponse(GuardResponse):
    """Explicit GuardResponse implementation over in-memory state."""

    def __init__(self, status_code: int, default_message: str = "") -> None:
        self._status_code = status_code
        self._body = default_message.encode()
        self._headers: dict[str, str] = {}

    @property
    def status_code(self) -> int:
        return self._status_code

    @property
    def headers(self) -> dict[str, str]:
        return self._headers

    @property
    def body(self) -> bytes | None:
        return self._body

    @body.setter
    def body(self, value: bytes | None) -> None:
        self._body = value if value is not None else b""


class _StubBodyResponse(_StubResponse):
    """A response with a bounded reader that counts its reads (modifier cases)."""

    def __init__(
        self,
        body: bytes,
        headers: dict[str, str],
        status_code: int,
    ) -> None:
        super().__init__(status_code)
        self._body = body
        self._headers.update(headers)
        self.prefix_reads = 0

    async def read_body_prefix(self, max_bytes: int) -> bytes:
        self.prefix_reads += 1
        return (self._body or b"")[:max_bytes]


class _ModifierCalls:
    """Named modifiers a case can install; counts the calls of the last one."""

    def __init__(self) -> None:
        self.count = 0

    def header_only(self) -> _ResponseModifier:
        async def modifier(response: GuardResponse) -> GuardResponse:
            self.count += 1
            response.headers["X-Modifier"] = "header-only"
            return response

        return modifier

    def reads_body(self, marked: bool) -> _ResponseModifier:
        async def modifier(response: GuardResponse) -> GuardResponse:
            self.count += 1
            response.headers[f"X-Call-{self.count}"] = "1"
            try:
                response.headers["X-Body"] = (response.body or b"").decode()
            except ResponseBodyUnavailableError:
                response.headers["X-Body"] = "unavailable"
            return response

        return reads_response_body(modifier) if marked else modifier

    def named(self, name: str) -> _ResponseModifier:
        if name == "header_only":
            return self.header_only()
        return self.reads_body(marked=name == "reads_body_marked")


class _RecordingEventBus(SecurityEventBus):
    """Captures (event_type, action_taken) pairs in emission order."""

    def __init__(self, config: SecurityConfig) -> None:
        super().__init__(agent_handler=None, config=config)
        self.events: list[tuple[str, str]] = []

    async def send_middleware_event(
        self,
        event_type: str,
        request: GuardRequest,
        action_taken: str,
        reason: str,
        **kwargs: object,
    ) -> None:
        self.events.append((str(event_type), str(action_taken)))

    async def send_https_violation_event(
        self, request: GuardRequest, route_config: RouteConfig | None
    ) -> None:
        route_demanded = bool(route_config and route_config.require_https)
        event_type = (
            EVENT_DECORATOR_VIOLATION if route_demanded else EVENT_HTTPS_ENFORCED
        )
        self.events.append((event_type, "https_redirect"))


class _RecordingOnBlock:
    """Captures the on_block hook payloads (the observable subset)."""

    PAYLOAD_KEYS = (
        "check_name",
        "reason",
        "trigger_info",
        "passive_mode",
        "client_ip",
        "path",
        "method",
        "status_code",
    )

    def __init__(self) -> None:
        self.payloads: list[JsonObject] = []

    def __call__(self, request: GuardRequest, payload: JsonObject) -> None:
        self.payloads.append({key: payload.get(key) for key in self.PAYLOAD_KEYS})


class _StubGeoHandler:
    """Answers from a fixed ip -> ISO country table, like the reference
    GeoIPHandler.get_country returning None on a miss."""

    def __init__(self, table: dict[str, str]) -> None:
        self.table = table

    @property
    def is_initialized(self) -> bool:
        return True

    def get_country(self, ip: str) -> str | None:
        return self.table.get(ip)

    async def initialize(self) -> None:
        return None

    async def initialize_redis(self, redis_handler: RedisHandlerProtocol) -> None:
        return None

    async def initialize_agent(self, agent_handler: AgentHandlerProtocol) -> None:
        return None

    async def refresh(self) -> None:
        return None

    async def close(self) -> None:
        return None


class _StubRouteResolver(RouteConfigResolver):
    """Exact-path route table over real RouteConfig objects."""

    def __init__(
        self,
        config: SecurityConfig,
        logger: logging.Logger,
        routes: dict[str, RouteConfig],
    ) -> None:
        super().__init__(RoutingContext(config=config, logger=logger))
        self.routes = routes

    def get_route_config(self, request: GuardRequest) -> RouteConfig | None:
        return self.routes.get(request.url_path)

    def should_bypass_check(
        self, check_name: str, route_config: RouteConfig | None
    ) -> bool:
        if route_config is None:
            return False
        return check_name in route_config.bypassed_checks

    def get_cloud_providers_to_check(
        self, route_config: RouteConfig | None
    ) -> list[str] | None:
        if route_config is None or not route_config.block_cloud_providers:
            return None
        return list(route_config.block_cloud_providers)


class _HarnessDecorator:
    def __init__(self, config: SecurityConfig, routes: dict[str, RouteConfig]) -> None:
        self._route_configs: dict[str, RouteConfig] = dict(routes)
        self.route_config_revision = RouteConfigRevision()
        self.behavior_tracker = BehaviorTracker(config)

    async def initialize_behavior_tracking(
        self, redis_handler: RedisHandlerProtocol | None = None
    ) -> None:
        return None


class _HarnessMiddleware:
    """Minimal GuardMiddlewareProtocol surface carrying the real config."""

    def __init__(
        self,
        config: SecurityConfig,
        rate_limit_handler: RateLimitManager,
        geo_ip_handler: _StubGeoHandler,
        routes: dict[str, RouteConfig],
        event_bus: _RecordingEventBus,
        on_block: _RecordingOnBlock,
    ) -> None:
        self.config = config
        self.logger = logging.getLogger("corpus.harness")
        self.rate_limit_handler = rate_limit_handler
        self.geo_ip_handler = geo_ip_handler
        self.event_bus = event_bus
        self.route_resolver = _StubRouteResolver(config, self.logger, routes)
        self.guard_decorator = _HarnessDecorator(config, routes)
        self.suspicious_request_counts: dict[str, dict[str, int]] = {}
        self.last_cloud_ip_refresh = 0
        self.agent_handler = None
        self.on_block_recorder = on_block

    @property
    def response_factory(self) -> _HarnessResponseFactory:
        return _HARNESS_RESPONSE_FACTORY

    @property
    def guard_response_factory(self) -> _HarnessResponseFactory:
        return _HARNESS_RESPONSE_FACTORY

    async def create_error_response(
        self, status_code: int, default_message: str
    ) -> _StubResponse:
        return await create_harness_error_response(
            self.config, status_code, default_message
        )

    async def refresh_cloud_ip_ranges(self) -> None:
        return None


class _HarnessResponseFactory:
    """ResponseFactory protocol over _StubResponse (message becomes body)."""

    def create_response(
        self,
        content: object,
        status_code: int,
        headers: Mapping[str, str] | None = None,
    ) -> _StubResponse:
        body = content if isinstance(content, (bytes, str)) else str(content)
        return _StubResponse(status_code, body if isinstance(body, str) else "")

    async def create_https_redirect(self, request: GuardRequest) -> _StubResponse:
        status_code = 301 if request.method.upper() in ("GET", "HEAD") else 308
        return self.create_redirect_response(
            str(request.url_replace_scheme("https")), status_code
        )

    def create_redirect_response(self, url: object, status_code: int) -> _StubResponse:
        response = _StubResponse(status_code)
        response.headers["Location"] = str(url)
        return response


_HARNESS_RESPONSE_FACTORY = _HarnessResponseFactory()


async def create_harness_error_response(
    config: SecurityConfig, status_code: int, default_message: str
) -> _StubResponse:
    """The reference ErrorResponseFactory.create_error_response path for a
    modifier-free deployment: custom message, security headers, no modifier."""
    from guard_core.handlers.security_headers_handler import (
        security_headers_manager,
    )

    custom_message = config.custom_error_responses.get(status_code, default_message)
    response: _StubResponse = _HARNESS_RESPONSE_FACTORY.create_response(
        custom_message, status_code
    )
    headers_config = config.security_headers
    if headers_config and headers_config.get("enabled", True):
        security_headers = await security_headers_manager.get_headers(
            None, config=config
        )
        for header_name, header_value in security_headers.items():
            response.headers[header_name] = header_value
    return response


def _build_route(path: str, overrides: JsonObject) -> RouteConfig:
    route_config = RouteConfig(RouteConfigRevision())
    for key, value in overrides.items():
        if key in ROUTE_KEYS:
            route_value: object = value
            if key in {
                "bypassed_checks",
                "excluded_detection_headers",
                "excluded_detection_params",
                "excluded_detection_body_fields",
            }:
                assert isinstance(value, list)
                route_value = set(value)
            setattr(route_config, key, route_value)
    return route_config


def endpoint_limit_windows(limits: JsonObject) -> dict[str, tuple[int, int]]:
    windows: dict[str, tuple[int, int]] = {}
    for path, limit_window in limits.items():
        assert isinstance(limit_window, list)
        limit, window = limit_window
        assert isinstance(limit, int)
        assert isinstance(window, int)
        windows[path] = (limit, window)
    return windows


def _make_config(case: ConfigCarrier, geo: _StubGeoHandler) -> SecurityConfig:
    overrides: dict[str, object] = dict(DEFAULT_STATE)
    overrides.update(
        {
            key: value
            for key, value in case.get("config", {}).items()
            if key in CONFIG_KEYS
        }
    )
    if overrides.get("blocked_countries") or overrides.get("whitelist_countries"):
        overrides["geo_ip_handler"] = geo
    limits = overrides.get("endpoint_rate_limits")
    if isinstance(limits, dict):
        overrides["endpoint_rate_limits"] = endpoint_limit_windows(limits)
    return SecurityConfig.model_validate(overrides)


class _CaseInsensitiveHeaders(dict[str, str]):
    """Header map like the framework adapters': lookup is case-insensitive."""

    def __init__(self, items: dict[str, str]) -> None:
        super().__init__({key.lower(): value for key, value in items.items()})

    @overload
    def get(self, key: str, default: None = None, /) -> str | None: ...

    @overload
    def get(self, key: str, default: str, /) -> str: ...

    @overload
    def get(self, key: str, default: _DefaultT, /) -> str | _DefaultT: ...

    def get(self, key: str, default: object = None, /) -> object:
        return super().get(key.lower(), default)

    def __getitem__(self, key: str) -> str:
        return super().__getitem__(key.lower())

    def __contains__(self, key: object) -> bool:
        return super().__contains__(str(key).lower())


class _PipelineRequest:
    def __init__(self, drive: RequestStep) -> None:
        self.query_params: dict[str, str] = dict(drive.get("query_params", {}))
        self.headers = _CaseInsensitiveHeaders(drive.get("headers", {}))
        self._body: bytes = drive.get("body", "").encode()
        if (
            self._body
            and "content-length" not in self.headers
            and "transfer-encoding" not in self.headers
            and not drive.get("omit_content_length", False)
        ):
            self.headers["content-length"] = str(len(self._body))
        self.url_path = drive.get("url_path", "/api")
        self.url_full = f"http://example.com{self.url_path}"
        self.url_scheme = "http"
        self.method = drive.get("method", "GET")
        self.client_host = drive["client_ip"]
        self.state = type("State", (), {})()
        self.state.client_ip = self.client_host

    async def body(self) -> bytes:
        return self._body

    @property
    def scope(self) -> dict[str, object]:
        return {}

    def url_replace_scheme(self, scheme: str) -> str:
        # Plain string, matching the display redaction path: the engine
        # passes the replaced-scheme URL straight into urlsplit-based
        # redaction, which requires a str.
        return f"{scheme}://example.com"


class HarnessCase:
    """One pipeline case: fresh engine state, sequential drives."""

    def __init__(self, case: PipelineCaseInput) -> None:
        self.case = case
        self.geo = _StubGeoHandler(case.get("geo_countries", {}))
        self.on_block = _RecordingOnBlock()
        self.config = _make_config(case, self.geo)
        self.config.on_block = self.on_block
        self.routes = {
            path: _build_route(path, overrides)
            for path, overrides in case.get("routes", {}).items()
        }
        self.event_bus = _RecordingEventBus(self.config)
        self.rate_limit_handler = RateLimitManager(self.config)
        self.middleware = _HarnessMiddleware(
            self.config,
            self.rate_limit_handler,
            self.geo,
            self.routes,
            self.event_bus,
            self.on_block,
        )
        self.pipeline = build_default_pipeline(self.middleware)
        self.error_factory = ErrorResponseFactory(
            ResponseContext(
                config=self.config,
                logger=self.middleware.logger,
                metrics_collector=_NullMetrics(self.config),
                agent_handler=None,
                response_factory=_HARNESS_RESPONSE_FACTORY,
            )
        )
        self.behavior_processor = BehavioralProcessor(
            BehavioralContext(
                config=self.config,
                logger=self.middleware.logger,
                event_bus=self.event_bus,
                guard_decorator=None,
                behavior_tracker=self.middleware.guard_decorator.behavior_tracker,
                middleware=self.middleware,
            )
        )


class _NullMetrics(MetricsCollector):
    def __init__(self, config: SecurityConfig) -> None:
        super().__init__(agent_handler=None, config=config)

    async def collect_request_metrics(
        self, request: GuardRequest, response_time: float, status_code: int
    ) -> None:
        return None


def replace_member(target: object, name: str, value: object) -> None:
    """Swap one member of a process-global singleton or module for a corpus stub."""
    setattr(target, name, value)


def reset_check_samplers() -> None:
    """Forget which emergency and detection-disabled lines were already sampled.

    The checks sample those lines once per client per window in module state, so
    without this a second generation in the same process drops the line the
    first one recorded.
    """
    emergency_mode._emergency_samples.clear()
    suspicious_activity._disabled_detection_samples.clear()


async def run_case(case: PipelineCaseInput) -> list[JsonObject]:
    """Drive the case; returns the observed records (one per drive)."""
    await reset_global_state()
    reset_check_samplers()
    # The headers manager caches per-config entries keyed by id(config); id
    # values are recycled across cases, so clear the cache to keep every
    # case's headers derived from its own config only.
    from guard_core.handlers.security_headers_handler import (
        security_headers_manager,
    )

    security_headers_manager.headers_cache.clear()
    harness = HarnessCase(case)
    # Clear the manager's window state so every case starts from a clean slate.
    await harness.rate_limit_handler.reset()
    observed: list[JsonObject] = []
    for drive in case["drives"]:
        request = _PipelineRequest(drive)
        record: JsonObject = {}
        harness.event_bus.events.clear()
        harness.on_block.payloads.clear()
        stage = drive.get("stage", "pipeline")
        if stage == "pipeline":
            response = await harness.pipeline.execute(request)
        elif stage == "process_response":
            response = _HARNESS_RESPONSE_FACTORY.create_response(
                drive.get("response_body", "ok"),
                drive.get("response_status", 200),
            )
            modifier_calls = _ModifierCalls()
            if "modifier" in drive:
                declared = drive.get("response_declared_length")
                response = _StubBodyResponse(
                    drive.get("response_body", "ok").encode(),
                    {
                        **drive.get("response_headers", {}),
                        **(
                            {"Content-Length": str(declared)}
                            if declared is not None
                            else {}
                        ),
                    },
                    drive.get("response_status", 200),
                )
                harness.config.custom_response_modifier = modifier_calls.named(
                    drive["modifier"]
                )
            response = await harness.error_factory.process_response(
                request,
                response,
                0.0,
                harness.middleware.route_resolver.get_route_config(request),
                harness.behavior_processor.process_return_rules,
                harness.behavior_processor.process_global_return_rules,
            )
        else:
            raise ValueError(f"unknown drive stage {stage!r}")
        if response is None:
            record["status"] = None
        else:
            record["status"] = response.status_code
            record["body"] = (
                response.body.decode() if isinstance(response.body, bytes) else ""
            )
            if response.headers:
                record["headers"] = dict(response.headers)
        if "modifier" in drive:
            record["modifier_calls"] = modifier_calls.count
            assert isinstance(response, _StubBodyResponse)
            record["prefix_reads"] = response.prefix_reads
        if getattr(request.state, "is_exempt", None) is not None:
            record["is_exempt"] = request.state.is_exempt
        if getattr(request.state, "is_whitelisted", None) is not None:
            record["is_whitelisted"] = request.state.is_whitelisted
        if harness.event_bus.events:
            record["events"] = [list(pair) for pair in harness.event_bus.events]
        if harness.on_block.payloads:
            record["on_block"] = [
                dict(payload) for payload in harness.on_block.payloads
            ]
        observed.append(record)
    return observed
