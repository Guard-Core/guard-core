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
from typing import Any, cast

from guard_core.core.behavioral.context import BehavioralContext
from guard_core.core.behavioral.processor import BehavioralProcessor
from guard_core.core.checks.factory import build_default_pipeline
from guard_core.core.responses.context import ResponseContext
from guard_core.core.responses.factory import ErrorResponseFactory
from guard_core.decorators.route_config import RouteConfig, RouteConfigRevision
from guard_core.handlers.behavior_handler import BehaviorTracker
from guard_core.handlers.ipban_handler import reset_global_state
from guard_core.handlers.ratelimit_handler import RateLimitManager
from guard_core.models import SecurityConfig
from guard_core.protocols.response_protocol import GuardResponse

# JSON config keys applied verbatim as SecurityConfig constructor kwargs.
# Everything a pipeline case needs is on this allow-list; anything else in
# the case config is harness-level (geo_countries, routes).
CONFIG_KEYS = (
    "whitelist",
    "blacklist",
    "exempt_ips",
    "blocked_user_agents",
    "blocked_countries",
    "whitelist_countries",
    "rate_limit",
    "rate_limit_window",
    "endpoint_rate_limits",
    "passive_mode",
    "custom_error_responses",
    "security_headers",
    "enable_cors",
    "cors_allow_origins",
    "cors_allow_methods",
    "cors_allow_headers",
    "cors_allow_credentials",
    "global_behavior_rules",
    "behavior_scan_response_body",
    "enable_rate_limiting",
    "enable_penetration_detection",
    "enable_ip_banning",
    "enable_rate_limit_auto_ban",
    "auto_ban_threshold",
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
)

DEFAULT_STATE = {
    # Ban-free, redis-free determinism knobs; a case config may raise
    # auto_ban_threshold but never lower it below this floor in the corpus.
    "enable_redis": False,
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


class _RecordingEventBus:
    """Captures (event_type, action_taken) pairs in emission order."""

    def __init__(self) -> None:
        self.events: list[tuple[str, str]] = []

    async def send_middleware_event(self, **kwargs: Any) -> None:
        self.events.append(
            (str(kwargs.get("event_type")), str(kwargs.get("action_taken", "")))
        )


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
        self.payloads: list[dict[str, Any]] = []

    def __call__(self, request: Any, payload: dict[str, Any]) -> None:
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

    async def initialize_redis(self, redis_handler: Any) -> None:
        return None

    async def initialize_agent(self, agent_handler: Any) -> None:
        return None

    async def refresh(self) -> None:
        return None

    async def close(self) -> None:
        return None


class _StubRouteResolver:
    """Exact-path route table over real RouteConfig objects."""

    def __init__(self, routes: dict[str, RouteConfig]) -> None:
        self.routes = routes

    def get_route_config(self, request: Any) -> RouteConfig | None:
        return self.routes.get(request.url_path)

    def should_bypass_check(self, check_name: str, route_config: Any) -> bool:
        if route_config is None:
            return False
        return check_name in route_config.bypassed_checks

    def get_cloud_providers_to_check(self, route_config: Any) -> set[str] | None:
        if route_config is None or not route_config.block_cloud_providers:
            return None
        return cast(set[str], route_config.block_cloud_providers)


class _HarnessDecorator:
    def __init__(self, config: SecurityConfig, routes: dict[str, RouteConfig]) -> None:
        self._route_configs: dict[str, RouteConfig] = dict(routes)
        self.route_config_revision = RouteConfigRevision()
        self.behavior_tracker = BehaviorTracker(config)

    async def initialize_behavior_tracking(self, redis_handler: Any = None) -> None:
        return None


class _HarnessMiddleware:
    """Minimal GuardMiddlewareProtocol surface carrying the real config."""

    def __init__(
        self,
        config: SecurityConfig,
        rate_limit_handler: RateLimitManager,
        geo_ip_handler: Any,
        routes: dict[str, RouteConfig],
        event_bus: _RecordingEventBus,
        on_block: _RecordingOnBlock,
    ) -> None:
        self.config = config
        self.logger = logging.getLogger("corpus.harness")
        self.rate_limit_handler = rate_limit_handler
        self.geo_ip_handler = geo_ip_handler
        self.event_bus = event_bus
        self.route_resolver = _StubRouteResolver(routes)
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
        self, content: Any, status_code: int, headers: Any = None
    ) -> _StubResponse:
        body = content if isinstance(content, (bytes, str)) else str(content)
        return _StubResponse(status_code, body if isinstance(body, str) else "")

    def create_redirect_response(self, url: Any, status_code: int) -> _StubResponse:
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


def _build_route(path: str, overrides: dict[str, Any]) -> RouteConfig:
    route_config = RouteConfig(RouteConfigRevision())
    for key, value in overrides.items():
        if key in ROUTE_KEYS:
            if key in {
                "bypassed_checks",
                "excluded_detection_headers",
                "excluded_detection_params",
                "excluded_detection_body_fields",
            }:
                value = set(value)
            setattr(route_config, key, value)
    return route_config


def _make_config(case: dict[str, Any], geo: _StubGeoHandler) -> SecurityConfig:
    overrides: dict[str, Any] = dict(DEFAULT_STATE)
    overrides.update(
        {
            key: value
            for key, value in case.get("config", {}).items()
            if key in CONFIG_KEYS
        }
    )
    if overrides.get("blocked_countries") or overrides.get("whitelist_countries"):
        overrides["geo_ip_handler"] = geo
    if "endpoint_rate_limits" in overrides:
        overrides["endpoint_rate_limits"] = {
            path: tuple(limit_window)
            for path, limit_window in overrides["endpoint_rate_limits"].items()
        }
    return SecurityConfig(**overrides)


class _CaseInsensitiveHeaders(dict):
    """Header map like the framework adapters': lookup is case-insensitive."""

    def __init__(self, items: dict[str, str]) -> None:
        super().__init__({key.lower(): value for key, value in items.items()})

    def get(self, key: str, default: Any = None) -> Any:
        return super().get(key.lower(), default)

    def __getitem__(self, key: str) -> Any:
        return super().__getitem__(key.lower())

    def __contains__(self, key: object) -> bool:
        return super().__contains__(str(key).lower())


class _PipelineRequest:
    def __init__(self, drive: dict[str, Any]) -> None:
        self.query_params: dict[str, str] = {}
        self.headers = _CaseInsensitiveHeaders(drive.get("headers", {}))
        self._body = drive.get("body", "").encode()
        if self._body and "content-length" not in self.headers:
            self.headers["content-length"] = str(len(self._body))
        self.url_path = drive.get("url_path", "/api")
        self.url_full = f"http://example.com{self.url_path}"
        self.url_scheme = "http"
        self.method = drive.get("method", "GET")
        self.client_host = drive["client_ip"]
        self.state = type("State", (), {})()
        self.state.client_ip = self.client_host

    async def body(self) -> bytes:
        return cast(bytes, self._body)

    def url_replace_scheme(self, scheme: str) -> Any:
        class _URL:
            def __init__(self, scheme: str) -> None:
                self.scheme = scheme

            def __str__(self) -> str:
                return f"{self.scheme}://example.com"

        return _URL(scheme)


class HarnessCase:
    """One pipeline case: fresh engine state, sequential drives."""

    def __init__(self, case: dict[str, Any]) -> None:
        self.case = case
        self.geo = _StubGeoHandler(case.get("geo_countries", {}))
        self.on_block = _RecordingOnBlock()
        self.config = _make_config(case, self.geo)
        self.config.on_block = self.on_block
        self.routes = {
            path: _build_route(path, overrides)
            for path, overrides in case.get("routes", {}).items()
        }
        self.event_bus = _RecordingEventBus()
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
                metrics_collector=cast(Any, _NullMetrics()),
                agent_handler=None,
                response_factory=_HARNESS_RESPONSE_FACTORY,
            )
        )
        self.behavior_processor = BehavioralProcessor(
            BehavioralContext(
                config=self.config,
                logger=self.middleware.logger,
                event_bus=cast(Any, self.event_bus),
                guard_decorator=None,
                behavior_tracker=self.middleware.guard_decorator.behavior_tracker,
                middleware=self.middleware,
            )
        )


class _NullMetrics:
    async def collect_request_metrics(self, *args: Any, **kwargs: Any) -> None:
        return None


async def run_case(case: dict[str, Any]) -> list[dict[str, Any]]:
    """Drive the case; returns the observed records (one per drive)."""
    await reset_global_state()
    # The headers manager caches per-config entries keyed by id(config); id
    # values are recycled across cases, so clear the cache to keep every
    # case's headers derived from its own config only.
    from guard_core.handlers.security_headers_handler import (
        security_headers_manager,
    )

    security_headers_manager.headers_cache.clear()
    harness = HarnessCase(case)
    # RateLimitManager is a process singleton with in-memory window state;
    # clear it so every case starts from a clean slate.
    await harness.rate_limit_handler.reset()
    observed: list[dict[str, Any]] = []
    for drive in case["drives"]:
        request = _PipelineRequest(drive)
        record: dict[str, Any] = {}
        harness.event_bus.events.clear()
        harness.on_block.payloads.clear()
        stage = drive.get("stage", "pipeline")
        if stage == "pipeline":
            response = await harness.pipeline.execute(cast(Any, request))
        elif stage == "process_response":
            response = _HARNESS_RESPONSE_FACTORY.create_response(
                drive.get("response_body", "ok"),
                drive.get("response_status", 200),
            )
            response = await harness.error_factory.process_response(
                cast(Any, request),
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
