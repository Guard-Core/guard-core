import logging
from collections.abc import Callable, Iterable, Sequence
from unittest.mock import MagicMock, Mock

import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.protocols.response_protocol import GuardResponse
from guard_core.protocols.route_identity import RouteIdentity
from guard_core.sync.core.checks.base import SecurityCheck
from guard_core.sync.core.checks.implementations.rate_limit import RateLimitCheck
from guard_core.sync.core.checks.implementations.route_config import RouteConfigCheck
from guard_core.sync.core.checks.pipeline import SecurityCheckPipeline
from guard_core.sync.handlers.ratelimit_handler import RateLimitTier, RateLimitVerdict
from guard_core.sync.protocols.request_protocol import SyncGuardRequest
from tests.test_sync.conftest import MockGuardResponse

BLOCKED = MockGuardResponse("blocked", 403)


def _config(**settings: object) -> SyncSecurityConfig:
    return SyncSecurityConfig(
        enable_redis=False,
        ban_on_hostile_signals=False,
        whitelist_access_only=False,
        **settings,
    )


class Slotted:
    __slots__ = (
        "config",
        "logger",
        "route_resolver",
        "agent_handler",
        "event_bus",
        "prefixes",
        "resolver",
        "rate_limit_handler",
        "last_cloud_ip_refresh",
        "suspicious_request_counts",
        "guard_decorator",
        "response_factory",
        "geo_ip_handler",
        "guard_response_factory",
    )

    def __init__(
        self,
        config: SyncSecurityConfig,
        prefixes: Iterable[str] | Exception,
        resolver: Exception | None,
    ) -> None:
        self.config = config
        self.logger: logging.Logger = Mock()
        self.route_resolver = Mock()
        self.route_resolver.get_route_config.return_value = None
        self.agent_handler = None
        self.event_bus = Mock()
        self.event_bus.send_middleware_event = MagicMock()
        self.prefixes = prefixes
        self.resolver = resolver
        self.rate_limit_handler = Mock()
        self.rate_limit_handler.tier_buckets = []
        self.rate_limit_handler.check_rate_limit_tiers = MagicMock(
            side_effect=self._record_endpoint_buckets
        )
        self.last_cloud_ip_refresh = 0
        self.suspicious_request_counts: dict[str, dict[str, int]] = {}
        self.guard_decorator = None
        self.response_factory = None
        self.geo_ip_handler = None
        self.guard_response_factory = None

    def _record_endpoint_buckets(
        self,
        request: SyncGuardRequest,
        client_ip: str,
        create_error_response: Callable[[int, str], GuardResponse],
        tiers: Sequence[RateLimitTier],
        config: SyncSecurityConfig | None = None,
        window_identity: str | None = None,
        verdict: RateLimitVerdict | None = None,
    ) -> None:
        self.rate_limit_handler.tier_buckets.append(
            [tier.bucket for tier in tiers if tier.kind == "endpoint"]
        )

    def static_route_prefixes(self) -> tuple[str, ...]:
        if isinstance(self.prefixes, Exception):
            raise self.prefixes
        return tuple(self.prefixes)

    def resolve_route(self, path: str) -> tuple[RouteIdentity, ...]:
        if isinstance(self.resolver, Exception):
            raise self.resolver
        return ()

    def create_error_response(
        self, status_code: int, default_message: str
    ) -> GuardResponse:
        return BLOCKED

    def refresh_cloud_ip_ranges(self) -> None:
        return None


def _slotted(
    config: SyncSecurityConfig,
    prefixes: Iterable[str] | Exception,
    resolver: Exception | None,
) -> Slotted:
    return Slotted(config, prefixes, resolver)


def _request() -> Mock:
    request = Mock()
    request.state = Mock(spec=["client_ip", "guard_route_unresolved"])
    request.state.guard_route_unresolved = False
    request.url_path = "/health"
    request.headers = {}
    request.client_host = "1.2.3.4"
    return request


@pytest.fixture(autouse=True)
def _client_ip(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "guard_core.sync.core.checks.implementations.route_config.extract_client_ip",
        MagicMock(return_value="1.2.3.4"),
    )


def _through_pipeline(
    middleware: Slotted, check: SecurityCheck
) -> GuardResponse | None:
    pipeline = SecurityCheckPipeline([check], config=middleware.config)
    return pipeline.execute(_request())


def test_a_slotted_middleware_still_gets_the_warning_and_the_request_passes(
    caplog: pytest.LogCaptureFixture,
) -> None:
    middleware = _slotted(_config(exclude_paths=["/typo"]), ("/health",), None)
    with caplog.at_level(logging.WARNING, logger="guard_core"):
        for _ in range(3):
            assert _through_pipeline(middleware, RouteConfigCheck(middleware)) is None

    typos = [r for r in caplog.records if "'/typo' matches no registered" in r.message]
    assert len(typos) == 1


@pytest.mark.parametrize("error", [RuntimeError("boom"), ValueError("bad app")])
def test_a_raising_static_route_prefixes_never_fails_the_request(
    error: Exception, caplog: pytest.LogCaptureFixture
) -> None:
    middleware = _slotted(_config(exclude_paths=["/typo"]), error, None)
    with caplog.at_level(logging.WARNING, logger="guard_core"):
        for _ in range(2):
            assert _through_pipeline(middleware, RouteConfigCheck(middleware)) is None

    failures = [
        r for r in caplog.records if "static_route_prefixes() raised" in r.message
    ]
    assert len(failures) == 1
    assert repr(error) in failures[0].message


def test_a_raising_resolve_route_never_fails_the_request_and_keeps_the_limit(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = _config(endpoint_rate_limits={"/health": (1, 60)}, passive_mode=False)
    middleware = _slotted(config, (), RuntimeError("no app context"))
    check = RateLimitCheck(middleware)
    with caplog.at_level(logging.WARNING, logger="guard_core"):
        for _ in range(2):
            assert _through_pipeline(middleware, check) is None

    assert middleware.rate_limit_handler.tier_buckets == [["/health"], ["/health"]]
    raised = [r for r in caplog.records if "resolve_route() raised" in r.message]
    assert len(raised) == 1
    assert "'/health'" in raised[0].message
    assert not [r for r in caplog.records if "matches no registered route" in r.message]
