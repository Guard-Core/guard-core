from collections.abc import Callable, Mapping
from typing import Any, Protocol

from guard_core.models import SyncSecurityConfig
from tests.test_sync.test_core.conftest import (
    build_route_pipeline,
    fixed_country_geo_ip,
    send_request,
)

IP = "203.0.113.80"


class _RecordingAgent:
    def __init__(self) -> None:
        self.events: list[Any] = []

    def send_event(self, event: object) -> None:
        self.events.append(event)

    def rate_limited(self) -> list[Any]:
        return [e for e in self.events if e.event_type == "rate_limited"]


def _config(**settings: object) -> SyncSecurityConfig:
    defaults: dict[str, Any] = {
        "enable_redis": False,
        "enable_penetration_detection": False,
        "enable_rate_limiting": True,
        "rate_limit": 100,
        "rate_limit_window": 60,
    }
    return SyncSecurityConfig(**{**defaults, **settings})


class _EventWithLimits(Protocol):
    @property
    def metadata(self) -> Mapping[str, int]: ...


def _limit(event: _EventWithLimits) -> int:
    metadata = event.metadata
    return int(
        metadata["rate_limit"] if "rate_limit" in metadata else metadata["limit"]
    )


def _run(
    config: SyncSecurityConfig,
    *decorators: Callable[[Any], Any],
    requests: int = 2,
) -> _RecordingAgent:
    geo = fixed_country_geo_ip("US")
    config.geo_ip_handler = geo
    pipeline, middleware, route_id = build_route_pipeline(
        config, *decorators, geo_ip_handler=geo
    )
    agent = _RecordingAgent()
    middleware.guard_decorator.initialize_agent(agent)
    middleware.rate_limit_handler.initialize_agent(agent)
    for _ in range(requests):
        send_request(pipeline, route_id, ip=IP)
    return agent


def test_a_route_limit_block_sends_one_rate_limited_event_with_own_values() -> None:
    agent = _run(_config(), lambda d: d.rate_limit(1, 30))

    (event,) = agent.rate_limited()
    assert _limit(event) == 1
    assert event.metadata["window"] == 30


def test_a_geo_limit_block_sends_one_rate_limited_event_with_own_values() -> None:
    agent = _run(_config(), lambda d: d.geo_rate_limit({"US": (1, 45)}))

    (event,) = agent.rate_limited()
    assert _limit(event) == 1
    assert event.metadata["window"] == 45


def test_an_endpoint_limit_block_sends_one_rate_limited_event_own_values() -> None:
    config = _config(endpoint_rate_limits={"/x": (1, 20)})
    agent = _run(config, lambda d: d.require_https())

    (event,) = agent.rate_limited()
    assert _limit(event) == 1
    assert event.metadata["window"] == 20


def test_a_global_limit_block_sends_one_rate_limited_event() -> None:
    agent = _run(
        _config(rate_limit=1, rate_limit_window=60), lambda d: d.require_https()
    )

    (event,) = agent.rate_limited()
    assert _limit(event) == 1
    assert event.metadata["window"] == 60
    assert event.action_taken == "request_blocked"


def test_a_passive_block_is_reported_as_logged_only() -> None:
    agent = _run(_config(rate_limit=1, passive_mode=True), lambda d: d.require_https())

    (event,) = agent.rate_limited()
    assert event.action_taken == "logged_only"


def test_a_muted_rate_limited_event_is_not_sent() -> None:
    agent = _run(
        _config(rate_limit=1, muted_event_types=frozenset({"rate_limited"})),
        lambda d: d.require_https(),
    )

    assert agent.rate_limited() == []


def test_an_allowed_request_sends_no_rate_limited_event() -> None:
    agent = _run(_config(rate_limit=5), lambda d: d.require_https(), requests=3)

    assert agent.rate_limited() == []
