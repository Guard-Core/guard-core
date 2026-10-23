import logging
from typing import Any
from unittest.mock import MagicMock, Mock

import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.protocols.route_identity import RouteIdentity
from guard_core.sync.core.checks.endpoint_limit_keys import EndpointLimitKeyMap
from guard_core.sync.core.checks.implementations.rate_limit import RateLimitCheck

HANDLER = object()


def _resolver(*known: str) -> Any:
    return lambda path: (RouteIdentity(HANDLER, ()),) if path in known else ()


def _check(config: SyncSecurityConfig, resolver: Any) -> RateLimitCheck:
    middleware = Mock()
    middleware.config = config
    middleware.resolve_route = resolver
    middleware.logger = Mock()
    middleware.event_bus.send_middleware_event = MagicMock()
    return RateLimitCheck(middleware)


def _warnings(caplog: pytest.LogCaptureFixture) -> list[str]:
    return [
        r.getMessage()
        for r in caplog.records
        if r.name == "guard_core.models" and r.levelno == logging.WARNING
    ]


def _message(key: str) -> str:
    return (
        f"endpoint_rate_limits key {key!r} matches no registered route; check "
        "it for a typo. It still applies to requests whose path matches it "
        "after normalization."
    )


@pytest.fixture
def config() -> SyncSecurityConfig:
    return SyncSecurityConfig(enable_redis=False, passive_mode=False)


def test_the_key_map_lists_the_keys_no_route_resolved() -> None:
    key_map = EndpointLimitKeyMap(["/a", "/ghost"], _resolver("/a"))
    assert key_map.unresolved == frozenset({"/ghost"})


def test_the_key_map_has_no_unresolved_keys_without_a_resolver() -> None:
    assert EndpointLimitKeyMap(["/a"], None).unresolved == frozenset()


def test_an_unmatched_key_warns_once_and_a_matched_key_never(
    config: SyncSecurityConfig, caplog: pytest.LogCaptureFixture
) -> None:
    config.endpoint_rate_limits = {"/a": (1, 60), "/ghost": (1, 60)}
    check = _check(config, _resolver("/a"))
    with caplog.at_level(logging.WARNING, logger="guard_core"):
        for _ in range(3):
            assert isinstance(check.needs_route_identity, bool)

    assert _warnings(caplog) == [_message("/ghost")]


def test_a_key_added_later_warns_and_an_old_one_does_not_repeat(
    config: SyncSecurityConfig, caplog: pytest.LogCaptureFixture
) -> None:
    config.endpoint_rate_limits = {"/ghost": (1, 60)}
    check = _check(config, _resolver())
    with caplog.at_level(logging.WARNING, logger="guard_core"):
        assert isinstance(check.needs_route_identity, bool)
        config.endpoint_rate_limits = {"/ghost": (1, 60), "/ghost2": (1, 60)}
        assert isinstance(check.needs_route_identity, bool)

    assert _warnings(caplog) == [_message("/ghost"), _message("/ghost2")]


def test_no_warning_without_a_resolver_or_without_keys(
    config: SyncSecurityConfig, caplog: pytest.LogCaptureFixture
) -> None:
    config.endpoint_rate_limits = {"/ghost": (1, 60)}
    with caplog.at_level(logging.WARNING, logger="guard_core"):
        assert isinstance(_check(config, None).needs_route_identity, bool)
        config.endpoint_rate_limits = {}
        assert isinstance(_check(config, _resolver()).needs_route_identity, bool)

    assert _warnings(caplog) == []


def test_the_warning_is_never_fatal(
    config: SyncSecurityConfig, caplog: pytest.LogCaptureFixture
) -> None:
    config.fail_on_misconfiguration = True
    config.endpoint_rate_limits = {"/ghost": (1, 60)}
    with caplog.at_level(logging.WARNING, logger="guard_core"):
        assert isinstance(_check(config, _resolver()).needs_route_identity, bool)

    assert _warnings(caplog) == [_message("/ghost")]
