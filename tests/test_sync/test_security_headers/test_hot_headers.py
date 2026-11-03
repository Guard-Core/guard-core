from collections.abc import Callable
from unittest.mock import MagicMock

import pytest
from cachetools import TTLCache

from guard_core._security_headers_override import OverrideRecord
from guard_core.models import SyncSecurityConfig
from guard_core.sync.core.events.metrics import MetricsCollector
from guard_core.sync.core.responses.context import ResponseContext
from guard_core.sync.core.responses.factory import ErrorResponseFactory
from guard_core.sync.handlers._security_headers_cache import HotHeadersCache
from tests.test_sync.conftest import (
    MockGuardResponse,
    MockGuardResponseFactory,
    SyncMockGuardRequest,
)

CSP = {"default-src": ["'self'"]}


def _factory(config: SyncSecurityConfig) -> ErrorResponseFactory:
    metrics = MagicMock(spec=MetricsCollector)
    metrics.collect_request_metrics = MagicMock()
    context = ResponseContext(
        config=config,
        logger=MagicMock(),
        metrics_collector=metrics,
        response_factory=MockGuardResponseFactory(),
    )
    return ErrorResponseFactory(context)


def _config(**headers: object) -> SyncSecurityConfig:
    return SyncSecurityConfig(
        enable_redis=False, security_headers={"enabled": True, "csp": CSP, **headers}
    )


def _respond(factory: ErrorResponseFactory) -> dict[str, str]:
    response = MockGuardResponse("ok", 200)
    result = factory.process_response(SyncMockGuardRequest(), response, 0.0, None)
    return dict(result.headers)


def _count_resolutions(
    factory: ErrorResponseFactory, monkeypatch: pytest.MonkeyPatch
) -> list[int]:
    manager = factory.security_headers_manager
    resolved: list[int] = []
    real = manager.get_headers

    def counting(
        request_path: str | None = None,
        config: SyncSecurityConfig | None = None,
        override: OverrideRecord | None = None,
        checked: bool = False,
    ) -> dict[str, str]:
        resolved.append(1)
        return real(request_path, config, override, checked)

    monkeypatch.setattr(manager, "get_headers", counting)
    return resolved


def test_a_second_response_resolves_nothing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    factory = _factory(_config())
    resolved = _count_resolutions(factory, monkeypatch)

    first = _respond(factory)
    second = _respond(factory)

    assert second == first
    assert resolved == [1]


def test_clearing_the_cache_makes_the_next_response_resolve_again(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    factory = _factory(_config())
    resolved = _count_resolutions(factory, monkeypatch)
    _respond(factory)

    factory.security_headers_manager.headers_cache.clear()
    headers = _respond(factory)

    assert resolved == [1, 1]
    assert headers["Content-Security-Policy"] == "default-src 'self'"


def test_a_direct_write_to_the_cache_reaches_the_next_response() -> None:
    factory = _factory(_config())
    manager = factory.security_headers_manager
    _respond(factory)
    key = manager._generate_cache_key(None, factory.context.config, manager._override)

    manager.headers_cache[key] = {"X-Swapped": "1"}

    assert (_respond(factory))["X-Swapped"] == "1"


def test_a_config_change_reaches_the_next_response() -> None:
    config = _config()
    factory = _factory(config)
    _respond(factory)

    config.security_headers = {
        "enabled": True,
        "csp": {"default-src": ["'none'"]},
    }

    headers = _respond(factory)
    assert headers["Content-Security-Policy"] == "default-src 'none'"


def test_replacing_the_cache_object_drops_what_was_hot(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    factory = _factory(_config())
    resolved = _count_resolutions(factory, monkeypatch)
    _respond(factory)

    factory.security_headers_manager.headers_cache = TTLCache(maxsize=10, ttl=300)
    headers = _respond(factory)

    assert resolved == [1, 1]
    assert headers["Content-Security-Policy"] == "default-src 'self'"


def test_an_expired_entry_is_resolved_again(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = [0.0]
    factory = _factory(_config())
    factory.security_headers_manager.headers_cache = HotHeadersCache(
        maxsize=10, ttl=300, timer=lambda: now[0]
    )
    resolved = _count_resolutions(factory, monkeypatch)
    _respond(factory)
    _respond(factory)
    assert resolved == [1]

    now[0] = 301.0
    _respond(factory)

    assert resolved == [1, 1]


def _hot_cache() -> HotHeadersCache:
    cache = HotHeadersCache(maxsize=2, ttl=300)
    cache["k"] = {"X": "1"}
    cache.remember_hot("k", {"s": 1}, {"X": "1"})
    assert cache.hot is not None
    return cache


@pytest.mark.parametrize(
    "mutate",
    [
        lambda cache: cache.__setitem__("other", {}),
        lambda cache: cache.__delitem__("k"),
        lambda cache: cache.pop("k"),
        lambda cache: cache.popitem(),
        lambda cache: cache.clear(),
    ],
)
def test_every_way_the_cache_changes_drops_the_hot_entry(
    mutate: Callable[[HotHeadersCache], object],
) -> None:
    cache = _hot_cache()

    mutate(cache)

    assert cache.hot is None


def test_an_entry_without_a_recorded_expiry_is_never_hot() -> None:
    cache = HotHeadersCache(maxsize=2, ttl=300)

    cache.remember_hot("unknown", {"s": 1}, {"X": "1"})

    assert cache.hot is None


def test_nothing_is_hot_while_an_override_an_event_or_redis_is_in_play() -> None:
    config = _config()
    factory = _factory(config)
    manager = factory.security_headers_manager
    _respond(factory)
    quiet = manager._override
    assert manager.hot_headers(config, quiet) is not None

    with_keys = OverrideRecord(set_at=1.0, keys={"enabled": True})
    with_event = OverrideRecord(set_at=0.0, keys={}, event={"kind": "x"})
    assert manager.hot_headers(config, with_keys) is None
    assert manager.hot_headers(config, with_event) is None

    manager.redis_handler = MagicMock()
    assert manager.hot_headers(config, quiet) is None
    manager.redis_handler = None

    config.enable_redis = True
    assert manager.hot_headers(config, quiet) is None
