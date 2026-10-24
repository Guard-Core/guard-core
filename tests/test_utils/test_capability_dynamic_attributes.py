import logging
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import MagicMock

import pytest
from cachetools import TTLCache

from guard_core._utils import body_reader
from guard_core._utils.body_reader import (
    _body_reader_kind,
    _read_capped_body_or_raise,
)
from guard_core._utils.capability import (
    has_callable,
    has_callables,
    serves_attributes_dynamically,
)
from guard_core._utils.response_prefetch import ResponseBodyPrefetch
from guard_core.core.initialization._cloud_initialization import (
    CloudInitializationMixin,
)
from guard_core.handlers._behavior_response_pattern import (
    BehaviorResponsePatternMixin,
)
from guard_core.models import SecurityConfig
from tests.conftest import MockGuardRequest

LOGGER = "guard_core"
POST = {"content-type": "text/plain", "content-length": "4"}


class _Idle:
    async def read_body_prefix_until_idle(
        self, max_bytes: int, idle_timeout: float
    ) -> bytes:
        return b"idle"


class _Prefix:
    async def read_body_prefix(self, max_bytes: int) -> bytes:
        return b"pref"


class _Delegating(MockGuardRequest):
    def __init__(self, inner: object) -> None:
        super().__init__(method="POST", path="/x", headers=POST)
        self._inner = inner

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)


class _PlainIdle(MockGuardRequest):
    async def read_body_prefix_until_idle(
        self, max_bytes: int, idle_timeout: float
    ) -> bytes:
        return b"idle"


def _config() -> SecurityConfig:
    return SecurityConfig(enable_redis=False, rate_limit=10000)


def test_has_callable_sees_what_getattr_serves() -> None:
    assert has_callable(_Delegating(_Idle()), "read_body_prefix_until_idle")
    assert not has_callable(_Delegating(_Prefix()), "read_body_prefix_until_idle")
    assert not has_callable(SimpleNamespace(read_body_prefix=None), "read_body_prefix")
    assert has_callables(_Delegating(_Prefix()), ("read_body_prefix",))
    assert not has_callables(_Delegating(_Prefix()), ("read_body_prefix", "nope"))


def test_dynamic_classes_are_told_apart_from_static_ones() -> None:
    assert serves_attributes_dynamically(_Delegating)
    assert serves_attributes_dynamically(MagicMock)
    assert not serves_attributes_dynamically(_PlainIdle)

    class _Getattribute:
        def __getattribute__(self, name: str) -> Any:
            return object.__getattribute__(self, name)

    assert serves_attributes_dynamically(_Getattribute)


async def test_a_plain_class_gets_the_idle_bounded_reader() -> None:
    request = _PlainIdle(method="POST", path="/x", headers=POST)
    assert _body_reader_kind(request) == "read_body_prefix_until_idle"
    assert await _read_capped_body_or_raise(request, _config()) == b"idle"


async def test_a_delegating_wrapper_gets_the_idle_bounded_reader() -> None:
    request = _Delegating(_Idle())
    assert _body_reader_kind(request) == "read_body_prefix_until_idle"
    assert await _read_capped_body_or_raise(request, _config()) == b"idle"


async def test_a_mock_with_a_callable_idle_method_gets_the_idle_reader() -> None:
    request = MagicMock()
    request.headers = POST
    request.state = SimpleNamespace()
    request.read_body_prefix_until_idle = _Idle().read_body_prefix_until_idle
    assert _body_reader_kind(request) == "read_body_prefix_until_idle"


async def test_a_delegating_wrapper_over_the_old_prefix_method_warns_and_falls_back(
    caplog: pytest.LogCaptureFixture,
) -> None:
    class _Fresh(_Delegating):
        pass

    request = _Fresh(_Prefix())
    with caplog.at_level(logging.WARNING, logger=LOGGER):
        assert _body_reader_kind(request) == "read_body_prefix"
    assert any("no read_body_prefix_until_idle" in r.message for r in caplog.records)


async def test_a_class_without_the_methods_warns_and_reads_the_full_body(
    caplog: pytest.LogCaptureFixture,
) -> None:
    class _Fresh(_Delegating):
        pass

    request = _Fresh(object())
    with caplog.at_level(logging.WARNING, logger=LOGGER):
        assert _body_reader_kind(request) == "body"
    assert any(
        "neither read_body_prefix_until_idle" in r.message for r in caplog.records
    )


async def test_wrappers_of_one_class_that_differ_are_not_cached_wrongly() -> None:
    with_idle = _Delegating(_Idle())
    without = _Delegating(object())
    assert _body_reader_kind(without) == "body"
    assert _body_reader_kind(with_idle) == "read_body_prefix_until_idle"
    assert _body_reader_kind(without) == "body"
    assert _Delegating not in body_reader._reader_kind_by_class


async def test_a_wrapper_class_warns_once_per_fallback_kind(
    caplog: pytest.LogCaptureFixture,
) -> None:
    class _Wrapper(_Delegating):
        pass

    with caplog.at_level(logging.WARNING, logger=LOGGER):
        _body_reader_kind(_Wrapper(_Prefix()))
        _body_reader_kind(_Wrapper(object()))
    assert len(caplog.records) == 2


async def test_the_fallback_warning_of_a_wrapper_is_logged_once_per_class(
    caplog: pytest.LogCaptureFixture,
) -> None:
    class _Wrapper(_Delegating):
        pass

    with caplog.at_level(logging.WARNING, logger=LOGGER):
        for _ in range(3):
            _body_reader_kind(_Wrapper(object()))
    assert len([r for r in caplog.records if "neither" in r.message]) == 1


async def test_a_plain_class_verdict_is_cached_per_class() -> None:
    request = _PlainIdle(method="POST", path="/x", headers=POST)
    _body_reader_kind(request)
    assert (
        body_reader._reader_kind_by_class[_PlainIdle] == "read_body_prefix_until_idle"
    )


class _DelegatingResponse:
    status_code = 200

    def __init__(self, inner: object) -> None:
        self._inner = inner

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)


class _PlainResponse:
    status_code = 200

    async def read_body_prefix(self, max_bytes: int) -> bytes:
        return b"pref"


@pytest.mark.parametrize(
    ("response", "expected"),
    [
        (_PlainResponse(), b"pref"),
        (_DelegatingResponse(_Prefix()), b"pref"),
        (_DelegatingResponse(object()), None),
    ],
)
async def test_the_response_prefetch_reads_through_a_delegating_response(
    response: Any, expected: bytes | None
) -> None:
    assert await ResponseBodyPrefetch(response).read(16, 1.0) == expected


class _Mixin(BehaviorResponsePatternMixin):
    def __init__(self) -> None:
        self.config = SecurityConfig(behavior_scan_response_body=True)
        self.logger = logging.getLogger("guard_core.test_capability")
        self._body_unavailable_log_cache = TTLCache(maxsize=8, ttl=60)


@pytest.mark.parametrize(
    ("response", "expected"),
    [
        (_PlainResponse(), b"pref"),
        (_DelegatingResponse(_Prefix()), b"pref"),
        (_DelegatingResponse(object()), None),
    ],
)
async def test_the_response_pattern_scan_reads_a_delegating_response(
    response: Any, expected: bytes | None
) -> None:
    assert await _Mixin()._read_response_body_prefix(response, "x") == expected


class _Store:
    async def get(self, provider: str) -> set[str] | None:
        return None

    async def set(
        self, provider: str, ranges: set[str], ttl: int | None = None
    ) -> None:
        return None

    async def clear(self) -> None:
        return None


class _DelegatingCallableStore:
    def __init__(self) -> None:
        self._inner = _Store()

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)

    def __call__(self, redis_handler: object) -> str:
        return "invoked as a factory"


class _Initializer(CloudInitializationMixin):
    def __init__(self, store: object) -> None:
        self.config = cast(Any, SimpleNamespace(cloud_ip_store=store))
        self.redis_handler = None


def test_a_callable_delegating_store_is_used_as_the_store_not_as_a_factory() -> None:
    store = _DelegatingCallableStore()
    assert _Initializer(store)._resolve_cloud_ip_store() is store


def test_a_plain_factory_is_still_invoked() -> None:
    def factory(redis_handler: object) -> _Store:
        return store

    store = _Store()
    assert _Initializer(factory)._resolve_cloud_ip_store() is store
