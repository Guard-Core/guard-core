from typing import Any
from unittest.mock import AsyncMock, Mock, patch

import pytest

from guard_core.core.checks.base import SecurityCheck
from guard_core.core.checks.endpoint_limit_keys import (
    EndpointLimitKeyMap,
    normalize_limit_path,
)
from guard_core.core.checks.implementations.rate_limit import RateLimitCheck
from guard_core.core.checks.pipeline import SecurityCheckPipeline
from guard_core.models import SecurityConfig
from guard_core.protocols.route_identity import RouteIdentity


def _identity(handler: object, **params: str) -> RouteIdentity:
    return RouteIdentity(handler, tuple(sorted(params.items())))


@pytest.mark.parametrize(
    "path,expected",
    [
        ("/login", "/login"),
        ("/login/", "/login"),
        ("//login", "/login"),
        ("/login/.", "/login"),
        ("/a/./b/../c/", "/a/c"),
        ("/", "/"),
        ("//", "/"),
        ("/Login", "/Login"),
    ],
)
def test_normalize_limit_path(path: str, expected: str) -> None:
    assert normalize_limit_path(path) == expected


def test_key_map_maps_every_key_by_normalized_path_without_a_resolver() -> None:
    key_map = EndpointLimitKeyMap(["/login", "/login/", "/api/x"], None)

    assert key_map.by_identity == {}
    assert key_map.matched_keys(None, "//login") == ("/login", "/login/")
    assert key_map.matched_keys(None, "/api/x/") == ("/api/x",)
    assert key_map.matched_keys(None, "/Login") == ()


def test_key_map_maps_keys_that_reach_one_handler_to_the_same_identity() -> None:
    handler = object()
    identity = _identity(handler)

    def resolve(path: str) -> tuple[RouteIdentity, ...]:
        return (identity,) if path in ("/login", "/login/") else ()

    key_map = EndpointLimitKeyMap(["/login", "/login/", "/other"], resolve)

    assert key_map.matched_keys(identity, "/somewhere/else") == ("/login", "/login/")
    assert key_map.matched_keys(_identity(handler, id="1"), "/zzz") == ()


def test_key_map_uses_the_path_only_when_the_identity_does_not_hit() -> None:
    identity_x = _identity(object())
    identity_y = _identity(object())

    def resolve(path: str) -> tuple[RouteIdentity, ...]:
        return {"/a": (identity_x,), "/a/": (identity_y,)}.get(path, ())

    key_map = EndpointLimitKeyMap(["/a", "/a/", "/ghost"], resolve)

    assert key_map.matched_keys(identity_y, "/a/") == ("/a/",)
    assert key_map.matched_keys(identity_x, "/a") == ("/a",)
    assert key_map.matched_keys(_identity(object()), "/a/") == ("/a", "/a/")
    assert key_map.matched_keys(None, "//ghost/") == ("/ghost",)


@pytest.fixture
def config() -> SecurityConfig:
    return SecurityConfig(enable_redis=False, passive_mode=False)


def _check(config: SecurityConfig, resolver: Any) -> RateLimitCheck:
    middleware = Mock()
    middleware.config = config
    middleware.resolve_route = resolver
    middleware.logger = Mock()
    middleware.event_bus.send_middleware_event = AsyncMock()
    return RateLimitCheck(middleware)


def _request(path: str, identity: RouteIdentity | None) -> Any:
    request = Mock()
    request.url_path = path
    request.state = Mock(spec=["guard_route_identity"])
    request.state.guard_route_identity = identity
    return request


def test_needs_route_identity_is_false_without_endpoint_limits(
    config: SecurityConfig,
) -> None:
    resolver = Mock(return_value=())
    check = _check(config, resolver)

    assert check.needs_route_identity is False
    resolver.assert_not_called()


def test_needs_route_identity_is_false_when_no_key_resolves(
    config: SecurityConfig,
) -> None:
    config.endpoint_rate_limits = {"/x": (1, 60)}

    assert _check(config, lambda p: ()).needs_route_identity is False
    assert _check(config, None).needs_route_identity is False


def test_needs_route_identity_rebuilds_when_the_keys_change(
    config: SecurityConfig,
) -> None:
    identity = _identity(object())
    resolver = Mock(return_value=(identity,))
    config.endpoint_rate_limits = {"/x": (1, 60)}
    check = _check(config, resolver)

    assert check.needs_route_identity is True
    assert check.needs_route_identity is True
    assert resolver.call_count == 1

    config.endpoint_rate_limits = {"/y": (1, 60)}
    assert check.needs_route_identity is True
    assert resolver.call_count == 2


def test_pipeline_needs_route_identity_follows_its_checks(
    config: SecurityConfig,
) -> None:
    identity = _identity(object())
    config.endpoint_rate_limits = {"/x": (1, 60)}
    with_identity = _check(config, lambda p: (identity,))
    without_identity = _check(config, None)

    pipeline = SecurityCheckPipeline([])
    assert pipeline.needs_route_identity is False
    pipeline.add_check(without_identity)
    assert pipeline.needs_route_identity is False
    pipeline.add_check(with_identity)
    assert pipeline.needs_route_identity is True


async def _enforced_keys(check: RateLimitCheck, request: Any) -> list[str]:
    seen: list[str] = []

    async def apply(*args: Any, **kwargs: Any) -> None:
        seen.append(kwargs["endpoint_path"])

    with patch.object(check, "_apply_rate_limit_check", apply):
        await check._check_endpoint_rate_limit(request, "1.2.3.4")
    return seen


async def test_every_matched_key_is_enforced_in_its_own_bucket(
    config: SecurityConfig,
) -> None:
    identity = _identity(object())
    config.endpoint_rate_limits = {"/login": (5, 60), "/login/": (2, 60)}
    check = _check(config, lambda p: (identity,))

    assert await _enforced_keys(check, _request("/anything", identity)) == [
        "/login",
        "/login/",
    ]


async def test_unresolved_key_still_limits_a_request_that_has_an_identity(
    config: SecurityConfig,
) -> None:
    config.endpoint_rate_limits = {"/ghost": (5, 60)}
    check = _check(config, lambda p: ())

    assert await _enforced_keys(check, _request("//ghost/", _identity(object()))) == [
        "/ghost"
    ]


async def test_other_ids_do_not_borrow_a_concrete_id_key(
    config: SecurityConfig,
) -> None:
    handler = object()
    config.endpoint_rate_limits = {"/users/42": (5, 60)}
    check = _check(
        config, lambda p: (_identity(handler, id="42"),) if p == "/users/42" else ()
    )

    assert await _enforced_keys(
        check, _request("/users/42", _identity(handler, id="42"))
    ) == ["/users/42"]
    assert (
        await _enforced_keys(check, _request("/users/7", _identity(handler, id="7")))
        == []
    )


class _PlainCheck(SecurityCheck):
    check_name = "plain"

    async def check(self, request: Any) -> None:
        return None


def test_checks_without_a_key_map_never_need_a_route_identity() -> None:
    plain = _PlainCheck(Mock(config=SecurityConfig(enable_redis=False)))

    assert plain.needs_route_identity is False
    assert SecurityCheckPipeline([plain]).needs_route_identity is False
