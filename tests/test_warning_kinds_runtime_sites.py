import logging
from types import SimpleNamespace
from typing import cast

import pytest

from guard_core._utils.app_managers import _warn_split_connection
from guard_core.core.routing.context import RoutingContext
from guard_core.core.routing.resolver import RouteConfigResolver
from guard_core.decorators import SecurityDecorator
from guard_core.exceptions import MisconfigurationError
from guard_core.handlers.ipban_handler import IPBanManager
from guard_core.handlers.redis_handler import RedisManager
from guard_core.handlers.security_headers_handler import SecurityHeadersManager
from guard_core.models import SecurityConfig
from guard_core.protocols.request_protocol import GuardRequest

_QUIET = {"enable_redis": False, "rate_limit": 10, "ban_on_hostile_signals": False}
_FLAGS = [True, False]


def _config(flag: bool, **fields: object) -> SecurityConfig:
    return SecurityConfig(**{**_QUIET, "fail_on_misconfiguration": flag, **fields})


def _problems(record: logging.LogRecord) -> object:
    return getattr(record, "problems", None)


def _the_one_warning(caplog: pytest.LogCaptureFixture) -> logging.LogRecord:
    [record] = [r for r in caplog.records if r.levelno >= logging.WARNING]
    return record


def _route() -> None:
    return None


@pytest.mark.parametrize("flag", _FLAGS)
def test_max_request_size_zero_warns_with_its_kind_in_both_flag_modes(
    flag: bool, caplog: pytest.LogCaptureFixture
) -> None:
    decorator = SecurityDecorator(_config(flag))

    with caplog.at_level(logging.WARNING):
        decorator.max_request_size(0)(_route)

    record = _the_one_warning(caplog)
    assert record.getMessage() == (
        f"max_request_size(0) on {_route.__qualname__}: 0 now refuses any request "
        "body; use None for no limit"
    )
    assert _problems(record) == (("decorator.max_request_size.zero", None),)


@pytest.mark.parametrize("flag", _FLAGS)
def test_bypass_of_an_unknown_check_warns_with_its_kind_in_both_flag_modes(
    flag: bool, caplog: pytest.LogCaptureFixture
) -> None:
    decorator = SecurityDecorator(_config(flag))

    with caplog.at_level(logging.WARNING):
        decorator.bypass(["rate_limit", "zzz", "aaa"])(_route)

    record = _the_one_warning(caplog)
    assert record.getMessage() == "@bypass: ignored unknown checks ['aaa', 'zzz']"
    assert _problems(record) == (("decorator.bypass.unknown_check", "aaa, zzz"),)


@pytest.mark.parametrize("flag", _FLAGS)
def test_require_auth_with_a_capitalized_scheme_warns_with_its_kind(
    flag: bool, caplog: pytest.LogCaptureFixture
) -> None:
    decorator = SecurityDecorator(_config(flag))

    with caplog.at_level(logging.WARNING):
        decorator.require_auth(type="Bearer")(_route)

    record = _the_one_warning(caplog)
    assert record.getMessage() == (
        f"require_auth(type='Bearer') on {_route.__qualname__} uses the built-in "
        "'bearer' scheme, as HTTP auth scheme names are case-insensitive. Its "
        "verifier receives only the credential, as for type='bearer'; guard-core "
        "4.x handed it the whole Authorization header, so a verifier that parses "
        "that header must read the credential instead. Write type='bearer' to "
        "say it plainly."
    )
    assert _problems(record) == (("decorator.require_auth.capitalized_scheme", None),)


def test_a_csp_with_unsafe_sources_warns_with_its_kind_per_directive(
    caplog: pytest.LogCaptureFixture,
) -> None:
    manager = SecurityHeadersManager.isolated()

    with caplog.at_level(logging.WARNING):
        manager._compute_csp_config(
            {"script-src": ["'unsafe-inline'"], "style-src": ["'unsafe-eval'"]}
        )

    records = [r for r in caplog.records if r.levelno >= logging.WARNING]
    assert [r.getMessage() for r in records] == [
        "CSP directive 'script-src' contains unsafe sources",
        "CSP directive 'style-src' contains unsafe sources",
    ]
    assert [_problems(r) for r in records] == [
        (("security_headers.csp_unsafe_source", "script-src"),),
        (("security_headers.csp_unsafe_source", "style-src"),),
    ]


def test_hsts_preload_with_a_short_max_age_warns_with_its_kind(
    caplog: pytest.LogCaptureFixture,
) -> None:
    manager = SecurityHeadersManager.isolated()

    with caplog.at_level(logging.WARNING):
        manager._compute_hsts_config(86400, True, True)

    record = _the_one_warning(caplog)
    assert record.getMessage() == "HSTS preload requires max_age >= 31536000"
    assert _problems(record) == (
        ("security_headers.hsts_preload_max_age_too_low", None),
    )


def test_hsts_preload_without_include_subdomains_warns_with_its_kind(
    caplog: pytest.LogCaptureFixture,
) -> None:
    manager = SecurityHeadersManager.isolated()

    with caplog.at_level(logging.WARNING):
        manager._compute_hsts_config(31536000, False, True)

    record = _the_one_warning(caplog)
    assert record.getMessage() == "HSTS preload requires includeSubDomains"
    assert _problems(record) == (
        ("security_headers.hsts_preload_without_include_subdomains", None),
    )


def test_a_headers_manager_given_wildcard_credentials_warns_with_its_kind(
    caplog: pytest.LogCaptureFixture,
) -> None:
    manager = SecurityHeadersManager.isolated()

    with caplog.at_level(logging.WARNING):
        manager._compute_cors_config(["*"], True, None, None)

    record = _the_one_warning(caplog)
    assert record.getMessage() == (
        "CORS misconfiguration: wildcard origin '*' is incompatible with "
        "cors_allow_credentials=True."
    )
    assert _problems(record) == (
        ("cors.wildcard_origin_with_credentials_dropped", None),
    )


def test_a_response_meeting_wildcard_credentials_warns_with_its_kind(
    caplog: pytest.LogCaptureFixture,
) -> None:
    manager = SecurityHeadersManager.isolated()

    with caplog.at_level(logging.WARNING):
        blocked = manager._is_wildcard_with_credentials(
            ["*"], {"allow_credentials": True}
        )

    record = _the_one_warning(caplog)
    assert blocked is True
    assert record.getMessage() == (
        "Credentials cannot be used with wildcard origin - blocking CORS"
    )
    assert _problems(record) == (
        ("cors.wildcard_origin_with_credentials_blocked", None),
    )


def test_two_apps_on_two_connections_warn_with_the_split_connection_kind(
    caplog: pytest.LogCaptureFixture,
) -> None:
    first = SimpleNamespace(redis_prefix="shared:", redis_url="redis://a.example/0")
    second = SimpleNamespace(redis_prefix="shared:", redis_url="redis://b.example/0")

    with caplog.at_level(logging.WARNING):
        _warn_split_connection(
            cast("SecurityConfig", first), cast("SecurityConfig", second), None, None
        )

    record = _the_one_warning(caplog)
    assert record.getMessage() == (
        "Two apps use the Redis prefix 'shared:' on different Redis connections "
        "(redis://a.example/0 and redis://b.example/0): each keeps its own "
        "in-process managers and they share state only through Redis."
    )
    assert _problems(record) == (("redis_prefix.split_connection", "shared:"),)


@pytest.mark.parametrize("flag", _FLAGS)
def test_an_unenforced_ban_warns_once_with_its_kind(
    flag: bool, caplog: pytest.LogCaptureFixture
) -> None:
    manager = IPBanManager()
    config = _config(flag, redis_prefix=f"kind-unenforced-{flag}:")

    with caplog.at_level(logging.WARNING):
        assert manager._ban_stands_for("127.0.0.1", config) is False
        assert manager._ban_stands_for("127.0.0.1", config) is False

    record = _the_one_warning(caplog)
    assert record.getMessage() == (
        f"A stored ban on 127.0.0.1 is not enforced for the app with the Redis "
        f"prefix 'kind-unenforced-{flag}:' ({config.redis_url}): the address "
        "is one of its trusted proxies or a loopback address, and a ban there "
        "would block every user behind it. The ban stays in force for apps that "
        "do not trust it."
    )
    assert _problems(record) == (("ban.unenforced_for_app", None),)


def test_an_unknown_route_is_refused_with_its_kind_with_the_flag_on() -> None:
    logger = logging.getLogger("guard_core.routing.kind_pin")
    resolver = RouteConfigResolver(RoutingContext(_config(True), logger))
    request = cast("GuardRequest", SimpleNamespace(state=SimpleNamespace()))

    for _ in range(2):
        with pytest.raises(MisconfigurationError) as refused:
            resolver._flag_route_unknown_to_decorator(request, "pkg.handler")
        assert [(p.kind, p.subject) for p in refused.value.problems] == [
            ("route.unknown_to_decorator", "pkg.handler")
        ]


def test_an_unknown_route_warns_once_with_its_kind_with_the_flag_off(
    caplog: pytest.LogCaptureFixture,
) -> None:
    logger = logging.getLogger("guard_core.routing.kind_pin")
    resolver = RouteConfigResolver(RoutingContext(_config(False), logger))
    request = cast("GuardRequest", SimpleNamespace(state=SimpleNamespace()))

    with caplog.at_level(logging.WARNING):
        for _ in range(2):
            resolver._flag_route_unknown_to_decorator(request, "pkg.handler")

    record = _the_one_warning(caplog)
    assert record.getMessage() == (
        "Route 'pkg.handler' carries a route id that this SecurityDecorator does "
        "not know: it was decorated by a different SecurityDecorator instance "
        "than the one the middleware uses, so none of its decorators apply. "
        "Decorate the route with the SecurityDecorator the middleware uses. "
        "fail_on_misconfiguration=False keeps starting with it."
    )
    assert _problems(record) == (("route.unknown_to_decorator", "pkg.handler"),)


@pytest.mark.parametrize("flag", _FLAGS)
async def test_enable_redis_without_a_url_warns_with_its_kind(
    flag: bool, caplog: pytest.LogCaptureFixture
) -> None:
    config = _config(flag, enable_redis=True, redis_url=None)

    with caplog.at_level(logging.WARNING):
        await RedisManager(config).initialize()

    record = _the_one_warning(caplog)
    assert record.getMessage() == "Redis URL is None, skipping connection"
    assert _problems(record) == (("redis_url.none_with_enable_redis", None),)
