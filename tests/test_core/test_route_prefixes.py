import logging
from collections.abc import Iterable
from unittest.mock import AsyncMock, Mock

import pytest

from guard_core.core.checks.implementations.rate_limit import RateLimitCheck
from guard_core.core.checks.implementations.route_config import RouteConfigCheck
from guard_core.core.checks.route_prefixes import (
    entry_matches_route_prefixes,
    regex_route_prefix,
    template_route_prefix,
)
from guard_core.models import SecurityConfig


@pytest.mark.parametrize(
    ("template", "prefix"),
    [
        ("/health", "/health"),
        ("/health/", "/health"),
        ("/", ""),
        ("/api/users/{id}", "/api/users/"),
        ("/api/users/<int:id>", "/api/users/"),
        ("/{anything}", "/"),
        ("/user-{id}", "/"),
        ("/files/{p:path}", "/files/"),
    ],
)
def test_template_route_prefix(template: str, prefix: str) -> None:
    assert template_route_prefix(template) == prefix


@pytest.mark.parametrize(
    ("pattern", "prefix"),
    [
        ("/ok$", "/ok"),
        ("^health$", "/health"),
        ("^health/$", "/health"),
        ("^$", ""),
        ("/static/(.*)$", "/static/"),
        ("^api/", "/api/"),
        ("^api/users/(?P<id>[0-9]+)/$", "/api/users/"),
        ("^colou?r$", "/"),
        ("(?P<x>.*)$", "/"),
        ("^a/b.c$", "/a/"),
    ],
)
def test_regex_route_prefix(pattern: str, prefix: str) -> None:
    assert regex_route_prefix(pattern) == prefix


@pytest.mark.parametrize(
    ("entry", "prefixes", "expected"),
    [
        ("/health", ["/health"], True),
        ("/health/", ["/health"], True),
        ("/healthz", ["/health"], False),
        ("/api", ["/api/users/"], True),
        ("/api/users", ["/api/users/"], True),
        ("/api/users/42", ["/api/users/"], True),
        ("/api/users/42", ["/api/users"], False),
        ("/admin/x", ["/admin", "/admin/"], True),
        ("/typo", ["/health", "/api/"], False),
        ("/typo", ["/"], True),
        ("/typo", [], False),
        ("/", [""], True),
        ("/typo", [""], False),
        ("/health/x", ["/health"], False),
    ],
)
def test_entry_matches_route_prefixes(
    entry: str, prefixes: list[str], expected: bool
) -> None:
    assert entry_matches_route_prefixes(entry, prefixes) is expected


def _middleware(config: SecurityConfig, prefixes: Iterable[str] | None = None) -> Mock:
    middleware = Mock()
    middleware.config = config
    middleware.logger = Mock()
    middleware.event_bus.send_middleware_event = AsyncMock()
    middleware.route_resolver.get_route_config.return_value = None
    if prefixes is None:
        del middleware.static_route_prefixes
    else:
        middleware.static_route_prefixes = Mock(return_value=tuple(prefixes))
    return middleware


def _warnings(caplog: pytest.LogCaptureFixture) -> list[str]:
    return [
        r.getMessage()
        for r in caplog.records
        if r.name == "guard_core.models" and r.levelno == logging.WARNING
    ]


async def _first_requests(middleware: Mock, count: int = 2) -> None:
    check = RouteConfigCheck(middleware)
    request = Mock()
    request.state = Mock(spec=["client_ip", "guard_route_unresolved"])
    request.state.guard_route_unresolved = False
    request.headers = {}
    request.client_host = "1.2.3.4"
    for _ in range(count):
        await check.check(request)


def _config(**settings: object) -> SecurityConfig:
    return SecurityConfig(enable_redis=False, **settings)


async def test_a_typo_entry_warns_once_and_a_matched_or_default_entry_never(
    caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "guard_core.core.checks.implementations.route_config.extract_client_ip",
        AsyncMock(return_value="1.2.3.4"),
    )
    config = _config(exclude_paths=["/docs", "/admin", "/api", "/typo"])
    middleware = _middleware(config, ["/admin/", "/api/users/"])
    with caplog.at_level(logging.WARNING, logger="guard_core"):
        await _first_requests(middleware, 3)
        await _first_requests(middleware, 2)

    assert _warnings(caplog) == [
        "exclude_paths entry '/typo' matches no registered route; check it for a typo."
    ]
    assert middleware.static_route_prefixes.call_count == 1


async def test_no_warning_without_the_adapter_call_and_never_fatal(
    caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "guard_core.core.checks.implementations.route_config.extract_client_ip",
        AsyncMock(return_value="1.2.3.4"),
    )
    config = _config(exclude_paths=["/typo"], fail_on_misconfiguration=True)
    with caplog.at_level(logging.WARNING, logger="guard_core"):
        await _first_requests(_middleware(config, None))
        await _first_requests(_middleware(config, []))

    assert _warnings(caplog) == [
        "exclude_paths entry '/typo' matches no registered route; check it for a typo."
    ]


def test_a_rebuilt_rate_limit_check_does_not_repeat_a_key_warning(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = _config(endpoint_rate_limits={"/ghost": (1, 60)})
    middleware = _middleware(config, None)
    middleware.resolve_route = lambda path: ()
    with caplog.at_level(logging.WARNING, logger="guard_core"):
        for _ in range(2):
            assert RateLimitCheck(middleware).needs_route_identity is False

    assert len(_warnings(caplog)) == 1


async def test_the_entries_are_examined_on_the_first_request_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "guard_core.core.checks.implementations.route_config.extract_client_ip",
        AsyncMock(return_value="1.2.3.4"),
    )
    config = _config(exclude_paths=["/typo"])
    middleware = _middleware(config, ["/health"])
    await _first_requests(middleware, 1)
    config.exclude_paths = ["/typo2", "/typo3"]
    await _first_requests(middleware, 2)

    assert middleware.static_route_prefixes.call_count == 1
