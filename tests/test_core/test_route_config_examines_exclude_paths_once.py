import logging
from collections.abc import Iterable
from unittest.mock import AsyncMock, Mock, patch

import pytest

from guard_core.core.checks.implementations.route_config import RouteConfigCheck
from guard_core.models import SecurityConfig

_ROUTE_CONFIG = "guard_core.core.checks.implementations.route_config"
_TYPO_WARNING = (
    "exclude_paths entry '/typo' matches no registered route; check it for a typo."
)


def _middleware(prefixes: Iterable[str]) -> Mock:
    middleware = Mock()
    middleware.config = SecurityConfig(enable_redis=False, exclude_paths=["/typo"])
    middleware.logger = Mock()
    middleware.route_resolver.get_route_config.return_value = None
    middleware.static_route_prefixes = Mock(return_value=tuple(prefixes))
    return middleware


def _request() -> Mock:
    request = Mock()
    request.state = Mock(spec=["client_ip", "guard_route_unresolved"])
    request.state.guard_route_unresolved = False
    request.headers = {}
    request.client_host = "1.2.3.4"
    return request


async def _serve(check: RouteConfigCheck, requests: int) -> None:
    with patch(f"{_ROUTE_CONFIG}.extract_client_ip", AsyncMock(return_value="1.2.3.4")):
        for _ in range(requests):
            await check.check(_request())


def _warnings(caplog: pytest.LogCaptureFixture) -> list[str]:
    return [
        r.getMessage()
        for r in caplog.records
        if r.name == "guard_core.models" and r.levelno == logging.WARNING
    ]


async def test_n_requests_make_one_examination_of_the_exclude_paths() -> None:
    check = RouteConfigCheck(_middleware(["/admin/"]))
    with patch(f"{_ROUTE_CONFIG}.warn_unmatched_exclude_paths") as examine:
        await _serve(check, 5)

    assert examine.call_count == 1


async def test_a_config_with_an_unmatched_exclude_path_still_warns(
    caplog: pytest.LogCaptureFixture,
) -> None:
    check = RouteConfigCheck(_middleware(["/admin/"]))
    with caplog.at_level(logging.WARNING, logger="guard_core"):
        await _serve(check, 5)

    assert _warnings(caplog) == [_TYPO_WARNING]


async def test_a_second_configuration_warns_for_itself(
    caplog: pytest.LogCaptureFixture,
) -> None:
    first = RouteConfigCheck(_middleware(["/admin/"]))
    second = RouteConfigCheck(_middleware(["/admin/"]))
    with caplog.at_level(logging.WARNING, logger="guard_core"):
        await _serve(first, 3)
        await _serve(second, 3)

    assert _warnings(caplog) == [_TYPO_WARNING, _TYPO_WARNING]
