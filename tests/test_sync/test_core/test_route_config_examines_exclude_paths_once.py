import logging
from collections.abc import Iterable
from unittest.mock import MagicMock, Mock, patch

import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.sync.core.checks.implementations.route_config import RouteConfigCheck

_ROUTE_CONFIG = "guard_core.sync.core.checks.implementations.route_config"
_TYPO_WARNING = (
    "exclude_paths entry '/typo' matches no registered route; check it for a typo."
)


def _middleware(prefixes: Iterable[str]) -> Mock:
    middleware = Mock()
    middleware.config = SyncSecurityConfig(enable_redis=False, exclude_paths=["/typo"])
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


def _serve(check: RouteConfigCheck, requests: int) -> None:
    with patch(f"{_ROUTE_CONFIG}.extract_client_ip", MagicMock(return_value="1.2.3.4")):
        for _ in range(requests):
            check.check(_request())


def _warnings(caplog: pytest.LogCaptureFixture) -> list[str]:
    return [
        r.getMessage()
        for r in caplog.records
        if r.name == "guard_core.models" and r.levelno == logging.WARNING
    ]


def test_n_requests_make_one_examination_of_the_exclude_paths() -> None:
    check = RouteConfigCheck(_middleware(["/admin/"]))
    with patch(f"{_ROUTE_CONFIG}.warn_unmatched_exclude_paths") as examine:
        _serve(check, 5)

    assert examine.call_count == 1


def test_a_config_with_an_unmatched_exclude_path_still_warns(
    caplog: pytest.LogCaptureFixture,
) -> None:
    check = RouteConfigCheck(_middleware(["/admin/"]))
    with caplog.at_level(logging.WARNING, logger="guard_core"):
        _serve(check, 5)

    assert _warnings(caplog) == [_TYPO_WARNING]


def test_a_second_configuration_warns_for_itself(
    caplog: pytest.LogCaptureFixture,
) -> None:
    first = RouteConfigCheck(_middleware(["/admin/"]))
    second = RouteConfigCheck(_middleware(["/admin/"]))
    with caplog.at_level(logging.WARNING, logger="guard_core"):
        _serve(first, 3)
        _serve(second, 3)

    assert _warnings(caplog) == [_TYPO_WARNING, _TYPO_WARNING]


class _CountingState:
    """A request state that counts every read of an attribute it does not hold."""

    def __init__(self) -> None:
        self.template_reads = 0

    def __getattr__(self, name: str) -> object:
        if name == "guard_route_template":
            self.template_reads += 1
        raise AttributeError(name)


def _counting_request(state: _CountingState) -> Mock:
    request = Mock()
    request.state = state
    request.headers = {}
    request.client_host = "1.2.3.4"
    return request


def test_a_middleware_without_a_template_lookup_never_reads_the_template() -> None:
    middleware = _middleware(["/admin/"])
    middleware.route_template = None
    check = RouteConfigCheck(middleware)
    state = _CountingState()
    with patch(f"{_ROUTE_CONFIG}.extract_client_ip", MagicMock(return_value="1.2.3.4")):
        for _ in range(5):
            check.check(_counting_request(state))

    assert state.template_reads == 0


def test_a_middleware_with_a_template_lookup_records_it_each_request() -> None:
    middleware = _middleware(["/admin/"])
    middleware.route_template = Mock(return_value="/orders/{id}")
    check = RouteConfigCheck(middleware)
    states = [_CountingState() for _ in range(3)]
    with patch(f"{_ROUTE_CONFIG}.extract_client_ip", MagicMock(return_value="1.2.3.4")):
        for state in states:
            check.check(_counting_request(state))

    assert [vars(state).get("guard_route_template") for state in states] == [
        "/orders/{id}"
    ] * 3
