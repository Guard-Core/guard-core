import logging
from unittest.mock import MagicMock, Mock, patch

import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.sync.core.checks.implementations.route_config import RouteConfigCheck

_ROUTE_CONFIG = "guard_core.sync.core.checks.implementations.route_config"
_TYPO_WARNING = (
    "exclude_paths entry '/typo' matches no registered route; check it for a typo."
)


def _middleware(route_template: object) -> Mock:
    middleware = Mock()
    middleware.config = SyncSecurityConfig(enable_redis=False, exclude_paths=["/typo"])
    middleware.logger = Mock()
    middleware.route_resolver.get_route_config.return_value = None
    middleware.static_route_prefixes = Mock(return_value=("/admin/",))
    middleware.route_template = route_template
    return middleware


def _request() -> Mock:
    request = Mock()
    request.state = Mock(spec=["client_ip", "guard_route_unresolved"])
    request.state.guard_route_unresolved = False
    request.headers = {}
    request.client_host = "1.2.3.4"
    return request


@pytest.mark.parametrize(
    "route_template",
    [None, Mock(return_value="/orders/{id}")],
    ids=["plain", "template"],
)
def test_the_check_keeps_its_class_through_the_first_and_second_request(
    route_template: object,
    caplog: pytest.LogCaptureFixture,
) -> None:
    check = RouteConfigCheck(_middleware(route_template))
    born = type(check)
    classes = []
    with (
        caplog.at_level(logging.WARNING, logger="guard_core"),
        patch(f"{_ROUTE_CONFIG}.extract_client_ip", MagicMock(return_value="1.2.3.4")),
    ):
        for _ in range(3):
            check.check(_request())
            classes.append(type(check))

    assert classes == [born] * 3
    assert isinstance(check, RouteConfigCheck)
    assert "check" not in vars(check)
    assert [
        r.getMessage()
        for r in caplog.records
        if r.name == "guard_core.models" and r.levelno == logging.WARNING
    ] == [_TYPO_WARNING]


def test_each_check_is_born_in_a_class_of_its_own() -> None:
    first = RouteConfigCheck(_middleware(None))
    second = RouteConfigCheck(_middleware(None))

    assert type(first) is not type(second)
