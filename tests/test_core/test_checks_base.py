from unittest.mock import AsyncMock, Mock

import pytest

from guard_core.core.checks.base import SecurityCheck
from guard_core.protocols.request_protocol import GuardRequest
from guard_core.protocols.response_protocol import GuardResponse


class ConcreteSecurityCheck(SecurityCheck):
    async def check(self, request: GuardRequest) -> GuardResponse | None:
        return None

    @property
    def check_name(self) -> str:
        return "test_check"


@pytest.fixture
def mock_middleware() -> Mock:
    middleware = Mock()
    middleware.config = Mock()
    middleware.config.passive_mode = False
    middleware.logger = Mock()
    middleware.event_bus = Mock()
    middleware.event_bus.send_middleware_event = AsyncMock()
    middleware.create_error_response = AsyncMock(return_value=Mock(status_code=403))
    return middleware


@pytest.fixture
def security_check(mock_middleware: Mock) -> ConcreteSecurityCheck:
    return ConcreteSecurityCheck(mock_middleware)


@pytest.fixture
def mock_request() -> Mock:
    request = Mock()
    request.url_path = "/test"
    request.client_host = "127.0.0.1"
    return request


async def test_cannot_instantiate_abstract_class(mock_middleware: Mock) -> None:
    with pytest.raises(TypeError, match="Can't instantiate abstract class"):
        abstract_check: type[object] = SecurityCheck
        abstract_check()


async def test_init(mock_middleware: Mock) -> None:
    check = ConcreteSecurityCheck(mock_middleware)
    assert check.middleware == mock_middleware
    assert check.config == mock_middleware.config
    assert check.logger == mock_middleware.logger


async def test_check_abstract_method(
    security_check: ConcreteSecurityCheck, mock_request: Mock
) -> None:
    result = await security_check.check(mock_request)
    assert result is None


def test_check_name_abstract_property(
    security_check: ConcreteSecurityCheck,
) -> None:
    assert security_check.check_name == "test_check"


async def test_send_event(
    security_check: ConcreteSecurityCheck,
    mock_request: Mock,
    mock_middleware: Mock,
) -> None:
    await security_check.send_event(
        event_type="test_event",
        request=mock_request,
        action_taken="blocked",
        reason="test reason",
        extra_data="test",
    )

    mock_middleware.event_bus.send_middleware_event.assert_called_once_with(
        event_type="test_event",
        request=mock_request,
        action_taken="blocked",
        reason="test reason",
        extra_data="test",
    )


async def test_send_event_no_extra_kwargs(
    security_check: ConcreteSecurityCheck,
    mock_request: Mock,
    mock_middleware: Mock,
) -> None:
    await security_check.send_event(
        event_type="test_event",
        request=mock_request,
        action_taken="allowed",
        reason="passed checks",
    )

    mock_middleware.event_bus.send_middleware_event.assert_called_once_with(
        event_type="test_event",
        request=mock_request,
        action_taken="allowed",
        reason="passed checks",
    )


async def test_create_error_response(
    security_check: ConcreteSecurityCheck, mock_middleware: Mock
) -> None:
    response = await security_check.create_error_response(403, "Forbidden")

    assert response.status_code == 403
    mock_middleware.create_error_response.assert_called_once_with(403, "Forbidden")


async def test_create_error_response_different_codes(
    security_check: ConcreteSecurityCheck, mock_middleware: Mock
) -> None:
    mock_middleware.create_error_response.reset_mock()
    mock_middleware.create_error_response.return_value = Mock(status_code=429)

    response = await security_check.create_error_response(429, "Too Many Requests")

    assert response.status_code == 429
    mock_middleware.create_error_response.assert_called_once_with(
        429, "Too Many Requests"
    )


def test_is_passive_mode_false(security_check: ConcreteSecurityCheck) -> None:
    result = security_check.is_passive_mode()
    assert result is False


def test_is_passive_mode_true(
    security_check: ConcreteSecurityCheck, mock_middleware: Mock
) -> None:
    mock_middleware.config.passive_mode = True
    result = security_check.is_passive_mode()
    assert result is True
