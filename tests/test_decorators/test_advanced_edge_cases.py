from unittest.mock import Mock

import pytest

from guard_core import utils
from guard_core.decorators import SecurityDecorator, get_route_id
from guard_core.models import SecurityConfig
from tests.conftest import MockGuardRequest


@pytest.fixture
def adv_security_config() -> SecurityConfig:
    return SecurityConfig()


@pytest.fixture
def decorator(adv_security_config: SecurityConfig) -> SecurityDecorator:
    return SecurityDecorator(adv_security_config)


async def test_honeypot_form_non_utf8_body_without_trap_value_not_blocked(
    decorator: SecurityDecorator,
) -> None:
    mock_func = Mock()
    mock_func.__name__ = mock_func.__qualname__ = "test_func"
    mock_func.__module__ = "test_module"

    honeypot_decorator = decorator.honeypot_detection(["trap_field"])
    decorated_func = honeypot_decorator(mock_func)

    route_id = get_route_id(decorated_func)
    route_config = decorator.get_route_config(route_id)
    assert route_config is not None
    validator = route_config.custom_validators[0]

    from tests.conftest import MockGuardRequest

    mock_request = MockGuardRequest(
        method="POST",
        headers={
            "content-type": "application/x-www-form-urlencoded",
            "content-length": "16",
        },
        body_content=b"\xff\xfe invalid utf8",
    )

    result = await validator(mock_request)
    assert result is None


async def test_honeypot_form_non_utf8_body_with_trap_value_is_blocked(
    decorator: SecurityDecorator,
) -> None:
    mock_func = Mock()
    mock_func.__name__ = mock_func.__qualname__ = "test_func"
    mock_func.__module__ = "test_module"

    honeypot_decorator = decorator.honeypot_detection(["trap_field"])
    decorated_func = honeypot_decorator(mock_func)

    route_id = get_route_id(decorated_func)
    route_config = decorator.get_route_config(route_id)
    assert route_config is not None
    validator = route_config.custom_validators[0]

    from tests.conftest import MockGuardRequest

    body = b"trap_field=bait\xff"
    mock_request = MockGuardRequest(
        method="POST",
        headers={
            "content-type": "application/x-www-form-urlencoded",
            "content-length": str(len(body)),
        },
        body_content=body,
    )

    result = await validator(mock_request)
    assert result is not None
    assert result.status_code == 403


async def test_honeypot_json_non_utf8_body_with_trap_value_is_blocked(
    decorator: SecurityDecorator,
) -> None:
    mock_func = Mock()
    mock_func.__name__ = mock_func.__qualname__ = "test_func"
    mock_func.__module__ = "test_module"

    honeypot_decorator = decorator.honeypot_detection(["trap_field"])
    decorated_func = honeypot_decorator(mock_func)

    route_id = get_route_id(decorated_func)
    route_config = decorator.get_route_config(route_id)
    assert route_config is not None
    validator = route_config.custom_validators[0]

    from tests.conftest import MockGuardRequest

    body = b'{"trap_field": "bait\xff"}'
    mock_request = MockGuardRequest(
        method="POST",
        headers={
            "content-type": "application/json",
            "content-length": str(len(body)),
        },
        body_content=body,
    )

    result = await validator(mock_request)
    assert result is not None
    assert result.status_code == 403


async def test_honeypot_json_non_object_body_not_blocked(
    decorator: SecurityDecorator,
) -> None:
    mock_func = Mock()
    mock_func.__name__ = mock_func.__qualname__ = "test_func"
    mock_func.__module__ = "test_module"

    honeypot_decorator = decorator.honeypot_detection(["trap_field"])
    decorated_func = honeypot_decorator(mock_func)

    route_id = get_route_id(decorated_func)
    route_config = decorator.get_route_config(route_id)
    assert route_config is not None
    validator = route_config.custom_validators[0]

    from tests.conftest import MockGuardRequest

    body = b"123"
    mock_request = MockGuardRequest(
        method="POST",
        headers={
            "content-type": "application/json",
            "content-length": str(len(body)),
        },
        body_content=body,
    )

    result = await validator(mock_request)
    assert result is None


async def test_honeypot_json_deeply_nested_body_not_blocked(
    decorator: SecurityDecorator,
) -> None:
    mock_func = Mock()
    mock_func.__name__ = mock_func.__qualname__ = "test_func"
    mock_func.__module__ = "test_module"

    honeypot_decorator = decorator.honeypot_detection(["trap_field"])
    decorated_func = honeypot_decorator(mock_func)

    route_id = get_route_id(decorated_func)
    route_config = decorator.get_route_config(route_id)
    assert route_config is not None
    validator = route_config.custom_validators[0]

    from tests.conftest import MockGuardRequest

    body = (b"[" * 2000) + (b"]" * 2000)
    mock_request = MockGuardRequest(
        method="POST",
        headers={
            "content-type": "application/json",
            "content-length": str(len(body)),
        },
        body_content=body,
    )

    result = await validator(mock_request)
    assert result is None


async def test_honeypot_non_post_method(decorator: SecurityDecorator) -> None:
    mock_func = Mock()
    mock_func.__name__ = mock_func.__qualname__ = "test_func"
    mock_func.__module__ = "test_module"

    honeypot_decorator = decorator.honeypot_detection(["trap_field"])
    decorated_func = honeypot_decorator(mock_func)

    route_id = get_route_id(decorated_func)
    route_config = decorator.get_route_config(route_id)
    assert route_config is not None
    validator = route_config.custom_validators[0]

    for method in ("GET", "DELETE"):
        result = await validator(MockGuardRequest(method=method))
        assert result is None


async def test_honeypot_unsupported_content_type(
    decorator: SecurityDecorator,
) -> None:
    mock_func = Mock()
    mock_func.__name__ = mock_func.__qualname__ = "test_func"
    mock_func.__module__ = "test_module"

    honeypot_decorator = decorator.honeypot_detection(["trap_field"])
    decorated_func = honeypot_decorator(mock_func)

    route_id = get_route_id(decorated_func)
    route_config = decorator.get_route_config(route_id)
    assert route_config is not None
    validator = route_config.custom_validators[0]

    for content_type in ("text/plain", "image/png"):
        request = MockGuardRequest(
            method="POST",
            headers={"content-type": content_type, "content-length": "20"},
            body_content=b"trap_field=filled   ",
        )
        result = await validator(request)
        assert result is None


@pytest.mark.parametrize(
    "method",
    ["GET", "DELETE", "OPTIONS", "HEAD"],
)
async def test_honeypot_various_non_modifying_methods(
    decorator: SecurityDecorator, method: str
) -> None:
    mock_func = Mock()
    mock_func.__name__ = mock_func.__qualname__ = "test_func"
    mock_func.__module__ = "test_module"

    honeypot_decorator = decorator.honeypot_detection(["trap_field"])
    decorated_func = honeypot_decorator(mock_func)

    route_id = get_route_id(decorated_func)
    route_config = decorator.get_route_config(route_id)
    assert route_config is not None
    validator = route_config.custom_validators[0]

    result = await validator(MockGuardRequest(method=method))
    assert result is None


@pytest.mark.parametrize(
    "method",
    ["POST", "PUT", "PATCH"],
)
async def test_honeypot_modifying_methods_without_content_type(
    decorator: SecurityDecorator, method: str
) -> None:
    mock_func = Mock()
    mock_func.__name__ = mock_func.__qualname__ = "test_func"
    mock_func.__module__ = "test_module"

    honeypot_decorator = decorator.honeypot_detection(["trap_field"])
    decorated_func = honeypot_decorator(mock_func)

    route_id = get_route_id(decorated_func)
    route_config = decorator.get_route_config(route_id)
    assert route_config is not None
    validator = route_config.custom_validators[0]

    request = MockGuardRequest(
        method=method,
        headers={"content-type": "application/xml", "content-length": "20"},
        body_content=b"trap_field=filled   ",
    )

    result = await validator(request)
    assert result is None


class _BodyTrackingRequest:
    def __init__(self, body: bytes = b"", content_length: int | None = None) -> None:
        self._body = body
        self.headers: dict[str, str] = {"content-type": "application/json"}
        if content_length is not None:
            self.headers["content-length"] = str(content_length)
        self.method = "POST"
        self.url_full = "https://test/x"
        self.body_read = False
        self.state = type("S", (), {})()

    async def body(self) -> bytes:
        self.body_read = True
        return self._body


class _BoundedBodyReaderTrackingRequest(_BodyTrackingRequest):
    def __init__(self, body: bytes = b"") -> None:
        super().__init__(body=body, content_length=None)
        self.prefix_requested_max_bytes: int | None = None

    async def read_body_prefix(self, max_bytes: int) -> bytes:
        self.prefix_requested_max_bytes = max_bytes
        return self._body[:max_bytes]


async def test_honeypot_missing_content_length_without_bounded_reader_not_read(
    decorator: SecurityDecorator,
) -> None:
    mock_func = Mock()
    mock_func.__name__ = mock_func.__qualname__ = "test_func"
    mock_func.__module__ = "test_module"

    honeypot_decorator = decorator.honeypot_detection(["trap_field"])
    decorated_func = honeypot_decorator(mock_func)

    route_id = get_route_id(decorated_func)
    route_config = decorator.get_route_config(route_id)
    assert route_config is not None
    validator = route_config.custom_validators[0]

    request = _BodyTrackingRequest(body=b'{"trap_field": "value"}', content_length=None)

    result = await validator(request)

    assert request.body_read is False
    assert result is None


async def test_honeypot_missing_content_length_with_bounded_reader_still_blocks(
    decorator: SecurityDecorator,
) -> None:
    mock_func = Mock()
    mock_func.__name__ = mock_func.__qualname__ = "test_func"
    mock_func.__module__ = "test_module"

    honeypot_decorator = decorator.honeypot_detection(["trap_field"])
    decorated_func = honeypot_decorator(mock_func)

    route_id = get_route_id(decorated_func)
    route_config = decorator.get_route_config(route_id)
    assert route_config is not None
    validator = route_config.custom_validators[0]

    request = _BoundedBodyReaderTrackingRequest(body=b'{"trap_field": "value"}')

    result = await validator(request)

    cap = decorator.config.detection_max_body_inspect_bytes
    max_overlap = utils._MAX_STRADDLE_OVERLAP_BYTES
    assert request.body_read is False
    assert request.prefix_requested_max_bytes is not None
    assert cap <= request.prefix_requested_max_bytes <= cap + max_overlap
    assert result is not None
    assert result.status_code == 403


async def test_honeypot_under_cap_body_still_read_and_blocked(
    decorator: SecurityDecorator,
) -> None:
    mock_func = Mock()
    mock_func.__name__ = mock_func.__qualname__ = "test_func"
    mock_func.__module__ = "test_module"

    honeypot_decorator = decorator.honeypot_detection(["trap_field"])
    decorated_func = honeypot_decorator(mock_func)

    route_id = get_route_id(decorated_func)
    route_config = decorator.get_route_config(route_id)
    assert route_config is not None
    validator = route_config.custom_validators[0]

    request = _BodyTrackingRequest(body=b'{"trap_field": "value"}', content_length=24)

    result = await validator(request)

    assert request.body_read is True
    assert result is not None
    assert result.status_code == 403
