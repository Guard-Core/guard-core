import time
from datetime import datetime, timezone
from typing import Any
from unittest.mock import AsyncMock, Mock

import pytest

from guard_core.core.validation import validator as validator_module
from guard_core.core.validation.context import ValidationContext
from guard_core.core.validation.validator import RequestValidator
from guard_core.models import SecurityConfig


@pytest.fixture
def mock_config() -> Any:
    config = Mock()
    config.trust_x_forwarded_proto = True
    config.trusted_proxies = ["192.168.1.1", "10.0.0.0/8"]
    config.exclude_paths = ["/health", "/metrics"]
    config.log_sensitive_params = frozenset()
    config.log_sensitive_body_fields = frozenset()
    config.log_sensitive_headers = frozenset()
    return config


@pytest.fixture
def mock_event_bus() -> Any:
    event_bus = Mock()
    event_bus.send_middleware_event = AsyncMock()
    return event_bus


@pytest.fixture
def validation_context(mock_config: Any, mock_event_bus: Any) -> ValidationContext:
    return ValidationContext(
        config=mock_config,
        logger=Mock(),
        event_bus=mock_event_bus,
    )


@pytest.fixture
def validator(validation_context: ValidationContext) -> RequestValidator:
    return RequestValidator(validation_context)


@pytest.fixture
def mock_request() -> Any:
    request = Mock()
    request.url_scheme = "http"
    request.url_path = "/test"
    request.headers = {}
    request.client_host = "127.0.0.1"
    return request


def test_init(validation_context: ValidationContext) -> None:
    validator = RequestValidator(validation_context)
    assert validator.context == validation_context


def test_is_request_https_direct_https(
    validator: RequestValidator, mock_request: Any
) -> None:
    mock_request.url_scheme = "https"

    result = validator.is_request_https(mock_request)

    assert result is True


def test_is_request_https_direct_http(
    validator: RequestValidator, mock_request: Any
) -> None:
    mock_request.url_scheme = "http"

    result = validator.is_request_https(mock_request)

    assert result is False


def test_is_request_https_forwarded_proto_trusted_proxy(
    validator: RequestValidator, mock_request: Any
) -> None:
    mock_request.url_scheme = "http"
    mock_request.headers = {"X-Forwarded-Proto": "https"}
    mock_request.client_host = "192.168.1.1"

    result = validator.is_request_https(mock_request)

    assert result is True


def test_is_request_https_forwarded_proto_untrusted_proxy(
    validator: RequestValidator, mock_request: Any
) -> None:
    mock_request.url_scheme = "http"
    mock_request.headers = {"X-Forwarded-Proto": "https"}
    mock_request.client_host = "1.2.3.4"

    result = validator.is_request_https(mock_request)

    assert result is False


def test_is_request_https_no_client(
    validator: RequestValidator, mock_request: Any
) -> None:
    mock_request.url_scheme = "http"
    mock_request.client_host = None

    result = validator.is_request_https(mock_request)

    assert result is False


def test_is_request_https_trust_disabled(
    validator: RequestValidator, mock_request: Any
) -> None:
    validator.context.config.trust_x_forwarded_proto = False
    mock_request.url_scheme = "http"
    mock_request.headers = {"X-Forwarded-Proto": "https"}

    result = validator.is_request_https(mock_request)

    assert result is False


def test_is_request_https_no_trusted_proxies(
    validator: RequestValidator, mock_request: Any
) -> None:
    validator.context.config.trusted_proxies = ()
    mock_request.url_scheme = "http"
    mock_request.headers = {"X-Forwarded-Proto": "https"}

    result = validator.is_request_https(mock_request)

    assert result is False


def test_is_trusted_proxy_single_ip_match(
    validator: RequestValidator,
) -> None:
    result = validator.is_trusted_proxy("192.168.1.1")

    assert result is True


def test_is_trusted_proxy_single_ip_no_match(
    validator: RequestValidator,
) -> None:
    result = validator.is_trusted_proxy("192.168.1.2")

    assert result is False


def test_is_trusted_proxy_cidr_match(validator: RequestValidator) -> None:
    result = validator.is_trusted_proxy("10.0.5.10")

    assert result is True


def test_is_trusted_proxy_cidr_no_match(validator: RequestValidator) -> None:
    result = validator.is_trusted_proxy("11.0.0.1")

    assert result is False


async def test_check_time_window_within_range(
    validator: RequestValidator,
) -> None:
    current = datetime.now(timezone.utc)

    hour = current.hour
    start_hour = (hour - 1) % 24
    end_hour = (hour + 1) % 24

    time_restrictions = {
        "start": f"{start_hour:02d}:00",
        "end": f"{end_hour:02d}:59",
    }

    result = await validator.check_time_window(time_restrictions)

    assert result is True


async def test_check_time_window_outside_range(
    validator: RequestValidator,
) -> None:
    current = datetime.now(timezone.utc)

    hour = current.hour
    start_hour = (hour + 6) % 24
    end_hour = (hour + 8) % 24

    time_restrictions = {
        "start": f"{start_hour:02d}:00",
        "end": f"{end_hour:02d}:00",
    }

    result = await validator.check_time_window(time_restrictions)

    assert result is False


async def test_check_time_window_overnight_within(
    validator: RequestValidator,
) -> None:
    time_restrictions = {"start": "22:00", "end": "06:00"}

    result = await validator.check_time_window(time_restrictions)

    assert isinstance(result, bool)


async def test_check_time_window_error_handling(
    validator: RequestValidator,
) -> None:
    time_restrictions = {"invalid": "data"}

    result = await validator.check_time_window(time_restrictions)

    assert result is True


async def test_is_path_excluded_matching_path(
    validator: RequestValidator, mock_request: Any, mock_event_bus: Any
) -> None:
    mock_request.url_path = "/health"

    result = await validator.is_path_excluded(mock_request)

    assert result is True
    mock_event_bus.send_middleware_event.assert_called_once()
    call_kwargs = mock_event_bus.send_middleware_event.call_args[1]
    assert call_kwargs["event_type"] == "path_excluded"
    assert call_kwargs["excluded_path"] == "/health"


async def test_is_path_excluded_prefix_match(
    validator: RequestValidator, mock_request: Any, mock_event_bus: Any
) -> None:
    mock_request.url_path = "/health/check"

    result = await validator.is_path_excluded(mock_request)

    assert result is True
    mock_event_bus.send_middleware_event.assert_called_once()


async def test_is_path_excluded_no_match(
    validator: RequestValidator, mock_request: Any, mock_event_bus: Any
) -> None:
    mock_request.url_path = "/api/endpoint"

    result = await validator.is_path_excluded(mock_request)

    assert result is False
    mock_event_bus.send_middleware_event.assert_not_called()


async def test_is_path_excluded_rejects_prefix_confusion_at_validator_level(
    validator: RequestValidator, mock_request: Any, mock_event_bus: Any
) -> None:
    validator.context.config.exclude_paths = ["/static"]
    mock_request.url_path = "/staticadmin"

    result = await validator.is_path_excluded(mock_request)

    assert result is False
    mock_event_bus.send_middleware_event.assert_not_called()


async def test_is_path_excluded_rejects_traversal_escaping_subtree_at_validator_level(
    validator: RequestValidator, mock_request: Any, mock_event_bus: Any
) -> None:
    validator.context.config.exclude_paths = ["/static"]
    mock_request.url_path = "/static/../../../root/.ssh/id_rsa"

    result = await validator.is_path_excluded(mock_request)

    assert result is False
    mock_event_bus.send_middleware_event.assert_not_called()


async def test_is_path_excluded_emits_event_once_across_many_requests(
    validator: RequestValidator, mock_request: Any, mock_event_bus: Any
) -> None:
    mock_request.url_path = "/health"

    results = [await validator.is_path_excluded(mock_request) for _ in range(100)]

    assert results == [True] * 100
    mock_event_bus.send_middleware_event.assert_called_once()


async def test_is_path_excluded_emits_separate_event_for_second_distinct_path(
    validator: RequestValidator, mock_request: Any, mock_event_bus: Any
) -> None:
    mock_request.url_path = "/health"
    await validator.is_path_excluded(mock_request)

    mock_request.url_path = "/metrics"
    await validator.is_path_excluded(mock_request)

    assert mock_event_bus.send_middleware_event.call_count == 2
    excluded_paths_seen = {
        call.kwargs["excluded_path"]
        for call in mock_event_bus.send_middleware_event.call_args_list
    }
    assert excluded_paths_seen == {"/health", "/metrics"}


async def test_is_path_excluded_emits_again_after_ttl_expires(
    validator: RequestValidator, mock_request: Any, mock_event_bus: Any
) -> None:
    mock_request.url_path = "/health"

    await validator.is_path_excluded(mock_request)
    assert mock_event_bus.send_middleware_event.call_count == 1

    validator._path_excluded_event_cache.expire(time=time.monotonic() + 301)

    await validator.is_path_excluded(mock_request)
    assert mock_event_bus.send_middleware_event.call_count == 2


async def test_is_path_excluded_decision_unaffected_by_cache_hit(
    validator: RequestValidator, mock_request: Any, mock_event_bus: Any
) -> None:
    mock_request.url_path = "/health"

    first = await validator.is_path_excluded(mock_request)
    second = await validator.is_path_excluded(mock_request)

    assert first is True
    assert second is True
    mock_event_bus.send_middleware_event.assert_called_once()


async def test_is_path_excluded_cached_entry_does_not_exclude_unrelated_path(
    validator: RequestValidator, mock_request: Any, mock_event_bus: Any
) -> None:
    mock_request.url_path = "/health"
    await validator.is_path_excluded(mock_request)
    mock_event_bus.send_middleware_event.reset_mock()

    mock_request.url_path = "/unrelated"
    result = await validator.is_path_excluded(mock_request)

    assert result is False
    mock_event_bus.send_middleware_event.assert_not_called()


async def test_is_path_excluded_unresolvable_request_path_is_not_excluded(
    validator: RequestValidator, mock_request: Any, mock_event_bus: Any
) -> None:
    mock_request.url_path = "/health%c0%af.."

    result = await validator.is_path_excluded(mock_request)

    assert result is False
    mock_event_bus.send_middleware_event.assert_not_called()


async def test_is_path_excluded_throttle_keyed_on_normalized_path_not_raw(
    validator: RequestValidator, mock_request: Any, mock_event_bus: Any
) -> None:
    for raw_variant in ("/health", "/./health", "/health/.", "/health/"):
        mock_request.url_path = raw_variant
        result = await validator.is_path_excluded(mock_request)
        assert result is True

    assert mock_event_bus.send_middleware_event.call_count == 1
    assert len(validator._path_excluded_event_cache) == 1


async def test_is_path_excluded_reflects_exclude_paths_mutated_at_runtime() -> None:
    config = SecurityConfig(exclude_paths=["/old"])
    event_bus = Mock()
    event_bus.send_middleware_event = AsyncMock()
    context = ValidationContext(config=config, logger=Mock(), event_bus=event_bus)
    validator = RequestValidator(context)
    request = Mock()
    request.url_path = "/new"
    request.client_host = "127.0.0.1"
    request.headers = {}

    assert await validator.is_path_excluded(request) is False

    config.exclude_paths = ["/new"]

    assert await validator.is_path_excluded(request) is True


async def test_is_path_excluded_normalizes_exclude_list_once_until_content_changes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = SecurityConfig(exclude_paths=["/health"])
    event_bus = Mock()
    event_bus.send_middleware_event = AsyncMock()
    context = ValidationContext(config=config, logger=Mock(), event_bus=event_bus)
    validator = RequestValidator(context)
    request = Mock()
    request.url_path = "/health"
    request.client_host = "127.0.0.1"
    request.headers = {}

    call_count = 0
    original_normalize_exclude_paths = validator_module.normalize_exclude_paths

    def counting_normalize_exclude_paths(paths: Any) -> tuple[str, ...]:
        nonlocal call_count
        call_count += 1
        return original_normalize_exclude_paths(paths)

    monkeypatch.setattr(
        validator_module, "normalize_exclude_paths", counting_normalize_exclude_paths
    )

    for _ in range(5):
        await validator.is_path_excluded(request)
    assert call_count == 1

    config.exclude_paths = ["/other"]
    await validator.is_path_excluded(request)
    assert call_count == 2


async def test_is_path_excluded_reflects_exclude_paths_appended_in_place() -> None:
    config = SecurityConfig(exclude_paths=["/healthz"])
    event_bus = Mock()
    event_bus.send_middleware_event = AsyncMock()
    context = ValidationContext(config=config, logger=Mock(), event_bus=event_bus)
    validator = RequestValidator(context)
    request = Mock()
    request.url_path = "/newsection/x"
    request.client_host = "127.0.0.1"
    request.headers = {}

    assert await validator.is_path_excluded(request) is False

    revision_before = config.revision
    config.exclude_paths.append("/newsection")

    assert config.revision == revision_before
    assert await validator.is_path_excluded(request) is True


async def test_is_path_excluded_reflects_exclude_paths_shrunk_in_place() -> None:
    config = SecurityConfig(exclude_paths=["/healthz", "/newsection"])
    event_bus = Mock()
    event_bus.send_middleware_event = AsyncMock()
    context = ValidationContext(config=config, logger=Mock(), event_bus=event_bus)
    validator = RequestValidator(context)
    request = Mock()
    request.url_path = "/newsection/x"
    request.client_host = "127.0.0.1"
    request.headers = {}

    assert await validator.is_path_excluded(request) is True

    config.exclude_paths.pop()

    assert await validator.is_path_excluded(request) is False


async def test_is_path_excluded_reflects_size_preserving_in_place_replace() -> None:
    config = SecurityConfig(exclude_paths=["/healthz", "/old"])
    event_bus = Mock()
    event_bus.send_middleware_event = AsyncMock()
    context = ValidationContext(config=config, logger=Mock(), event_bus=event_bus)
    validator = RequestValidator(context)
    request = Mock()
    request.url_path = "/new/x"
    request.client_host = "127.0.0.1"
    request.headers = {}

    assert await validator.is_path_excluded(request) is False

    config.exclude_paths[1] = "/new"

    assert await validator.is_path_excluded(request) is True
