import logging
from collections.abc import Awaitable, Callable
from typing import Any, cast
from unittest.mock import AsyncMock, MagicMock

import pytest

from guard_core.core.events.metrics import MetricsCollector
from guard_core.core.responses.context import ResponseContext
from guard_core.core.responses.factory import ErrorResponseFactory
from guard_core.decorators.base import RouteConfig
from guard_core.models import SecurityConfig
from tests.conftest import MockGuardRequest, MockGuardResponse, MockGuardResponseFactory


def _make_factory(
    passive_mode: bool = False,
    custom_error_responses: dict[int, str] | None = None,
    custom_response_modifier: object = None,
    security_headers: dict[str, object] | None = None,
    **config_overrides: object,
) -> ErrorResponseFactory:
    config = SecurityConfig(
        enable_redis=False,
        passive_mode=passive_mode,
        custom_error_responses=custom_error_responses or {},
        security_headers=security_headers,
        **config_overrides,
    )
    if custom_response_modifier:
        config.custom_response_modifier = cast(
            Callable[[Any], Awaitable[Any]],
            custom_response_modifier,
        )
    metrics = MagicMock(spec=MetricsCollector)
    metrics.collect_request_metrics = AsyncMock()
    ctx = ResponseContext(
        config=config,
        logger=MagicMock(),
        metrics_collector=metrics,
        response_factory=MockGuardResponseFactory(),
    )
    return ErrorResponseFactory(ctx)


async def test_create_error_response_default() -> None:
    factory = _make_factory()
    resp = await factory.create_error_response(403, "Forbidden")
    assert resp.status_code == 403


async def test_create_error_response_custom_message() -> None:
    factory = _make_factory(custom_error_responses={403: "Custom Forbidden"})
    resp = await factory.create_error_response(403, "Forbidden")
    assert resp.status_code == 403


async def test_create_https_redirect() -> None:
    factory = _make_factory()
    req = MockGuardRequest(scheme="http", path="/test")
    resp = await factory.create_https_redirect(req)
    assert resp.status_code == 301
    assert "Location" in resp.headers


async def test_apply_security_headers_enabled() -> None:
    factory = _make_factory(security_headers={"enabled": True})
    resp = MockGuardResponse("ok", 200)
    result = await factory.apply_security_headers(resp, "/test")
    assert result is not None


async def test_apply_security_headers_disabled() -> None:
    factory = _make_factory(security_headers={"enabled": False})
    resp = MockGuardResponse("ok", 200)
    result = await factory.apply_security_headers(resp)
    assert result is resp


async def test_apply_security_headers_none() -> None:
    factory = _make_factory(security_headers=None)
    resp = MockGuardResponse("ok", 200)
    result = await factory.apply_security_headers(resp)
    assert result is resp


async def test_apply_security_headers_with_a_resolved_override() -> None:
    factory = _make_factory(security_headers={"enabled": True})
    override = factory.security_headers_manager.resolve_override()
    resp = MockGuardResponse("ok", 200)
    result = await factory.apply_security_headers(resp, "/test", override)
    assert result.headers["X-Content-Type-Options"] == "nosniff"


async def test_apply_cors_headers_with_a_resolved_override() -> None:
    factory = _make_factory(
        security_headers={"enabled": True},
        enable_cors=True,
        cors_allow_origins=["https://example.com"],
    )
    override = factory.security_headers_manager.resolve_override()
    resp = MockGuardResponse("ok", 200)
    result = await factory.apply_cors_headers(resp, "https://example.com", override)
    assert result.headers["Access-Control-Allow-Origin"] == "https://example.com"


async def test_apply_cors_headers() -> None:
    factory = _make_factory(
        security_headers={"enabled": True},
        enable_cors=True,
        cors_allow_origins=["https://example.com"],
    )
    resp = MockGuardResponse("ok", 200)
    result = await factory.apply_cors_headers(resp, "https://example.com")
    assert result is not None


async def test_apply_cors_headers_disabled() -> None:
    factory = _make_factory(security_headers={"enabled": False})
    resp = MockGuardResponse("ok", 200)
    result = await factory.apply_cors_headers(resp, "https://example.com")
    assert result is resp


async def test_apply_modifier_none() -> None:
    factory = _make_factory()
    resp = MockGuardResponse("ok", 200)
    result = await factory.apply_modifier(resp)
    assert result is resp


async def test_apply_modifier_custom() -> None:
    async def modifier(response: object) -> object:
        return response

    factory = _make_factory(custom_response_modifier=modifier)
    resp = MockGuardResponse("ok", 200)
    result = await factory.apply_modifier(resp)
    assert result is resp


async def test_apply_modifier_logs_and_returns_unmodified_when_modifier_raises(
    caplog: pytest.LogCaptureFixture,
) -> None:
    async def modifier(response: object) -> object:
        raise RuntimeError("boom")

    factory = _make_factory(custom_response_modifier=modifier)
    resp = MockGuardResponse("ok", 200)

    with caplog.at_level(logging.ERROR, logger="guard_core.core.responses.factory"):
        result = await factory.apply_modifier(resp)

    assert result is resp
    error_records = [r for r in caplog.records if r.levelno == logging.ERROR]
    assert len(error_records) == 1
    record = error_records[0]
    assert "custom_response_modifier raised" in record.getMessage()
    assert "returning unmodified response" in record.getMessage()
    assert "boom" in record.getMessage()
    assert record.exc_info is not None
    assert record.exc_info[0] is RuntimeError
    assert str(record.exc_info[1]) == "boom"


async def test_apply_cors_headers_writes_each_header() -> None:
    factory = _make_factory(
        security_headers={"enabled": True},
        enable_cors=True,
        cors_allow_origins=["https://example.com"],
        cors_allow_methods=["GET"],
        cors_allow_headers=["X-Test"],
    )
    resp = MockGuardResponse("ok", 200)
    result = await factory.apply_cors_headers(resp, "https://example.com")
    assert result.headers.get("Access-Control-Allow-Origin") == "https://example.com"
    assert result.headers.get("Access-Control-Allow-Headers") == "X-Test"


async def test_process_response_basic() -> None:
    factory = _make_factory()
    req = MockGuardRequest(path="/api")
    resp = MockGuardResponse("ok", 200)
    result = await factory.process_response(req, resp, 0.1, None)
    assert result is not None


async def test_process_response_with_behavioral_rules() -> None:
    factory = _make_factory()
    factory.context.agent_handler = None
    req = MockGuardRequest(path="/api")
    resp = MockGuardResponse("ok", 200)
    rc = RouteConfig()
    from guard_core.handlers.behavior_handler import BehaviorRule

    rc.behavior_rules = [
        BehaviorRule(rule_type="usage", threshold=10, window=60, action="log")
    ]
    process_fn = AsyncMock()
    from unittest.mock import patch

    with patch(
        "guard_core.core.responses.factory.extract_client_ip",
        new_callable=AsyncMock,
        return_value="1.2.3.4",
    ):
        result = await factory.process_response(req, resp, 0.1, rc, process_fn)
    process_fn.assert_called_once()
    assert result is not None


async def test_process_response_with_origin() -> None:
    factory = _make_factory(
        security_headers={"enabled": True},
        enable_cors=True,
        cors_allow_origins=["https://example.com"],
    )
    req = MockGuardRequest(path="/api", headers={"origin": "https://example.com"})
    resp = MockGuardResponse("ok", 200)
    result = await factory.process_response(req, resp, 0.1, None)
    assert result is not None
