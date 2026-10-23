import functools
import logging
from collections.abc import Callable
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from guard_core.core.callable_slot import CallableSlot
from guard_core.core.checks.implementations.custom_request import CustomRequestCheck
from guard_core.core.responses.context import ResponseContext
from guard_core.core.responses.factory import ErrorResponseFactory
from guard_core.exceptions import CallableShapeError
from guard_core.models import SecurityConfig
from guard_core.protocols.response_protocol import GuardResponse
from tests.conftest import MockGuardRequest, MockGuardResponse


class _Metrics:
    async def collect_request_metrics(self, *args: Any, **kwargs: Any) -> None:
        return None


class _Request:
    def __init__(self) -> None:
        self.url_path = "/api"
        self.method = "GET"
        self.headers: dict[str, str] = {}
        self.state = type("State", (), {})()


def _blocked() -> MockGuardResponse:
    return MockGuardResponse("blocked", 403)


async def _async_check(request: Any) -> Any:
    return _blocked()


def _sync_check(request: Any) -> Any:
    return _blocked()


class _AsyncCallCheck:
    async def __call__(self, request: Any) -> Any:
        return _blocked()


class _SyncCallCheck:
    def __call__(self, request: Any) -> Any:
        return _blocked()


class _Methods:
    async def async_check(self, request: Any) -> Any:
        return _blocked()

    def sync_check(self, request: Any) -> Any:
        return _blocked()


def _sync_decorator_around_async(
    function: Callable[..., Any],
) -> Callable[..., Any]:
    @functools.wraps(function)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        return function(*args, **kwargs)

    return wrapper


async def _partial_target(extra: int, request: Any) -> Any:
    return _blocked()


def _sync_partial_target(extra: int, request: Any) -> Any:
    return _blocked()


CHECKS: dict[str, Callable[[], Callable[..., Any]]] = {
    "async function": lambda: _async_check,
    "partial of an async function": lambda: functools.partial(_partial_target, 1),
    "instance with an async __call__": lambda: _AsyncCallCheck(),
    "bound async method": lambda: _Methods().async_check,
    "sync decorator around an async function": lambda: _sync_decorator_around_async(
        _async_check
    ),
    "lambda returning a coroutine": lambda: lambda request: _async_check(request),
    "sync function": lambda: _sync_check,
    "partial of a sync function": lambda: functools.partial(_sync_partial_target, 1),
    "instance with a sync __call__": lambda: _SyncCallCheck(),
    "bound sync method": lambda: _Methods().sync_check,
}


def _middleware(check: Callable[..., Any] | None) -> MagicMock:
    middleware = MagicMock()
    middleware.config = SecurityConfig(enable_redis=False)
    middleware.config.custom_request_check = check
    middleware.logger = MagicMock()
    middleware.event_bus.send_middleware_event = AsyncMock()
    middleware.response_factory.apply_modifier = AsyncMock(side_effect=lambda r: r)
    return middleware


@pytest.mark.parametrize("shape", list(CHECKS))
async def test_every_shape_of_custom_request_check_blocks_in_the_async_tree(
    shape: str,
) -> None:
    check = CustomRequestCheck(_middleware(CHECKS[shape]()))
    result = await check.check(MockGuardRequest())
    assert result is not None
    assert result.status_code == 403


async def test_a_sync_check_runs_inline_and_is_called_once_per_request() -> None:
    calls: list[Any] = []

    def sync_check(request: Any) -> Any:
        calls.append(request)
        return None

    check = CustomRequestCheck(_middleware(sync_check))
    for _ in range(3):
        assert await check.check(MockGuardRequest()) is None
    assert len(calls) == 3


async def test_the_check_is_reclassified_when_the_configured_object_changes() -> None:
    middleware = _middleware(_async_check)
    check = CustomRequestCheck(middleware)
    first = await check.check(MockGuardRequest())
    middleware.config.custom_request_check = _sync_check
    second = await check.check(MockGuardRequest())
    middleware.config.custom_request_check = None
    third = await check.check(MockGuardRequest())
    assert (first is not None, second is not None, third) == (True, True, None)


async def test_a_shape_error_raised_by_a_check_is_not_swallowed() -> None:
    def refusing(request: Any) -> Any:
        raise CallableShapeError("custom_request_check")

    check = CustomRequestCheck(_middleware(refusing))
    with pytest.raises(CallableShapeError):
        await check.check(MockGuardRequest())


def _modified() -> MockGuardResponse:
    return MockGuardResponse("modified", 200, {"X-Mod": "1"})


async def _async_modifier(response: Any) -> Any:
    return _modified()


def _sync_modifier(response: Any) -> Any:
    return _modified()


class _AsyncCallModifier:
    async def __call__(self, response: Any) -> Any:
        return await _async_modifier(response)


class _SyncCallModifier:
    def __call__(self, response: Any) -> Any:
        return _sync_modifier(response)


class _ModifierMethods:
    async def async_modifier(self, response: Any) -> Any:
        return await _async_modifier(response)

    def sync_modifier(self, response: Any) -> Any:
        return _sync_modifier(response)


async def _async_partial_target(extra: int, response: Any) -> Any:
    return await _async_modifier(response)


def _sync_partial_modifier(extra: int, response: Any) -> Any:
    return _sync_modifier(response)


MODIFIERS: dict[str, Callable[[], Callable[..., Any]]] = {
    "async function": lambda: _async_modifier,
    "partial of an async function": lambda: functools.partial(_async_partial_target, 1),
    "instance with an async __call__": lambda: _AsyncCallModifier(),
    "bound async method": lambda: _ModifierMethods().async_modifier,
    "sync decorator around an async function": lambda: _sync_decorator_around_async(
        _async_modifier
    ),
    "lambda returning a coroutine": lambda: lambda response: _async_modifier(response),
    "sync function": lambda: _sync_modifier,
    "partial of a sync function": lambda: functools.partial(_sync_partial_modifier, 1),
    "instance with a sync __call__": lambda: _SyncCallModifier(),
    "bound sync method": lambda: _ModifierMethods().sync_modifier,
}


def _factory(modifier: Callable[..., Any] | None) -> ErrorResponseFactory:
    config = SecurityConfig(enable_redis=False)
    config.custom_response_modifier = modifier
    return ErrorResponseFactory(
        ResponseContext(
            config=config,
            logger=logging.getLogger("guard_core.test_callables_follow_the_type"),
            metrics_collector=MagicMock(collect_request_metrics=AsyncMock()),
            response_factory=None,
        )
    )


def _response() -> Any:
    return MockGuardResponse("body", 200, {"Content-Length": "4"})


@pytest.mark.parametrize("with_request", [False, True])
@pytest.mark.parametrize("shape", list(MODIFIERS))
async def test_every_shape_of_response_modifier_applies_in_the_async_tree(
    shape: str, with_request: bool
) -> None:
    factory = _factory(MODIFIERS[shape]())
    response = _response()
    request: Any = _Request() if with_request else None
    result: GuardResponse = await factory.apply_modifier(response, request)
    assert result is not response
    assert result.headers["X-Mod"] == "1"


async def test_the_modifier_is_reclassified_when_the_configured_object_changes() -> (
    None
):
    factory = _factory(_async_modifier)
    first = await factory.apply_modifier(_response())
    factory.context.config.custom_response_modifier = _sync_modifier
    second = await factory.apply_modifier(_response())
    factory.context.config.custom_response_modifier = None
    third = _response()
    assert await factory.apply_modifier(third) is third
    assert (first.headers["X-Mod"], second.headers["X-Mod"]) == ("1", "1")
    assert "X-Mod" not in third.headers


@pytest.mark.parametrize("with_request", [False, True])
async def test_a_shape_error_raised_by_a_modifier_is_not_swallowed(
    with_request: bool,
) -> None:
    def refusing(response: Any) -> Any:
        raise CallableShapeError("custom_response_modifier")

    request: Any = _Request() if with_request else None
    with pytest.raises(CallableShapeError):
        await _factory(refusing).apply_modifier(_response(), request)


async def test_a_modifier_that_raises_still_returns_the_unmodified_response() -> None:
    def broken(response: Any) -> Any:
        raise RuntimeError("boom")

    response = _response()
    assert await _factory(broken).apply_modifier(response) is response


async def test_a_slot_with_nothing_configured_refuses_to_be_called() -> None:
    slot: CallableSlot[int, int] = CallableSlot("custom_request_check")
    with pytest.raises(TypeError, match="custom_request_check is not configured"):
        await slot.invoke(1)


async def test_an_async_function_is_the_invoked_callable_itself() -> None:
    slot: CallableSlot[Any, Any] = CallableSlot("custom_request_check", _async_check)
    assert slot.invoke is _async_check
    assert slot.source is _async_check
