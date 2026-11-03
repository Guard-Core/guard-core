import functools
import inspect
import logging
from collections.abc import Callable, Generator
from typing import Any
from unittest.mock import MagicMock

import pytest
from pydantic import ValidationError

from guard_core._security_config_batch import prepare_config_batch
from guard_core.exceptions import CallableShapeError
from guard_core.models import SyncSecurityConfig
from guard_core.protocols.response_protocol import GuardResponse
from guard_core.sync.core.callable_slot import CallableSlot
from guard_core.sync.core.checks.implementations.custom_request import (
    CustomRequestCheck,
)
from guard_core.sync.core.responses.context import ResponseContext
from guard_core.sync.core.responses.factory import ErrorResponseFactory
from guard_core.sync.protocols.request_protocol import SyncGuardRequest
from tests.test_sync.conftest import MockGuardResponse, SyncMockGuardRequest


class _Request:
    def __init__(self) -> None:
        self.url_path = "/api"
        self.method = "GET"
        self.headers: dict[str, str] = {}
        self.state = type("State", (), {})()


def _blocked() -> MockGuardResponse:
    return MockGuardResponse("blocked", 403)


def _modified() -> MockGuardResponse:
    return MockGuardResponse("modified", 200, {"X-Mod": "1"})


def _sync_decorator_around_async(
    function: Callable[..., Any],
) -> Callable[..., Any]:
    @functools.wraps(function)
    def wrapper(*args: object, **kwargs: object) -> object:
        return function(*args, **kwargs)

    return wrapper


async def _async_check(request: SyncGuardRequest) -> GuardResponse | None:
    return _blocked()


async def _async_modifier(response: GuardResponse) -> GuardResponse:
    return _modified()


def _sync_check(request: SyncGuardRequest) -> GuardResponse | None:
    return _blocked()


def _sync_modifier(response: GuardResponse) -> GuardResponse:
    return _modified()


async def _async_check_with_extra(
    extra: int, request: SyncGuardRequest
) -> GuardResponse | None:
    return _blocked()


async def _async_modifier_with_extra(
    extra: int, response: GuardResponse
) -> GuardResponse:
    return _modified()


def _sync_check_with_extra(
    extra: int, request: SyncGuardRequest
) -> GuardResponse | None:
    return _blocked()


def _sync_modifier_with_extra(extra: int, response: GuardResponse) -> GuardResponse:
    return _modified()


class _AsyncCallCheck:
    async def __call__(self, request: SyncGuardRequest) -> GuardResponse | None:
        return _blocked()


class _AsyncCallModifier:
    async def __call__(self, response: GuardResponse) -> GuardResponse:
        return _modified()


class _SyncCallCheck:
    def __call__(self, request: SyncGuardRequest) -> GuardResponse | None:
        return _blocked()


class _SyncCallModifier:
    def __call__(self, response: GuardResponse) -> GuardResponse:
        return _modified()


class _Methods:
    async def async_check(self, request: SyncGuardRequest) -> GuardResponse | None:
        return _blocked()

    async def async_modifier(self, response: GuardResponse) -> GuardResponse:
        return _modified()

    def sync_check(self, request: SyncGuardRequest) -> GuardResponse | None:
        return _blocked()

    def sync_modifier(self, response: GuardResponse) -> GuardResponse:
        return _modified()


SYNC_CHECKS: dict[str, Callable[[], Callable[..., Any]]] = {
    "sync function": lambda: _sync_check,
    "partial of a sync function": lambda: functools.partial(_sync_check_with_extra, 1),
    "instance with a sync __call__": lambda: _SyncCallCheck(),
    "bound sync method": lambda: _Methods().sync_check,
}
SYNC_MODIFIERS: dict[str, Callable[[], Callable[..., Any]]] = {
    "sync function": lambda: _sync_modifier,
    "partial of a sync function": lambda: functools.partial(
        _sync_modifier_with_extra, 1
    ),
    "instance with a sync __call__": lambda: _SyncCallModifier(),
    "bound sync method": lambda: _Methods().sync_modifier,
}
ASYNC_CHECKS: dict[str, Callable[[], Callable[..., Any]]] = {
    "async function": lambda: _async_check,
    "partial of an async function": lambda: functools.partial(
        _async_check_with_extra, 1
    ),
    "instance with an async __call__": lambda: _AsyncCallCheck(),
    "bound async method": lambda: _Methods().async_check,
}
ASYNC_MODIFIERS: dict[str, Callable[[], Callable[..., Any]]] = {
    "async function": lambda: _async_modifier,
    "partial of an async function": lambda: functools.partial(
        _async_modifier_with_extra, 1
    ),
    "instance with an async __call__": lambda: _AsyncCallModifier(),
    "bound async method": lambda: _Methods().async_modifier,
}


def _middleware(check: Callable[..., Any] | None) -> MagicMock:
    middleware = MagicMock()
    middleware.config = SyncSecurityConfig(enable_redis=False)
    middleware.config.custom_request_check = check
    middleware.logger = MagicMock()
    middleware.response_factory.apply_modifier = MagicMock(side_effect=lambda r: r)
    return middleware


def _factory(modifier: Callable[..., Any] | None) -> ErrorResponseFactory:
    config = SyncSecurityConfig(enable_redis=False)
    config.custom_response_modifier = modifier
    return ErrorResponseFactory(
        ResponseContext(
            config=config,
            logger=logging.getLogger("guard_core.test_callables_follow_the_type"),
            metrics_collector=MagicMock(),
            response_factory=None,
        )
    )


def _response() -> GuardResponse:
    return MockGuardResponse("body", 200, {"Content-Length": "4"})


@pytest.mark.parametrize("shape", list(SYNC_CHECKS))
def test_every_sync_shape_of_custom_request_check_blocks(shape: str) -> None:
    check = CustomRequestCheck(_middleware(SYNC_CHECKS[shape]()))
    for _ in range(2):
        result = check.check(SyncMockGuardRequest())
        assert result is not None
        assert result.status_code == 403


@pytest.mark.parametrize("shape", list(ASYNC_CHECKS))
def test_an_async_check_fails_at_middleware_start_naming_the_field(
    shape: str,
) -> None:
    with pytest.raises(TypeError, match="custom_request_check.*sync"):
        CustomRequestCheck(_middleware(ASYNC_CHECKS[shape]()))


def test_a_check_set_to_async_after_start_fails_at_the_next_request() -> None:
    middleware = _middleware(_sync_check)
    check = CustomRequestCheck(middleware)
    assert check.check(SyncMockGuardRequest()) is not None
    middleware.config.custom_request_check = _async_check
    with pytest.raises(CallableShapeError, match="custom_request_check"):
        check.check(SyncMockGuardRequest())


def test_a_sync_decorator_around_an_async_check_fails_on_the_first_result() -> None:
    coroutines: list[Any] = []

    def check_returning_a_coroutine(request: SyncGuardRequest) -> object:
        coroutine = _async_check(request)
        coroutines.append(coroutine)
        return coroutine

    check = CustomRequestCheck(_middleware(check_returning_a_coroutine))
    with pytest.raises(CallableShapeError, match="custom_request_check"):
        check.check(SyncMockGuardRequest())
    assert inspect.getcoroutinestate(coroutines[0]) == inspect.CORO_CLOSED


def test_a_lambda_returning_a_coroutine_fails_on_the_first_result() -> None:
    check = CustomRequestCheck(_middleware(lambda request: _async_check(request)))
    with pytest.raises(CallableShapeError, match="custom_request_check"):
        check.check(SyncMockGuardRequest())


def test_a_sync_decorator_around_an_async_function_fails_on_the_first_result() -> None:
    check = CustomRequestCheck(_middleware(_sync_decorator_around_async(_async_check)))
    with pytest.raises(CallableShapeError, match="custom_request_check"):
        check.check(SyncMockGuardRequest())


def test_a_sync_check_is_verified_once_then_called_directly() -> None:
    check = CustomRequestCheck(_middleware(_sync_check))
    check.check(SyncMockGuardRequest())
    assert check._slot.invoke is _sync_check


@pytest.mark.parametrize("with_request", [False, True])
@pytest.mark.parametrize("shape", list(SYNC_MODIFIERS))
def test_every_sync_shape_of_response_modifier_applies(
    shape: str, with_request: bool
) -> None:
    factory = _factory(SYNC_MODIFIERS[shape]())
    request: Any = _Request() if with_request else None
    for _ in range(2):
        response = _response()
        result: GuardResponse = factory.apply_modifier(response, request)
        assert result is not response
        assert result.headers["X-Mod"] == "1"


@pytest.mark.parametrize("shape", list(ASYNC_MODIFIERS))
def test_an_async_modifier_fails_at_middleware_start_naming_the_field(
    shape: str,
) -> None:
    with pytest.raises(TypeError, match="custom_response_modifier.*sync"):
        _factory(ASYNC_MODIFIERS[shape]())


@pytest.mark.parametrize("with_request", [False, True])
def test_a_sync_decorator_around_an_async_modifier_fails_on_the_first_result(
    with_request: bool,
) -> None:
    coroutines: list[Any] = []

    def modifier_returning_a_coroutine(response: GuardResponse) -> object:
        coroutine = _async_modifier(response)
        coroutines.append(coroutine)
        return coroutine

    factory = _factory(modifier_returning_a_coroutine)
    request: Any = _Request() if with_request else None
    with pytest.raises(CallableShapeError, match="custom_response_modifier"):
        factory.apply_modifier(_response(), request)
    assert inspect.getcoroutinestate(coroutines[0]) == inspect.CORO_CLOSED


def test_a_modifier_set_to_async_after_start_fails_at_the_next_response() -> None:
    factory = _factory(_sync_modifier)
    factory.apply_modifier(_response())
    factory.context.config.custom_response_modifier = _async_modifier
    with pytest.raises(CallableShapeError, match="custom_response_modifier"):
        factory.apply_modifier(_response())


def test_a_sync_modifier_is_verified_once_then_called_directly() -> None:
    factory = _factory(_sync_modifier)
    factory.apply_modifier(_response())
    assert factory._modifier_slot.invoke is _sync_modifier


def test_a_modifier_that_raises_still_returns_the_unmodified_response() -> None:
    def broken(response: GuardResponse) -> GuardResponse:
        raise RuntimeError("boom")

    response = _response()
    assert _factory(broken).apply_modifier(response) is response


def test_a_slot_with_nothing_configured_refuses_to_be_called() -> None:
    slot: CallableSlot[int, int] = CallableSlot("custom_request_check")
    with pytest.raises(TypeError, match="custom_request_check is not configured"):
        slot.invoke(1)


def test_a_slot_adopted_by_another_thread_meanwhile_keeps_the_new_callable() -> None:
    slot: CallableSlot[int, int] = CallableSlot("custom_request_check")

    def old(argument: int) -> int:
        slot.adopt(new)
        return argument

    def new(argument: int) -> int:
        return argument + 1

    slot.adopt(old)
    assert slot.invoke(1) == 1
    assert slot.source is new
    assert slot.invoke is not old
    assert slot.invoke(1) == 2


def test_an_awaitable_that_is_not_a_coroutine_fails_on_the_first_result() -> None:
    class Pending:
        def __await__(self) -> Generator[None, None, None]:
            yield

    check = CustomRequestCheck(_middleware(lambda request: Pending()))
    with pytest.raises(CallableShapeError, match="custom_request_check"):
        check.check(SyncMockGuardRequest())


@pytest.mark.parametrize(
    "field", ["custom_request_check", "custom_response_modifier", "auth_verifier"]
)
def test_a_non_callable_is_refused_on_every_path_to_the_config(field: str) -> None:
    config = SyncSecurityConfig(enable_redis=False)
    with pytest.raises(ValidationError, match="callable"):
        SyncSecurityConfig(enable_redis=False, **{field: 123})
    with pytest.raises(ValueError, match=f"{field} must be callable"):
        setattr(config, field, 123)
    with pytest.raises(ValueError, match=f"{field} must be callable"):
        config.model_copy(update={field: 123})
    with pytest.raises(ValueError, match=f"{field} must be callable"):
        prepare_config_batch(config, {field: 123}, {field})
    assert getattr(config, field) is None


@pytest.mark.parametrize(
    "field", ["custom_request_check", "custom_response_modifier", "auth_verifier"]
)
def test_none_and_a_callable_are_accepted_on_assignment(field: str) -> None:
    config = SyncSecurityConfig(enable_redis=False)
    setattr(config, field, _sync_check)
    assert getattr(config, field) is _sync_check
    setattr(config, field, None)
    assert getattr(config, field) is None
