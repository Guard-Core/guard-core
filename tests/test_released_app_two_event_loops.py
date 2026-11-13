import asyncio
from collections.abc import Iterator
from unittest.mock import AsyncMock, MagicMock, Mock

import pytest

from guard_core._utils.app_managers import release_app
from guard_core._utils.app_scope import app_scope_of
from guard_core.core.checks import build_default_pipeline
from guard_core.core.checks.pipeline import SecurityCheckPipeline
from guard_core.core.initialization.handler_initializer import HandlerInitializer
from guard_core.decorators.base import BaseSecurityDecorator
from guard_core.handlers import ipban_handler as ipban_module
from guard_core.handlers import suspatterns_handler as patterns_module
from guard_core.models import SecurityConfig
from guard_core.protocols.response_protocol import GuardResponse


@pytest.fixture(autouse=True)
def _defaults_unserved() -> Iterator[None]:
    ipban_module._APP_BAN_MANAGERS.forget_default()
    patterns_module._APP_PATTERN_MANAGERS.forget_default()
    yield
    ipban_module._APP_BAN_MANAGERS.forget_default()
    patterns_module._APP_PATTERN_MANAGERS.forget_default()


class _SlowInitializer(HandlerInitializer):
    async def reinitialize_after_release(self) -> None:
        await asyncio.sleep(0.01)
        await super().reinitialize_after_release()


def _middleware(config: SecurityConfig, initializer: HandlerInitializer) -> Mock:
    middleware = Mock()
    middleware.config = config
    middleware.logger = Mock()
    middleware.handler_initializer = initializer
    middleware.guard_decorator = None
    middleware.create_error_response = AsyncMock(return_value=Mock(status_code=500))
    middleware.event_bus = Mock()
    middleware.event_bus.send_middleware_event = AsyncMock()
    middleware.route_resolver = Mock()
    middleware.geo_ip_handler = None
    middleware.suspicious_request_counts = {}
    middleware.rate_limit_handler = Mock(redis_handler=None)
    return middleware


def _request() -> MagicMock:
    request = MagicMock()
    request.state.client_ip = "203.0.113.9"
    request.url_path = "/x"
    return request


async def _two_first_requests(
    pipeline: SecurityCheckPipeline,
) -> list[GuardResponse | None]:
    return list(
        await asyncio.gather(
            pipeline._rebuild_response(_request()),
            pipeline._rebuild_response(_request()),
        )
    )


def test_a_second_event_loop_after_contention_still_decides() -> None:
    config = SecurityConfig(enable_redis=False)
    pipeline = build_default_pipeline(_middleware(config, _SlowInitializer(config)))
    for _ in range(3):
        release_app(config)
        assert asyncio.run(_two_first_requests(pipeline)) == [None, None]


def test_contended_decorator_adoption_completions_work_in_a_second_event_loop(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = SecurityConfig()
    initializer = HandlerInitializer(config)
    calls: list[int] = []

    async def slow(_: object = None) -> None:
        calls.append(1)
        await asyncio.sleep(0.02)

    async def two_contended_completions() -> None:
        await asyncio.gather(
            initializer.complete_decorator_adoption(),
            initializer.complete_decorator_adoption(),
        )

    for _ in range(2):
        adopted = BaseSecurityDecorator(SecurityConfig())
        monkeypatch.setattr(adopted, "initialize_behavior_tracking", slow)
        initializer.adopt_decorator(adopted)
        monkeypatch.setattr(app_scope_of(config), "redis_handler", object())
        asyncio.run(two_contended_completions())

    assert len(calls) == 2
