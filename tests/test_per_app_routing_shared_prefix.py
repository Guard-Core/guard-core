import logging
from dataclasses import dataclass
from typing import Any
from unittest.mock import AsyncMock, MagicMock, Mock

import pytest

from guard_core.core.checks.base import SecurityCheck
from guard_core.core.checks.pipeline import SecurityCheckPipeline
from guard_core.core.initialization.handler_initializer import HandlerInitializer
from guard_core.handlers.ipban_handler import ip_ban_manager_for
from guard_core.handlers.suspatterns_handler import sus_patterns_manager_for
from guard_core.models import SecurityConfig
from tests.conftest import MockGuardRequest

ONE = "redis://user:hunter2@one.invalid:6379/0"
TWO = "redis://user:hunter2@two.invalid:6379/0"
PROXY = "10.0.0.1"


@dataclass
class _App:
    config: SecurityConfig
    redis: MagicMock
    agent: MagicMock
    initializer: HandlerInitializer


def _agent() -> MagicMock:
    agent = MagicMock()
    for name in ("initialize_redis", "start", "flush_buffer", "send_event"):
        setattr(agent, name, AsyncMock())
    return agent


def _redis() -> MagicMock:
    redis = MagicMock()
    redis.initialize = AsyncMock()
    redis.initialize_agent = AsyncMock()
    redis.get_key = AsyncMock(return_value=None)
    return redis


async def _start(prefix: str, url: str, proxies: list[str]) -> _App:
    config = SecurityConfig(
        enable_redis=True,
        redis_url=url,
        redis_prefix=prefix,
        trusted_proxies=proxies,
        enable_agent=False,
    )
    redis, agent = _redis(), _agent()
    initializer = HandlerInitializer(config, redis_handler=redis, agent_handler=agent)
    await initializer.initialize_redis_handlers()
    await initializer.initialize_agent_integrations()
    return _App(config, redis, agent, initializer)


class _SeesManagers(SecurityCheck):
    check_name = "sees_managers"

    def __init__(self, middleware: Any, seen: dict[str, Any]) -> None:
        super().__init__(middleware)
        self.seen = seen

    async def check(self, request: Any) -> None:
        ban = ip_ban_manager_for(self.config)
        patterns = sus_patterns_manager_for(self.config)
        self.seen["ban"] = (ban.redis_handler, ban.agent_handler, ban.config)
        self.seen["patterns"] = (patterns.redis_handler, patterns.agent_handler)
        self.seen["refusal"] = ban._self_dos_refusal_reason(PROXY)
        return None


async def _run_request(app: _App) -> dict[str, Any]:
    seen: dict[str, Any] = {}
    middleware = Mock(config=app.config)
    pipeline = SecurityCheckPipeline(
        [_SeesManagers(middleware, seen)], config=app.config
    )
    request = MockGuardRequest(client_host="203.0.113.5", path="/")
    assert await pipeline.execute(request) is None
    return seen


def _telemetry(app: _App) -> Any:
    return app.initializer.composite_handler or app.initializer.agent_handler


async def test_same_prefix_and_connection_each_app_routes_its_own_handlers() -> None:
    first = await _start("wp136-same:", ONE, [PROXY])
    second = await _start("wp136-same:", ONE, [])
    assert ip_ban_manager_for(first.config) is ip_ban_manager_for(second.config)
    assert sus_patterns_manager_for(first.config) is sus_patterns_manager_for(
        second.config
    )

    seen_first = await _run_request(first)
    seen_second = await _run_request(second)

    assert seen_first["ban"][0] is first.redis
    assert seen_first["ban"][1] is _telemetry(first)
    assert seen_first["ban"][2] is first.config
    assert seen_first["patterns"] == (first.redis, _telemetry(first))
    assert seen_second["ban"][0] is second.redis
    assert seen_second["ban"][1] is _telemetry(second)
    assert seen_second["ban"][2] is second.config
    assert seen_second["patterns"] == (second.redis, _telemetry(second))
    assert _telemetry(first) is not _telemetry(second)


async def test_first_app_refuses_its_proxy_ban_though_the_second_bound_last() -> None:
    first = await _start("wp136-proxy:", ONE, [PROXY])
    await _start("wp136-proxy:", ONE, [])

    assert (await _run_request(first))["refusal"] == "trusted_proxy"
    manager = ip_ban_manager_for(first.config)
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(manager, "_log_refused_ban", Mock())
        assert await manager.ban_ip(PROXY, 60) is True


async def test_second_app_without_proxies_is_not_refused() -> None:
    await _start("wp136-noproxy:", ONE, [PROXY])
    second = await _start("wp136-noproxy:", ONE, [])
    assert (await _run_request(second))["refusal"] is None


async def test_scope_ends_with_the_request_and_the_last_bound_answers_outside() -> None:
    first = await _start("wp136-outside:", ONE, [PROXY])
    second = await _start("wp136-outside:", ONE, [])
    await _run_request(first)
    manager = ip_ban_manager_for(first.config)
    assert manager.redis_handler is second.redis
    assert manager.config is second.config


async def test_different_prefixes_keep_separate_managers_control() -> None:
    first = await _start("wp136-a:", ONE, [PROXY])
    second = await _start("wp136-b:", ONE, [])
    assert ip_ban_manager_for(first.config) is not ip_ban_manager_for(second.config)
    assert (await _run_request(first))["ban"][0] is first.redis
    assert (await _run_request(second))["ban"][0] is second.redis


async def test_same_prefix_on_two_urls_gives_two_managers_and_one_redacted_warning(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.WARNING):
        first = await _start("wp136-urls:", ONE, [PROXY])
        second = await _start("wp136-urls:", TWO, [])

    assert ip_ban_manager_for(first.config) is not ip_ban_manager_for(second.config)
    assert sus_patterns_manager_for(first.config) is not sus_patterns_manager_for(
        second.config
    )
    warnings = [r for r in caplog.records if r.name.endswith("app_managers")]
    assert len(warnings) == 1
    text = warnings[0].getMessage()
    assert "wp136-urls:" in text
    assert "one.invalid:6379" in text and "two.invalid:6379" in text
    assert "hunter2" not in text
    assert (await _run_request(first))["ban"][2] is first.config
    assert (await _run_request(second))["ban"][2] is second.config


async def test_same_prefix_and_connection_logs_no_split_warning(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.WARNING):
        await _start("wp136-quiet:", ONE, [])
        await _start("wp136-quiet:", ONE, [])
    assert not [r for r in caplog.records if r.name.endswith("app_managers")]
