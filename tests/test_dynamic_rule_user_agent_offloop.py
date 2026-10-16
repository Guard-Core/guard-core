import asyncio
import time
from collections.abc import Awaitable, Iterator
from datetime import datetime, timezone
from typing import Any
from unittest.mock import patch

import pytest

from guard_core.detection_engine.compiler import PatternCompiler
from guard_core.handlers.dynamic_rule_handler import DynamicRuleManager
from guard_core.models import DynamicRules, SecurityConfig

_UNSAFE = r"(a|aa)+$"
_PATTERNS = ["curl", r"bad[a-z]{2,6}bot", r"python-requests/\d+", _UNSAFE, r"sqlmap\S*"]


async def _apply(manager: DynamicRuleManager, **fields: Any) -> None:
    rules = DynamicRules(
        rule_id="plan", version=1, timestamp=datetime.now(timezone.utc), **fields
    )
    await manager._apply_rules(rules)


@pytest.fixture(autouse=True)
def reset_singleton() -> Iterator[None]:
    DynamicRuleManager._instance = None
    yield
    DynamicRuleManager._instance = None


async def _max_loop_lag_while(work: Awaitable[None]) -> float:
    lags: list[float] = []
    stop = asyncio.Event()

    async def ticker() -> None:
        last = time.perf_counter()
        while not stop.is_set():
            await asyncio.sleep(0.005)
            now = time.perf_counter()
            lags.append(now - last - 0.005)
            last = now

    task = asyncio.create_task(ticker())
    await asyncio.sleep(0.05)
    await work
    stop.set()
    await task
    return max(lags)


@pytest.mark.asyncio
async def test_user_agent_validation_does_not_block_the_event_loop() -> None:
    def slow(
        self: PatternCompiler, pattern: str, max_content_length: int
    ) -> tuple[bool, str]:
        time.sleep(0.2)
        return pattern != _UNSAFE, "stub verdict"

    manager = DynamicRuleManager(SecurityConfig(enable_redis=False))
    with patch.object(PatternCompiler, "validate_pattern_safety", slow):
        lag = await _max_loop_lag_while(_apply(manager, blocked_user_agents=_PATTERNS))

    assert lag < 0.05
    assert manager.config.blocked_user_agents == [
        "curl",
        r"bad[a-z]{2,6}bot",
        r"python-requests/\d+",
        r"sqlmap\S*",
    ]


@pytest.mark.asyncio
async def test_user_agent_verdicts_match_the_synchronous_validator() -> None:
    manager = DynamicRuleManager(SecurityConfig(enable_redis=False))
    await _apply(manager, blocked_user_agents=_PATTERNS)
    compiler = PatternCompiler()
    from guard_core.utils import _MAX_USER_AGENT_MATCH_LENGTH

    expected = [
        p
        for p in _PATTERNS
        if compiler.validate_pattern_safety(
            p, max_content_length=_MAX_USER_AGENT_MATCH_LENGTH
        )[0]
    ]
    assert list(manager.config.blocked_user_agents) == expected
    assert _UNSAFE not in manager.config.blocked_user_agents
