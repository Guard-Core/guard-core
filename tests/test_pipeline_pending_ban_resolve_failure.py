from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from guard_core.core.checks import pipeline as pipeline_module
from guard_core.core.checks._ban_flow import BanFlow
from guard_core.core.checks._pending_ban import PendingBan
from guard_core.core.checks.base import SecurityCheck
from guard_core.core.checks.pipeline import SecurityCheckPipeline
from guard_core.exceptions import GuardRedisError
from guard_core.models import SecurityConfig


class _LeavesPending(SecurityCheck):
    leaves_ban_pending = True

    @property
    def check_name(self) -> str:
        return "leaves_pending"

    async def check(self, request: Any) -> None:
        flow = BanFlow()
        flow.pending = PendingBan(MagicMock(), "198.51.100.9", MagicMock())
        request.state.guard_ban_flow = flow


class _Records(SecurityCheck):
    def __init__(self, middleware: Any, name: str, ran: list[str]) -> None:
        super().__init__(middleware)
        self.name = name
        self.ran = ran

    @property
    def check_name(self) -> str:
        return self.name

    async def check(self, request: Any) -> None:
        self.ran.append(self.name)


def _rig(**config: Any) -> tuple[SecurityCheckPipeline, list[str]]:
    middleware = MagicMock()
    middleware.config = SecurityConfig(**config)
    middleware.logger = MagicMock()
    middleware.create_error_response = AsyncMock(
        return_value=SimpleNamespace(status_code=503, headers={})
    )
    ran: list[str] = []
    checks: list[SecurityCheck] = [
        _LeavesPending(middleware),
        _Records(middleware, "first_later", ran),
        _Records(middleware, "second_later", ran),
    ]
    return SecurityCheckPipeline(checks), ran


def _request() -> Any:
    return SimpleNamespace(
        state=SimpleNamespace(), url_path="/x", method="GET", headers={}
    )


async def test_a_failed_pending_ban_resolve_never_skips_a_later_check(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    resolve = AsyncMock(side_effect=GuardRedisError(503, "Redis down"))
    monkeypatch.setattr(pipeline_module, "resolve_pending_ban", resolve)
    pipeline, ran = _rig(redis_fail_open=True)

    response = await pipeline.execute(_request())

    assert response is None
    assert ran == ["first_later", "second_later"]


async def test_a_failed_pending_ban_resolve_fails_closed_when_fail_secure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    resolve = AsyncMock(side_effect=GuardRedisError(503, "Redis down"))
    monkeypatch.setattr(pipeline_module, "resolve_pending_ban", resolve)
    pipeline, ran = _rig(fail_secure=True)

    response = await pipeline.execute(_request())

    assert response is not None
    assert ran == []
