from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from guard_core.exceptions import GuardRedisError
from guard_core.models import SyncSecurityConfig
from guard_core.sync.core.checks import pipeline as pipeline_module
from guard_core.sync.core.checks._ban_flow import BanFlow
from guard_core.sync.core.checks._pending_ban import PendingBan
from guard_core.sync.core.checks.base import SecurityCheck
from guard_core.sync.core.checks.pipeline import SecurityCheckPipeline
from guard_core.sync.protocols.middleware_protocol import SyncGuardMiddlewareProtocol
from guard_core.sync.protocols.request_protocol import SyncGuardRequest
from tests.test_sync.conftest import SyncMockGuardRequest


class _LeavesPending(SecurityCheck):
    leaves_ban_pending = True

    @property
    def check_name(self) -> str:
        return "leaves_pending"

    def check(self, request: SyncGuardRequest) -> None:
        flow = BanFlow()
        flow.pending = PendingBan(MagicMock(), "198.51.100.9", MagicMock())
        request.state.guard_ban_flow = flow


class _Records(SecurityCheck):
    def __init__(
        self, middleware: SyncGuardMiddlewareProtocol, name: str, ran: list[str]
    ) -> None:
        super().__init__(middleware)
        self.name = name
        self.ran = ran

    @property
    def check_name(self) -> str:
        return self.name

    def check(self, request: SyncGuardRequest) -> None:
        self.ran.append(self.name)


def _rig(**config: object) -> tuple[SecurityCheckPipeline, list[str]]:
    middleware = MagicMock()
    middleware.config = SyncSecurityConfig(**config)
    middleware.logger = MagicMock()
    middleware.create_error_response = MagicMock(
        return_value=SimpleNamespace(status_code=503, headers={})
    )
    ran: list[str] = []
    checks: list[SecurityCheck] = [
        _LeavesPending(middleware),
        _Records(middleware, "first_later", ran),
        _Records(middleware, "second_later", ran),
    ]
    return SecurityCheckPipeline(checks), ran


def _request() -> SyncMockGuardRequest:
    return SyncMockGuardRequest(path="/x", method="GET")


def test_a_failed_pending_ban_resolve_never_skips_a_later_check(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    resolve = MagicMock(side_effect=GuardRedisError(503, "Redis down"))
    monkeypatch.setattr(pipeline_module, "resolve_pending_ban", resolve)
    pipeline, ran = _rig(redis_fail_open=True)

    response = pipeline.execute(_request())

    assert response is None
    assert ran == ["first_later", "second_later"]


def test_a_failed_pending_ban_resolve_fails_closed_when_fail_secure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    resolve = MagicMock(side_effect=GuardRedisError(503, "Redis down"))
    monkeypatch.setattr(pipeline_module, "resolve_pending_ban", resolve)
    pipeline, ran = _rig(fail_secure=True)

    response = pipeline.execute(_request())

    assert response is not None
    assert ran == []
