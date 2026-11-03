from collections.abc import Coroutine
from unittest.mock import MagicMock, patch

from guard_core.models import SyncSecurityConfig
from guard_core.sync.core.checks.implementations.authentication import (
    AuthenticationCheck,
)
from guard_core.sync.decorators.base import RouteConfig
from guard_core.sync.protocols.request_protocol import SyncGuardRequest
from tests.test_sync.conftest import MockGuardResponse, SyncMockGuardRequest

_IMPL = "guard_core.sync.core.checks.implementations"


def _make_middleware(
    passive_mode: bool = False,
    **config_overrides: object,
) -> MagicMock:
    mw = MagicMock()
    config = SyncSecurityConfig(
        enable_redis=False,
        passive_mode=passive_mode,
        **config_overrides,
    )
    mw.config = config
    mw.logger = MagicMock()
    mw.event_bus = MagicMock()
    mw.event_bus.send_middleware_event = MagicMock()
    mw.create_error_response = MagicMock(return_value=MockGuardResponse("unauth", 401))
    return mw


def test_async_verifier_in_sync_rejected_fail_closed() -> None:
    captured: list[Coroutine[object, object, dict[str, str]]] = []

    def verifier(
        _request: SyncGuardRequest, _credential: str
    ) -> Coroutine[object, object, dict[str, str]]:
        async def _coro() -> dict[str, str]:
            return {"user": "x"}

        coro = _coro()
        captured.append(coro)
        return coro

    mw = _make_middleware()
    check = AuthenticationCheck(mw)
    rc = RouteConfig()
    rc.auth_required = "bearer"
    rc.auth_verifier = verifier
    req = SyncMockGuardRequest(headers={"authorization": "Bearer token"})
    req.state.route_config = rc
    with patch(f"{_IMPL}.authentication.log_activity"):
        result = check.check(req)
    assert result is not None
    assert result.status_code == 401
    for coro in captured:
        coro.close()
