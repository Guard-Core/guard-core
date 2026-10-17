import logging
from typing import Any

import pytest

from guard_core.core.checks.factory import build_default_pipeline
from guard_core.core.checks.implementations import rate_limit as rate_limit_module
from guard_core.core.checks.pipeline import SecurityCheckPipeline
from guard_core.decorators import SecurityDecorator
from guard_core.handlers.ipban_handler import ip_ban_manager
from guard_core.models import SecurityConfig
from tests.conftest import MockGuardRequest
from tests.test_core.conftest import build_middleware

GLOBAL_LIMIT_1 = {
    "enable_redis": False,
    "enable_penetration_detection": False,
    "enable_rate_limiting": True,
    "rate_limit": 1,
    "rate_limit_window": 60,
    "enable_rate_limit_auto_ban": True,
    "auto_ban_threshold": 2,
}


@pytest.fixture(autouse=True)
def _fresh_ban_store(monkeypatch: pytest.MonkeyPatch) -> Any:
    monkeypatch.setattr(
        rate_limit_module, "_non_ip_ban_refusal_logged", False, raising=False
    )
    ip_ban_manager.banned_ips.clear()
    ip_ban_manager.redis_handler = None
    yield
    ip_ban_manager.banned_ips.clear()


def _global_pipeline(config: SecurityConfig) -> SecurityCheckPipeline:
    middleware = build_middleware(config, SecurityDecorator(config))
    return build_default_pipeline(middleware)


async def _statuses(
    pipeline: SecurityCheckPipeline, client_host: str | None, count: int
) -> list[int | None]:
    statuses: list[int | None] = []
    for _ in range(count):
        request = MockGuardRequest(path="/x", client_host=client_host)
        response = await pipeline.execute(request)
        statuses.append(None if response is None else response.status_code)
    return statuses


async def test_a_peerless_client_is_rate_limited_and_never_turned_into_a_500(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    banned: list[str] = []

    async def record_ban(ip: str, *args: Any, **kwargs: Any) -> bool:
        banned.append(ip)
        return True

    monkeypatch.setattr(ip_ban_manager, "ban_ip", record_ban)
    pipeline = _global_pipeline(SecurityConfig(**GLOBAL_LIMIT_1))

    statuses = await _statuses(pipeline, None, 5)

    assert statuses == [None, 429, 429, 429, 429]
    assert "unknown" not in banned


async def test_the_refused_non_ip_ban_is_logged_once(
    caplog: pytest.LogCaptureFixture,
) -> None:
    pipeline = _global_pipeline(SecurityConfig(**GLOBAL_LIMIT_1))

    with caplog.at_level(logging.WARNING):
        await _statuses(pipeline, None, 6)

    refusals = [
        record for record in caplog.records if "is not an IP address" in record.message
    ]
    assert len(refusals) == 1
    assert "unknown" in refusals[0].message


async def test_an_exception_from_ban_ip_keeps_the_429(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    async def explode(*args: Any, **kwargs: Any) -> bool:
        raise RuntimeError("ban store down")

    monkeypatch.setattr(ip_ban_manager, "ban_ip", explode)
    pipeline = _global_pipeline(SecurityConfig(**GLOBAL_LIMIT_1))

    with caplog.at_level(logging.ERROR):
        statuses = await _statuses(pipeline, "198.51.100.40", 5)

    assert statuses == [None, 429, 429, 429, 429]
    assert any("ban store down" in str(record.exc_info) for record in caplog.records)


async def test_every_peerless_client_shares_one_rate_limit_bucket() -> None:
    config = SecurityConfig(**{**GLOBAL_LIMIT_1, "enable_rate_limit_auto_ban": False})
    pipeline = _global_pipeline(config)

    first_connection = await _statuses(pipeline, None, 1)
    second_connection = await _statuses(pipeline, None, 1)

    assert first_connection == [None]
    assert second_connection == [429]
