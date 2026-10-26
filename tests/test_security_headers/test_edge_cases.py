from collections.abc import AsyncGenerator
from types import TracebackType
from typing import Any, cast

import pytest
from cachetools import TTLCache

from guard_core.handlers.security_headers_handler import (
    SecurityHeadersManager,
    reset_global_state,
)


@pytest.fixture
async def headers_manager() -> AsyncGenerator[SecurityHeadersManager, None]:
    await reset_global_state()
    yield SecurityHeadersManager()
    await reset_global_state()


@pytest.mark.asyncio
async def test_reset_global_state() -> None:
    original_instance = SecurityHeadersManager._instance

    try:
        SecurityHeadersManager._instance = None

        manager = SecurityHeadersManager()
        manager.custom_headers = {"X-Test": "value"}
        manager.enabled = False

        SecurityHeadersManager._instance = None

        await reset_global_state()

        from guard_core.handlers.security_headers_handler import (
            security_headers_manager as new_manager,
        )

        assert new_manager.enabled is True
        assert len(new_manager.custom_headers) == 0

    finally:
        SecurityHeadersManager._instance = original_instance


@pytest.mark.asyncio
async def test_reset_global_state_drops_a_populated_redis_handler_reference() -> None:
    from unittest.mock import AsyncMock, MagicMock

    manager = SecurityHeadersManager()
    manager.redis_handler = AsyncMock()
    manager.redis_handler.get_connection = MagicMock(
        side_effect=RuntimeError("sentinel redis_handler, no real connection")
    )
    manager.agent_handler = AsyncMock()

    await reset_global_state()

    after_reset = SecurityHeadersManager()
    assert after_reset.redis_handler is None
    assert after_reset.agent_handler is None


@pytest.mark.asyncio
async def test_get_headers_with_cached_non_dict_value(
    headers_manager: SecurityHeadersManager,
) -> None:
    headers_manager.enabled = True

    cache_key = headers_manager._generate_cache_key("test_path")

    headers_manager.headers_cache[cache_key] = "invalid_value"

    headers = await headers_manager.get_headers("test_path")

    assert isinstance(headers, dict)
    assert "X-Content-Type-Options" in headers
    assert "X-Frame-Options" in headers

    assert isinstance(headers_manager.headers_cache[cache_key], dict)


@pytest.mark.asyncio
async def test_get_headers_survives_ttl_expiry_between_membership_check_and_read(
    headers_manager: SecurityHeadersManager,
) -> None:
    class _RaceTimer:
        def __init__(self) -> None:
            self._calls = 0

        def __call__(self) -> float:
            self._calls += 1
            return 0.0 if self._calls <= 2 else 300.001

    headers_manager.enabled = True
    original_cache = headers_manager.headers_cache
    headers_manager.headers_cache = TTLCache(maxsize=1000, ttl=300, timer=_RaceTimer())

    try:
        cache_key = headers_manager._generate_cache_key("race_path")
        cached_headers = headers_manager.default_headers.copy()
        headers_manager.headers_cache[cache_key] = cached_headers

        headers = await headers_manager.get_headers("race_path")

        assert isinstance(headers, dict)
        assert headers is cached_headers
        assert "X-Content-Type-Options" in headers
        assert "X-Frame-Options" in headers
    finally:
        headers_manager.headers_cache = original_cache


@pytest.mark.asyncio
async def test_get_headers_returns_cached_dict_on_live_cache_hit(
    headers_manager: SecurityHeadersManager,
) -> None:
    headers_manager.enabled = True

    cache_key = headers_manager._generate_cache_key("live_path")
    cached_headers = {"X-Content-Type-Options": "nosniff", "X-Test-Cache": "hit"}
    headers_manager.headers_cache[cache_key] = cached_headers

    headers = await headers_manager.get_headers("live_path")

    assert headers == cached_headers


@pytest.mark.asyncio
async def test_get_headers_rebuilds_headers_on_cache_miss(
    headers_manager: SecurityHeadersManager,
) -> None:
    headers_manager.enabled = True

    cache_key = headers_manager._generate_cache_key("missing_path")
    assert cache_key not in headers_manager.headers_cache

    headers = await headers_manager.get_headers("missing_path")

    assert headers == headers_manager.default_headers
    assert headers_manager.headers_cache[cache_key] == headers


@pytest.mark.asyncio
async def test_complete_secure_configuration() -> None:
    manager = SecurityHeadersManager()

    manager.configure(
        csp={
            "default-src": ["'self'"],
            "script-src": ["'self'", "https://cdn.example.com"],
            "style-src": ["'self'", "'nonce-abc123'"],
        },
        hsts_max_age=63072000,
        hsts_include_subdomains=True,
        hsts_preload=True,
        cors_origins=["https://app.example.com"],
        cors_allow_credentials=True,
        custom_headers={
            "X-Custom-Security": "enabled",
            "X-Request-ID": "123456",
        },
    )

    headers = await manager.get_headers("/api/endpoint")

    assert "Content-Security-Policy" in headers
    assert "default-src 'self'" in headers["Content-Security-Policy"]

    assert "Strict-Transport-Security" in headers
    hsts = headers["Strict-Transport-Security"]
    assert "max-age=63072000" in hsts
    assert "includeSubDomains" in hsts
    assert "preload" in hsts

    assert headers["X-Custom-Security"] == "enabled"
    assert headers["X-Request-ID"] == "123456"

    cors_headers = await manager.get_cors_headers("https://app.example.com")
    assert cors_headers["Access-Control-Allow-Origin"] == "https://app.example.com"
    assert cors_headers["Access-Control-Allow-Credentials"] == "true"


def test_new_returns_existing_instance_on_subsequent_calls() -> None:
    # Covers the outer "cls._instance is None" False branch, singleton fast path.
    from guard_core.handlers.security_headers_handler import SecurityHeadersManager

    first = SecurityHeadersManager()
    second = SecurityHeadersManager()
    assert first is second


def test_new_handles_race_where_other_thread_populates_instance_while_waiting() -> None:
    from guard_core.handlers.security_headers_handler import SecurityHeadersManager

    original_instance = SecurityHeadersManager._instance
    SecurityHeadersManager._instance = None
    racer_instance = SecurityHeadersManager()
    SecurityHeadersManager._instance = None
    real_lock = SecurityHeadersManager._lock

    class _LockWrapper:
        def __enter__(self) -> None:
            SecurityHeadersManager._instance = racer_instance
            real_lock.__enter__()

        def __exit__(
            self,
            exc_type: type[BaseException] | None,
            exc_val: BaseException | None,
            exc_tb: TracebackType | None,
        ) -> None:
            real_lock.__exit__(exc_type, exc_val, exc_tb)

    cast(Any, SecurityHeadersManager)._lock = _LockWrapper()
    try:
        result = SecurityHeadersManager()
        assert result is racer_instance
    finally:
        cast(Any, SecurityHeadersManager)._lock = real_lock
        SecurityHeadersManager._instance = original_instance


def test_build_hsts_without_include_subdomains_and_preload() -> None:
    from guard_core.handlers.security_headers_handler import SecurityHeadersManager

    mgr = SecurityHeadersManager()
    result = mgr._build_hsts(
        {"max_age": 31536000, "include_subdomains": False, "preload": False}
    )
    assert result == "max-age=31536000"


def test_build_hsts_with_only_include_subdomains() -> None:
    from guard_core.handlers.security_headers_handler import SecurityHeadersManager

    mgr = SecurityHeadersManager()
    result = mgr._build_hsts(
        {"max_age": 31536000, "include_subdomains": True, "preload": False}
    )
    assert "includeSubDomains" in result
    assert "preload" not in result
