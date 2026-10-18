import logging
from unittest.mock import AsyncMock, MagicMock

import pytest

from guard_core.handlers.security_headers_handler import security_headers_manager
from guard_core.models import SecurityConfig


def _config(**security_headers: object) -> SecurityConfig:
    return SecurityConfig(
        enable_redis=False, security_headers={"enabled": True, **security_headers}
    )


def test_equal_content_gives_one_key_whatever_the_config_object() -> None:
    first, second = _config(frame_options="DENY"), _config(frame_options="DENY")

    assert security_headers_manager._generate_cache_key(
        "/a", first
    ) == security_headers_manager._generate_cache_key("/a", second)


def test_different_content_gives_different_keys() -> None:
    deny, same = _config(frame_options="DENY"), _config()

    assert security_headers_manager._generate_cache_key(
        "/a", deny
    ) != security_headers_manager._generate_cache_key("/a", same)


def test_the_key_never_depends_on_the_object_identity() -> None:
    config = _config()

    key = security_headers_manager._generate_cache_key("/a", config)

    assert str(id(config)) not in key


def test_the_key_does_not_depend_on_the_request_path() -> None:
    config = _config()

    assert security_headers_manager._generate_cache_key(
        "/a", config
    ) == security_headers_manager._generate_cache_key("/b/c", config)


def test_the_legacy_no_config_key_is_still_default() -> None:
    assert security_headers_manager._generate_cache_key(None, None) == "default"


async def test_a_freed_config_never_leaks_its_headers_to_a_later_default() -> None:
    manager = security_headers_manager
    first = _config(frame_options="DENY", csp={"default-src": ["'none'"]})
    await manager.get_headers("/x", config=first)
    del first

    later = SecurityConfig(enable_redis=False)
    headers = await manager.get_headers("/x", config=later)

    assert headers["X-Frame-Options"] == "SAMEORIGIN"
    assert "Content-Security-Policy" not in headers


async def test_a_config_changed_in_place_serves_the_new_headers() -> None:
    config = _config(frame_options="DENY")
    assert (await security_headers_manager.get_headers("/x", config=config))[
        "X-Frame-Options"
    ] == "DENY"

    config.security_headers = {"enabled": True, "frame_options": "SAMEORIGIN"}

    assert (await security_headers_manager.get_headers("/x", config=config))[
        "X-Frame-Options"
    ] == "SAMEORIGIN"


async def test_many_paths_share_one_cache_entry() -> None:
    config = _config()

    for index in range(2000):
        await security_headers_manager.get_headers(f"/p/{index}", config=config)

    assert len(security_headers_manager.headers_cache) == 1


async def test_the_cache_stays_bounded_over_many_distinct_configs() -> None:
    maxsize = int(security_headers_manager.headers_cache.maxsize)

    for index in range(maxsize + 50):
        config = _config(custom={"X-Index": str(index)})
        await security_headers_manager.get_headers("/x", config=config)

    assert len(security_headers_manager.headers_cache) <= maxsize


async def test_many_paths_send_one_agent_event() -> None:
    agent = MagicMock()
    agent.send_event = AsyncMock()
    security_headers_manager.agent_handler = agent
    config = _config()

    for index in range(50):
        await security_headers_manager.get_headers(f"/p/{index}", config=config)

    assert agent.send_event.await_count == 1


async def test_the_unsafe_csp_warning_is_logged_once_not_per_path(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = _config(csp={"script-src": ["'self'", "'unsafe-inline'"]})

    with caplog.at_level(
        logging.WARNING, logger="guard_core.handlers.security_headers"
    ):
        for index in range(20):
            await security_headers_manager.get_headers(f"/p/{index}", config=config)

    unsafe = [r for r in caplog.records if "unsafe sources" in r.getMessage()]
    assert len(unsafe) == 1
