import json
import logging
from collections.abc import AsyncGenerator
from typing import Any
from unittest.mock import AsyncMock

import pytest

from guard_core.handlers.security_headers_handler import SecurityHeadersManager

OWN_CSP = {"default-src": ["'self'"]}
OWN_HSTS = {"max_age": 63072000, "include_subdomains": True, "preload": False}


@pytest.fixture
async def manager() -> AsyncGenerator[SecurityHeadersManager, None]:
    isolated = SecurityHeadersManager.isolated()
    isolated.csp_config = dict(OWN_CSP)
    isolated.hsts_config = dict(OWN_HSTS)
    yield isolated


async def _load(
    manager: SecurityHeadersManager, csp: object = None, hsts: object = None
) -> None:
    redis = AsyncMock()
    redis.get_key = AsyncMock(
        side_effect=[
            None if csp is None else json.dumps(csp),
            None if hsts is None else json.dumps(hsts),
            None,
        ]
    )
    manager.redis_handler = redis
    await manager._load_cached_config()


BAD_CSP: list[Any] = [
    {"default-src": ["'self'\r\nSet-Cookie: x=1"]},
    {"default-src": ["'self'\nX: y"]},
    {"default-src": ["'self'; script-src evil.example"]},
    {"default-src": ["'self', default-src evil.example"]},
    {"default-src 'none'; script-src": ["evil.example"]},
    {"default-src, script-src": ["'self'"]},
    {"default-src\r\nX": ["'self'"]},
    {"": ["'self'"]},
    {"default-src": ["'self'\x00"]},
    {"default-src": "'self'"},
    {"default-src": [1]},
    ["default-src"],
    "default-src 'self'",
]


@pytest.mark.parametrize("record", BAD_CSP)
async def test_an_invalid_cached_csp_is_dropped_and_the_own_config_kept(
    manager: SecurityHeadersManager,
    caplog: pytest.LogCaptureFixture,
    record: object,
) -> None:
    with caplog.at_level(logging.WARNING):
        await _load(manager, csp=record)

    assert manager.csp_config == OWN_CSP
    ignored = [m for m in caplog.messages if "cached csp_config" in m]
    assert len(ignored) == 1
    assert "\r" not in ignored[0]
    assert "\n" not in ignored[0]


BAD_HSTS: list[Any] = [
    {"max_age": -1},
    {"max_age": "31536000; includeSubDomains\r\nX: y"},
    {"max_age": True},
    {"max_age": 1.5},
    {"include_subdomains": True},
    {"max_age": 60, "include_subdomains": "yes"},
    {"max_age": 60, "preload": 1},
    [60],
    "max-age=60",
]


@pytest.mark.parametrize("record", BAD_HSTS)
async def test_an_invalid_cached_hsts_is_dropped_and_the_own_config_kept(
    manager: SecurityHeadersManager,
    caplog: pytest.LogCaptureFixture,
    record: object,
) -> None:
    with caplog.at_level(logging.WARNING):
        await _load(manager, hsts=record)

    assert manager.hsts_config == OWN_HSTS
    ignored = [m for m in caplog.messages if "cached hsts_config" in m]
    assert len(ignored) == 1
    assert "\r" not in ignored[0]
    assert "\n" not in ignored[0]


async def test_an_invalid_csp_does_not_stop_a_valid_hsts_from_loading(
    manager: SecurityHeadersManager,
) -> None:
    await _load(
        manager,
        csp={"default-src": ["'self';evil"]},
        hsts={"max_age": 60, "include_subdomains": False, "preload": False},
    )

    assert manager.csp_config == OWN_CSP
    assert manager.hsts_config == {
        "max_age": 60,
        "include_subdomains": False,
        "preload": False,
    }


async def test_valid_cached_records_still_load(
    manager: SecurityHeadersManager, caplog: pytest.LogCaptureFixture
) -> None:
    csp = {
        "default-src": ["'self'"],
        "script-src": ["'self'", "https://cdn.example.com", "'nonce-abc123'"],
        "upgrade-insecure-requests": [],
    }
    hsts = {"max_age": 0, "include_subdomains": False, "preload": False}

    with caplog.at_level(logging.WARNING):
        await _load(manager, csp=csp, hsts=hsts)

    assert manager.csp_config == csp
    assert manager.hsts_config == hsts
    assert caplog.messages == []


async def test_a_record_without_the_optional_flags_loads(
    manager: SecurityHeadersManager,
) -> None:
    await _load(manager, hsts={"max_age": 31536000})

    assert manager.hsts_config == {"max_age": 31536000}
