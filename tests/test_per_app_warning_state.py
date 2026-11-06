import io
import logging
import types
from typing import Any, cast

import pytest

from guard_core import _staged_defaults
from guard_core._security_headers_override import (
    PULLED_OVERRIDES,
    CorsParams,
    OverrideRecord,
    config_fingerprint,
)
from guard_core._utils import body_reader
from guard_core.handlers import _ipban_sharing
from guard_core.handlers.ipban_handler import IPBanManager
from guard_core.handlers.security_headers_handler import SecurityHeadersManager
from guard_core.models import SecurityConfig

CHANGED_DEFAULTS = "guard-core 5.0.0 changed defaults"
NOT_ENFORCED = "is not enforced for the app"
NO_BOUNDED_READER = "neither read_body_prefix_until_idle"
PREFIX_ONLY_READER = "has no read_body_prefix_until_idle"


@pytest.fixture(autouse=True)
def _nothing_logged_yet() -> None:
    _staged_defaults._changed_defaults_logged.clear()
    _ipban_sharing._warned_unenforced_bans.clear()
    body_reader._fallback_warned_kinds.clear()
    body_reader._reader_kind_by_class.clear()


def _logged_by(name: str) -> tuple[logging.Logger, io.StringIO]:
    stream = io.StringIO()
    logger = logging.getLogger(name)
    logger.addHandler(logging.StreamHandler(stream))
    return logger, stream


def test_every_app_logs_its_own_changed_defaults() -> None:
    logger, stream = _logged_by("guard_core.models")
    handler = logger.handlers[-1]
    try:
        SecurityConfig(enable_redis=False)
        after_first = stream.getvalue().count(CHANGED_DEFAULTS)
        SecurityConfig(enable_redis=False)
        after_second = stream.getvalue().count(CHANGED_DEFAULTS)
    finally:
        logger.removeHandler(handler)

    assert (after_first, after_second) == (1, 2)


def test_one_app_logs_its_changed_defaults_once() -> None:
    logger, stream = _logged_by("guard_core.models")
    handler = logger.handlers[-1]
    try:
        config = SecurityConfig(enable_redis=False)
        config.rate_limit = 120
        config.enable_rate_limiting = True
    finally:
        logger.removeHandler(handler)

    assert stream.getvalue().count(CHANGED_DEFAULTS) == 1


def test_every_app_logs_its_own_unenforced_ban(
    caplog: pytest.LogCaptureFixture,
) -> None:
    manager = IPBanManager()
    first = SecurityConfig(enable_redis=False, redis_prefix="warn-first:")
    second = SecurityConfig(enable_redis=False, redis_prefix="warn-second:")

    with caplog.at_level(logging.WARNING):
        assert manager._ban_stands_for("127.0.0.1", first) is False
        assert manager._ban_stands_for("127.0.0.1", first) is False
        assert manager._ban_stands_for("127.0.0.1", second) is False

    warnings = [
        r.getMessage() for r in caplog.records if NOT_ENFORCED in r.getMessage()
    ]
    assert len(warnings) == 2
    assert "warn-first:" in warnings[0]
    assert "warn-second:" in warnings[1]


async def test_an_override_pulled_for_one_app_does_not_slow_another_app(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first = SecurityConfig(
        enable_redis=False, enable_cors=True, cors_allow_origins=["https://a.test"]
    )
    second = SecurityConfig(
        enable_redis=False, enable_cors=True, cors_allow_origins=["https://b.test"]
    )
    manager = SecurityHeadersManager()
    merges: list[int] = []
    merge = manager.cors_params_for

    def counting(
        config: SecurityConfig, current: OverrideRecord | None = None
    ) -> CorsParams:
        merges.append(1)
        return merge(config, current)

    monkeypatch.setattr(manager, "cors_params_for", counting)
    monkeypatch.setitem(
        PULLED_OVERRIDES,
        config_fingerprint(first),
        OverrideRecord(5.0, {"enabled": True}),
    )

    headers = await manager.get_cors_headers(
        "https://b.test", second, OverrideRecord(0.0, {})
    )

    assert headers["Access-Control-Allow-Origin"] == "https://b.test"
    assert merges == []


class _BodyOnlyRequest:
    method = "POST"

    def __init__(self) -> None:
        self.headers = {"content-type": "text/plain", "content-length": "4"}
        self.state = types.SimpleNamespace()

    async def body(self) -> bytes:
        return b"abcd"


class _PrefixOnlyRequest(_BodyOnlyRequest):
    async def read_body_prefix(self, max_bytes: int) -> bytes:
        return b"abcd"


async def _read_as(request: object, config: SecurityConfig) -> None:
    await body_reader.read_body_for_inspection(
        cast(Any, request), config, "203.0.113.7", 1024
    )


@pytest.mark.parametrize(
    ("request_class", "needle"),
    [(_BodyOnlyRequest, NO_BOUNDED_READER), (_PrefixOnlyRequest, PREFIX_ONLY_READER)],
)
async def test_every_app_logs_its_own_body_reader_fallback(
    caplog: pytest.LogCaptureFixture, request_class: type, needle: str
) -> None:
    first = SecurityConfig(enable_redis=False)
    second = SecurityConfig(enable_redis=False)

    with caplog.at_level(logging.WARNING, logger="guard_core"):
        await _read_as(request_class(), first)
        await _read_as(request_class(), first)
        after_first = len([r for r in caplog.records if needle in r.getMessage()])
        await _read_as(request_class(), second)
        await _read_as(request_class(), second)

    after_second = len([r for r in caplog.records if needle in r.getMessage()])
    assert (after_first, after_second) == (1, 2)


async def test_one_app_logs_each_body_reader_fallback_kind_once(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = SecurityConfig(enable_redis=False)

    with caplog.at_level(logging.WARNING, logger="guard_core"):
        for request_class in (_BodyOnlyRequest, _PrefixOnlyRequest):
            for _ in range(3):
                await _read_as(request_class(), config)

    messages = [r.getMessage() for r in caplog.records]
    assert sum(NO_BOUNDED_READER in m for m in messages) == 1
    assert sum(PREFIX_ONLY_READER in m for m in messages) == 1
