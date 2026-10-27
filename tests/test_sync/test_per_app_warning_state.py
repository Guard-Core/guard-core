import io
import logging

import pytest

from guard_core import _staged_defaults
from guard_core._security_headers_override import (
    PULLED_OVERRIDES,
    CorsParams,
    OverrideRecord,
    config_fingerprint,
)
from guard_core.models import SyncSecurityConfig
from guard_core.sync.handlers import _ipban_sharing
from guard_core.sync.handlers.ipban_handler import IPBanManager
from guard_core.sync.handlers.security_headers_handler import SecurityHeadersManager

CHANGED_DEFAULTS = "guard-core 5.0.0 changed defaults"
NOT_ENFORCED = "is not enforced for the app"


@pytest.fixture(autouse=True)
def _nothing_logged_yet() -> None:
    _staged_defaults._changed_defaults_logged.clear()
    _ipban_sharing._warned_unenforced_bans.clear()


def _logged_by(name: str) -> tuple[logging.Logger, io.StringIO]:
    stream = io.StringIO()
    logger = logging.getLogger(name)
    logger.addHandler(logging.StreamHandler(stream))
    return logger, stream


def test_every_app_logs_its_own_changed_defaults() -> None:
    logger, stream = _logged_by("guard_core.models")
    handler = logger.handlers[-1]
    try:
        SyncSecurityConfig(enable_redis=False)
        after_first = stream.getvalue().count(CHANGED_DEFAULTS)
        SyncSecurityConfig(enable_redis=False)
        after_second = stream.getvalue().count(CHANGED_DEFAULTS)
    finally:
        logger.removeHandler(handler)

    assert (after_first, after_second) == (1, 2)


def test_one_app_logs_its_changed_defaults_once() -> None:
    logger, stream = _logged_by("guard_core.models")
    handler = logger.handlers[-1]
    try:
        config = SyncSecurityConfig(enable_redis=False)
        config.rate_limit = 120
        config.enable_rate_limiting = True
    finally:
        logger.removeHandler(handler)

    assert stream.getvalue().count(CHANGED_DEFAULTS) == 1


def test_every_app_logs_its_own_unenforced_ban(
    caplog: pytest.LogCaptureFixture,
) -> None:
    manager = IPBanManager()
    first = SyncSecurityConfig(enable_redis=False, redis_prefix="warn-first:")
    second = SyncSecurityConfig(enable_redis=False, redis_prefix="warn-second:")

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


def test_an_override_pulled_for_one_app_does_not_slow_another_app(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first = SyncSecurityConfig(
        enable_redis=False, enable_cors=True, cors_allow_origins=["https://a.test"]
    )
    second = SyncSecurityConfig(
        enable_redis=False, enable_cors=True, cors_allow_origins=["https://b.test"]
    )
    manager = SecurityHeadersManager()
    merges: list[int] = []
    merge = manager.cors_params_for

    def counting(
        config: SyncSecurityConfig, current: OverrideRecord | None = None
    ) -> CorsParams:
        merges.append(1)
        return merge(config, current)

    monkeypatch.setattr(manager, "cors_params_for", counting)
    monkeypatch.setitem(
        PULLED_OVERRIDES,
        config_fingerprint(first),
        OverrideRecord(5.0, {"enabled": True}),
    )

    headers = manager.get_cors_headers(
        "https://b.test", second, OverrideRecord(0.0, {})
    )

    assert headers["Access-Control-Allow-Origin"] == "https://b.test"
    assert merges == []
