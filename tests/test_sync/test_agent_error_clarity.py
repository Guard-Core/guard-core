import logging
from typing import Any
from unittest.mock import MagicMock

import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.sync.core.events.middleware_events import SecurityEventBus
from guard_core.sync.utils import invoke_error_hook


def test_agent_strict_defaults_false() -> None:
    assert SyncSecurityConfig().agent_strict is False


def test_on_error_defaults_none() -> None:
    assert SyncSecurityConfig().on_error is None


def test_on_error_accepts_callable() -> None:
    def hook(stage: str, exc: BaseException, ctx: dict[str, Any]) -> None:
        pass

    config = SyncSecurityConfig(on_error=hook)
    assert config.on_error is hook


def test_invoke_error_hook_forwards_stage_exc_context() -> None:
    calls: list[tuple[str, BaseException, dict[str, Any]]] = []
    err = ValueError("boom")

    invoke_error_hook(
        lambda s, e, c: calls.append((s, e, c)), "agent_init", err, {"k": "v"}
    )

    assert calls == [("agent_init", err, {"k": "v"})]


def test_invoke_error_hook_none_is_noop() -> None:
    invoke_error_hook(None, "geoip", ValueError("x"), {})


def test_invoke_error_hook_swallows_raising_hook(
    caplog: pytest.LogCaptureFixture,
) -> None:
    def bad_hook(stage: str, exc: BaseException, ctx: dict[str, Any]) -> None:
        raise RuntimeError("hook failed")

    with caplog.at_level(logging.ERROR):
        invoke_error_hook(bad_hook, "geoip", ValueError("x"), {})

    assert any("on_error hook raised" in r.message for r in caplog.records)


def test_geoip_lookup_failure_logs_and_fires_hook(
    caplog: pytest.LogCaptureFixture,
) -> None:
    captured: list[tuple[str, BaseException, dict[str, Any]]] = []
    config = SyncSecurityConfig(on_error=lambda s, e, c: captured.append((s, e, c)))
    geo = MagicMock()
    geo.get_country = MagicMock(side_effect=RuntimeError("geo down"))
    bus = SecurityEventBus(agent_handler=None, config=config, geo_ip_handler=geo)

    with caplog.at_level(logging.WARNING):
        result = bus._lookup_country("1.2.3.4")

    assert result is None
    assert any("GeoIP lookup failed" in r.message for r in caplog.records)
    assert len(captured) == 1
    assert captured[0][0] == "geoip"
    assert captured[0][2] == {"client_ip": "1.2.3.4"}
