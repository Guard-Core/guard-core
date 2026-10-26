import builtins
import logging
import sys
from collections.abc import Mapping, Sequence
from types import ModuleType
from typing import Any

import pytest

import guard_core
from guard_core import _pydantic_plugin_mute


def test_pytest_configure_eagerly_mutes_pydantic_plugin_instrumentation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from tests.conftest import (
        _GUARD_AGENT_FINDER_ATTR,
        pytest_configure,
    )

    saved_finder = getattr(sys, _GUARD_AGENT_FINDER_ATTR, None)
    monkeypatch.delattr(sys, _GUARD_AGENT_FINDER_ATTR, raising=False)
    spy_calls: list[bool] = []
    monkeypatch.setattr(
        _pydantic_plugin_mute,
        "_mute_pydantic_plugin_instrumentation",
        lambda: spy_calls.append(True),
    )

    try:
        pytest_configure(pytest.Config.fromdictargs({}, ["tests/test_x.py"]))
    finally:
        new_finder = getattr(sys, _GUARD_AGENT_FINDER_ATTR, None)
        if new_finder is not None and new_finder in sys.meta_path:
            sys.meta_path.remove(new_finder)
        if saved_finder is not None:
            setattr(sys, _GUARD_AGENT_FINDER_ATTR, saved_finder)
        else:
            monkeypatch.delattr(sys, _GUARD_AGENT_FINDER_ATTR, raising=False)

    assert spy_calls == [True]


def test_mute_pydantic_instrumentation_is_noop_without_agent_extra(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When the guard-agent extra is not installed, muting the telemetry models'
    pydantic-plugin instrumentation must be a clean no-op, not an ImportError."""
    monkeypatch.setattr(_pydantic_plugin_mute, "_applied", False)

    real_import = builtins.__import__

    def fake_import(
        name: str,
        globals: Mapping[str, object] | None = None,
        locals: Mapping[str, object] | None = None,
        fromlist: Sequence[str] = (),
        level: int = 0,
    ) -> ModuleType:
        if name == "guard_agent.models":
            raise ImportError("guard-agent extra not installed")
        return real_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", fake_import)

    guard_core._mute_pydantic_plugin_instrumentation()


def test_mute_pydantic_instrumentation_survives_rebuild_failure(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A guard-agent model that cannot be force-rebuilt must degrade to
    instrumentation-left-on instead of crashing."""
    from guard_agent.models import SecurityEvent

    monkeypatch.setattr(_pydantic_plugin_mute, "_applied", False)

    def boom(*args: object, **kwargs: object) -> None:
        raise RuntimeError("rebuild failed")

    monkeypatch.setattr(SecurityEvent, "model_rebuild", boom)

    with caplog.at_level(logging.WARNING, logger="guard_core"):
        guard_core._mute_pydantic_plugin_instrumentation()

    assert "Could not opt guard-agent telemetry models" in caplog.text
    assert _pydantic_plugin_mute._applied is False


def test_mute_pydantic_instrumentation_survives_a_none_plugin_settings(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    from guard_agent.models import SecurityEvent

    monkeypatch.setattr(_pydantic_plugin_mute, "_applied", False)
    monkeypatch.setitem(SecurityEvent.model_config, "plugin_settings", None)

    with caplog.at_level(logging.WARNING, logger="guard_core"):
        guard_core._mute_pydantic_plugin_instrumentation()

    assert "Could not opt guard-agent telemetry models" not in caplog.text
    assert SecurityEvent.model_config.get("plugin_settings") == {
        "logfire": {"record": "off"}
    }
    assert _pydantic_plugin_mute._applied is True


def test_mute_pydantic_instrumentation_is_idempotent_after_first_success(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A second call in the same process must not re-run `model_rebuild`;
    only the first call in the process does any work."""
    from guard_agent.models import EventBatch, SecurityEvent, SecurityMetric

    monkeypatch.setattr(_pydantic_plugin_mute, "_applied", False)

    rebuild_calls: list[str] = []

    def _count_rebuild(model: type[Any]) -> None:
        original = model.model_rebuild

        def wrapper(*args: object, **kwargs: object) -> Any:
            rebuild_calls.append(model.__name__)
            return original(*args, **kwargs)

        monkeypatch.setattr(model, "model_rebuild", wrapper)

    for model in (SecurityEvent, SecurityMetric, EventBatch):
        _count_rebuild(model)

    guard_core._mute_pydantic_plugin_instrumentation()
    assert len(rebuild_calls) == 3

    guard_core._mute_pydantic_plugin_instrumentation()
    assert len(rebuild_calls) == 3


def test_mute_pydantic_instrumentation_retries_all_models_after_a_failed_call(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A rebuild failure must not leave the applied flag set, or later models
    in the tuple stay permanently un-muted with no error and no retry. The
    next call must retry and actually mute all three models."""
    from guard_agent.models import EventBatch, SecurityEvent, SecurityMetric

    monkeypatch.setattr(_pydantic_plugin_mute, "_applied", False)

    original_rebuild = SecurityEvent.model_rebuild

    def boom(*args: object, **kwargs: object) -> None:
        raise RuntimeError("rebuild failed")

    monkeypatch.setattr(SecurityEvent, "model_rebuild", boom)
    guard_core._mute_pydantic_plugin_instrumentation()
    applied_after_failure = _pydantic_plugin_mute._applied
    assert applied_after_failure is False

    monkeypatch.setattr(SecurityEvent, "model_rebuild", original_rebuild)
    guard_core._mute_pydantic_plugin_instrumentation()
    applied_after_retry = _pydantic_plugin_mute._applied
    assert applied_after_retry is True

    for model in (SecurityEvent, SecurityMetric, EventBatch):
        assert model.model_config.get("plugin_settings") == {
            "logfire": {"record": "off"}
        }
