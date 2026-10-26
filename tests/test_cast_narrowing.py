import importlib
import logging
from datetime import datetime, timezone
from types import ModuleType, SimpleNamespace

import pytest

from guard_core._pydantic_plugin_mute import get_telemetry_model
from guard_core.core.checks.helpers import (
    _DETECTION_RESULT_STATE_ATTR,
    get_cached_detection_result,
)
from guard_core.core.checks.pipeline import SecurityCheckPipeline
from guard_core.core.initialization._cloud_initialization import (
    CloudInitializationMixin,
)
from guard_core.core.responses.modifier_view import RecordingHeaders
from guard_core.detection_result import DetectionResult
from guard_core.handlers._dynamic_rule_plan import (
    DynamicRulePlan,
    DynamicRulePlanMixin,
)
from guard_core.models import DynamicRules, SecurityConfig
from tests.conftest import MockGuardRequest


def _emergency_rules() -> DynamicRules:
    return DynamicRules(
        rule_id="r",
        version=1,
        timestamp=datetime.now(timezone.utc),
        emergency_mode=True,
    )


def _live_guard_agent() -> ModuleType:
    # other test modules swap sys.modules["guard_agent"]; patch the one
    # get_telemetry_model will import, not the one bound at collection time
    return importlib.import_module("guard_agent")


def test_telemetry_model_that_is_not_a_class_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(_live_guard_agent(), "SecurityEvent", "not a class")
    with pytest.raises(TypeError, match="guard_agent.SecurityEvent is not a class"):
        get_telemetry_model("SecurityEvent")


def test_telemetry_model_that_is_a_plain_class_is_returned_as_is(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(_live_guard_agent(), "SecurityEvent", SimpleNamespace)
    assert get_telemetry_model("SecurityEvent") is SimpleNamespace


def test_telemetry_model_that_is_a_class_is_returned() -> None:
    assert get_telemetry_model("SecurityEvent") is _live_guard_agent().SecurityEvent


async def test_rebuild_error_without_a_config_reraises_the_error() -> None:
    pipeline = SecurityCheckPipeline([])
    error = ValueError("rebuild failed")
    request = MockGuardRequest()
    with pytest.raises(ValueError, match="rebuild failed") as raised:
        await pipeline._handle_rebuild_error(request, error)
    assert raised.value is error


async def test_rebuild_error_with_a_config_still_fails_open() -> None:
    config = SecurityConfig(fail_secure=False)
    pipeline = SecurityCheckPipeline([], config=config)
    assert (
        await pipeline._handle_rebuild_error(MockGuardRequest(), ValueError("x"))
        is None
    )


def test_cloud_ip_store_that_is_none_raises() -> None:
    mixin = CloudInitializationMixin()
    mixin.config = SecurityConfig()
    with pytest.raises(TypeError, match="neither a store nor a store factory"):
        mixin._resolve_cloud_ip_store()


def test_cloud_ip_store_instance_and_factory_resolve() -> None:
    class Store:
        async def get(self, provider: str) -> set[str] | None:
            return None

        async def set(
            self, provider: str, ranges: set[str], ttl: int | None = None
        ) -> None:
            return None

        async def clear(self) -> None:
            return None

    instance = Store()
    mixin = CloudInitializationMixin()
    mixin.redis_handler = SimpleNamespace()
    mixin.config = SecurityConfig(cloud_ip_store=instance)
    assert mixin._resolve_cloud_ip_store() is instance
    mixin.config = SecurityConfig(cloud_ip_store=lambda redis: instance)
    assert mixin._resolve_cloud_ip_store() is instance


def test_emergency_threshold_that_is_not_an_int_raises() -> None:
    plan = DynamicRulePlan(state={"auto_ban_threshold": "5"})
    mixin = DynamicRulePlanMixin()
    mixin.logger = logging.getLogger("guard_core")
    rules = _emergency_rules()
    with pytest.raises(TypeError, match="auto_ban_threshold must be an int"):
        mixin._plan_emergency_mode(plan, rules)


def test_emergency_threshold_that_is_an_int_is_halved() -> None:
    plan = DynamicRulePlan(state={"auto_ban_threshold": 9})
    mixin = DynamicRulePlanMixin()
    mixin.logger = logging.getLogger("guard_core")
    mixin._plan_emergency_mode(plan, _emergency_rules())
    assert plan.state["auto_ban_threshold"] == 4


def test_recording_headers_append_on_headers_without_append_raises() -> None:
    headers = RecordingHeaders({})
    with pytest.raises(AttributeError, match="no attribute 'append'"):
        headers.append("x", "1")


def test_recording_headers_append_is_recorded_and_undone() -> None:
    class Appendable(dict[str, str]):
        def append(self, key: str, value: str) -> None:
            self[key] = value

    real = Appendable(a="1")
    headers = RecordingHeaders(real)
    headers.append("b", "2")
    assert real == {"a": "1", "b": "2"}
    headers.undo()
    assert real == {"a": "1"}


async def test_cached_detection_that_is_not_a_result_is_recomputed() -> None:
    config = SecurityConfig(enable_penetration_detection=False)
    request = MockGuardRequest()
    setattr(
        request.state,
        _DETECTION_RESULT_STATE_ATTR,
        (request, None, "not a result"),
    )
    result = await get_cached_detection_result(
        request, None, config, lambda *_args: True
    )
    assert isinstance(result, DetectionResult)
    assert result.is_threat is False


async def test_cached_detection_result_is_returned_as_is() -> None:
    config = SecurityConfig(enable_penetration_detection=False)
    request = MockGuardRequest()
    cached = DetectionResult(is_threat=True, trigger_info="cached")
    setattr(request.state, _DETECTION_RESULT_STATE_ATTR, (request, None, cached))
    assert (
        await get_cached_detection_result(request, None, config, lambda *_args: True)
        is cached
    )
