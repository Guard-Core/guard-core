import logging
from collections.abc import Iterator
from typing import Any

import pytest
from pydantic import ValidationError

from guard_core._security_config_batch import prepare_config_batch
from guard_core.models import BehaviorRuleConfig, SyncSecurityConfig
from guard_core.sync.decorators.base import BaseSecurityDecorator
from guard_core.sync.decorators.content_filtering import ContentFilteringMixin
from guard_core.sync.detection_engine.monitor_types import PatternStats
from guard_core.sync.handlers.suspatterns_handler import sus_patterns_manager_for

APP_B_NAME = "zebratok"
DEFAULT_NAME = "password"
ARBITER_PATTERN = r"(\b|\W+)*{name}=[a-z]{{8}}"
VALIDATOR_PATTERN = r"(a+)+{name}=hunter2"
PLAIN_PATTERN = r"{name}=[a-z]{{8}}"


class _Decorator(BaseSecurityDecorator, ContentFilteringMixin):
    pass


def _app(**settings: object) -> SyncSecurityConfig:
    return SyncSecurityConfig(enable_redis=False, lazy_init=False, **settings)


def _app_b(**settings: object) -> SyncSecurityConfig:
    return _app(log_sensitive_params=frozenset({APP_B_NAME}), **settings)


def _bound_app_b(default_app: SyncSecurityConfig) -> SyncSecurityConfig:
    sus_patterns_manager_for(default_app, bind=True)
    config = _app_b()
    sus_patterns_manager_for(config, bind=True)
    return config


@pytest.fixture
def app_b() -> Iterator[SyncSecurityConfig]:
    # The default manager serves its first app weakly: keep that app alive so
    # app B gets a manager of its own.
    default_app = _app()
    yield _bound_app_b(default_app)


def _monitor_of(config: SyncSecurityConfig) -> Any:
    monitor = sus_patterns_manager_for(config)._performance_monitor
    assert monitor is not None
    return monitor


def _no_adversarial_trigger(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "guard_core.sync.detection_engine._redos_cost_arbiter."
        "_reach_probe_candidate_builders",
        lambda _pattern, _flags, _deadline: [],
    )


@pytest.mark.parametrize("name", [APP_B_NAME, DEFAULT_NAME])
def test_the_arbiter_log_redacts_the_names_of_the_app_that_validates(
    name: str,
    app_b: SyncSecurityConfig,
    caplog: pytest.LogCaptureFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = app_b
    pattern = ARBITER_PATTERN.format(name=name)
    _no_adversarial_trigger(monkeypatch)
    compiler = sus_patterns_manager_for(config)._compiler
    assert compiler is not None

    with caplog.at_level(logging.WARNING, logger="guard_core.sync.detection_engine"):
        compiler.validate_pattern_safety(pattern)

    assert "structural rule flagged" in caplog.text
    assert pattern not in caplog.text
    assert "[REDACTED]" in caplog.text


@pytest.mark.parametrize("name", [APP_B_NAME, DEFAULT_NAME])
def test_the_monitor_report_redacts_the_names_of_its_app(
    name: str, app_b: SyncSecurityConfig
) -> None:
    monitor = _monitor_of(app_b)
    pattern = PLAIN_PATTERN.format(name=name)
    monitor.pattern_stats[pattern] = PatternStats(pattern=pattern)

    report = monitor.get_pattern_report(pattern)

    assert report is not None
    assert report["pattern"] == "[REDACTED]"


@pytest.mark.parametrize("name", [APP_B_NAME, DEFAULT_NAME])
def test_the_monitor_anomaly_data_redacts_the_names_of_its_app(
    name: str, app_b: SyncSecurityConfig
) -> None:
    monitor = _monitor_of(app_b)
    pattern = PLAIN_PATTERN.format(name=name)

    safe = monitor._sanitize_anomaly_data({"type": "timeout", "pattern": pattern})

    assert safe["pattern"] == "[REDACTED]"


class _CapturingAgent:
    def __init__(self) -> None:
        self.events: list[Any] = []

    def send_event(self, event: Any) -> None:
        self.events.append(event)


@pytest.mark.parametrize("name", [APP_B_NAME, DEFAULT_NAME])
def test_the_monitor_anomaly_event_redacts_the_names_of_its_app(
    name: str, app_b: SyncSecurityConfig
) -> None:
    monitor = _monitor_of(app_b)
    pattern = PLAIN_PATTERN.format(name=name)
    agent = _CapturingAgent()

    monitor._send_anomaly_event({"type": "timeout", "pattern": pattern}, agent, None)

    assert agent.events[0].metadata["pattern"] == "[REDACTED]"


@pytest.mark.parametrize("name", [APP_B_NAME, DEFAULT_NAME])
def test_the_blocked_user_agents_error_redacts_the_names_of_its_config(
    name: str,
) -> None:
    pattern = VALIDATOR_PATTERN.format(name=name)

    with pytest.raises(ValueError, match="rejected by ReDoS validator") as excinfo:
        _app_b(blocked_user_agents=[pattern])

    assert f"{name}=hunter2" not in str(excinfo.value)
    assert "[REDACTED]" in str(excinfo.value)


def test_the_blocked_user_agents_construction_error_keeps_its_location() -> None:
    pattern = VALIDATOR_PATTERN.format(name=APP_B_NAME)

    with pytest.raises(ValidationError, match="rejected by ReDoS validator") as excinfo:
        _app_b(blocked_user_agents=[pattern])

    assert excinfo.value.errors()[0]["loc"] == ("blocked_user_agents",)
    assert f"{APP_B_NAME}=hunter2" not in str(excinfo.value)
    assert "[REDACTED]" in str(excinfo.value)


def test_the_blocked_user_agents_copy_error_redacts_the_names_of_its_config() -> None:
    config = _app_b()
    pattern = VALIDATOR_PATTERN.format(name=APP_B_NAME)

    with pytest.raises(ValueError, match="rejected by ReDoS validator") as excinfo:
        config.model_copy(update={"blocked_user_agents": [pattern]})

    assert f"{APP_B_NAME}=hunter2" not in str(excinfo.value)
    assert "[REDACTED]" in str(excinfo.value)


def test_the_blocked_user_agents_batch_error_redacts_the_pending_names() -> None:
    config = _app()
    pattern = VALIDATOR_PATTERN.format(name=APP_B_NAME)
    values = {
        "blocked_user_agents": [pattern],
        "log_sensitive_params": frozenset({APP_B_NAME}),
    }

    with pytest.raises(ValueError, match="rejected by ReDoS validator") as excinfo:
        prepare_config_batch(config, values, set(values))

    assert f"{APP_B_NAME}=hunter2" not in str(excinfo.value)
    assert "[REDACTED]" in str(excinfo.value)


@pytest.mark.parametrize("name", [APP_B_NAME, DEFAULT_NAME])
def test_the_blocked_user_agents_reassignment_error_redacts_the_names_of_its_config(
    name: str,
) -> None:
    config = _app_b()

    with pytest.raises(ValueError, match="rejected by ReDoS validator") as excinfo:
        config.blocked_user_agents = [VALIDATOR_PATTERN.format(name=name)]

    assert f"{name}=hunter2" not in str(excinfo.value)
    assert "[REDACTED]" in str(excinfo.value)


@pytest.mark.parametrize("name", [APP_B_NAME, DEFAULT_NAME])
def test_the_return_pattern_error_redacts_the_names_of_its_config(name: str) -> None:
    rule = BehaviorRuleConfig(
        rule_type="return_pattern", threshold=3, pattern=f"{name}=hunter2"
    )

    with pytest.raises(ValueError, match="requires reading the response body") as exc:
        _app_b(behavior_scan_response_body=False, global_behavior_rules=[rule])

    assert f"{name}=hunter2" not in str(exc.value)
    assert "[REDACTED]" in str(exc.value)


@pytest.mark.parametrize("name", [APP_B_NAME, DEFAULT_NAME])
def test_the_block_user_agents_decorator_error_redacts_the_names_of_its_config(
    name: str,
) -> None:
    decorator = _Decorator(_app_b())

    with pytest.raises(ValueError, match="rejected by ReDoS validator") as excinfo:
        decorator.block_user_agents([VALIDATOR_PATTERN.format(name=name)])

    assert f"{name}=hunter2" not in str(excinfo.value)
    assert "[REDACTED]" in str(excinfo.value)
