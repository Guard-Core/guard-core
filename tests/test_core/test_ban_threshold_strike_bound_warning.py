import logging
import warnings
from typing import Any
from unittest.mock import MagicMock

import pytest

from guard_core.core.initialization.handler_initializer import HandlerInitializer
from guard_core.models import SecurityConfig, ThreatBanConfig

CAP = 610


async def _initialize(**overrides: Any) -> None:
    config = SecurityConfig(
        enable_redis=False,
        enable_penetration_detection=False,
        rate_limit=10,
        rate_limit_window=60,
        **overrides,
    )
    await HandlerInitializer(config).initialize_redis_handlers()


async def _startup_warnings(
    caplog: pytest.LogCaptureFixture, **overrides: Any
) -> list[str]:
    overrides.setdefault("fail_on_misconfiguration", False)
    with caplog.at_level(logging.WARNING, logger="guard_core"):
        with warnings.catch_warnings():
            warnings.simplefilter("error")
            await _initialize(**overrides)
    return [
        record.getMessage()
        for record in caplog.records
        if "can never fire" in record.getMessage()
    ]


async def test_auto_ban_threshold_at_the_cap_does_not_warn(
    caplog: pytest.LogCaptureFixture,
) -> None:
    assert await _startup_warnings(caplog, auto_ban_threshold=CAP) == []


async def test_auto_ban_threshold_above_the_cap_warns_once_naming_the_field(
    caplog: pytest.LogCaptureFixture,
) -> None:
    messages = await _startup_warnings(caplog, auto_ban_threshold=CAP + 1)

    assert len(messages) == 1
    assert "auto_ban_threshold" in messages[0]
    assert str(CAP + 1) in messages[0]
    assert "610" in messages[0]
    assert "fail_on_misconfiguration=False keeps starting" in messages[0]


async def test_threat_ban_config_threshold_at_the_cap_does_not_warn(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = {"honeypot": {"threshold": CAP, "duration": 60}}

    assert await _startup_warnings(caplog, threat_ban_config=config) == []


async def test_threat_ban_config_threshold_above_the_cap_warns_naming_the_category(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = {"honeypot": {"threshold": CAP + 1, "duration": 60}}

    messages = await _startup_warnings(caplog, threat_ban_config=config)

    assert len(messages) == 1
    assert "threat_ban_config['honeypot']" in messages[0]
    assert str(CAP + 1) in messages[0]
    assert "610" in messages[0]


async def test_an_unset_flag_makes_an_unreachable_auto_ban_threshold_fatal() -> None:
    with pytest.raises(ValueError, match="auto_ban_threshold") as caught:
        await _initialize(auto_ban_threshold=CAP + 1)

    assert "fail_on_misconfiguration=False" in str(caught.value)


async def test_flag_true_makes_an_unreachable_auto_ban_threshold_fatal() -> None:
    with pytest.raises(ValueError, match="auto_ban_threshold") as caught:
        await _initialize(fail_on_misconfiguration=True, auto_ban_threshold=CAP + 1)

    assert "can never fire" in str(caught.value)


async def test_flag_true_makes_an_unreachable_category_threshold_fatal() -> None:
    config = {"sqli": {"threshold": CAP + 1, "duration": 60}}

    with pytest.raises(ValueError, match=r"threat_ban_config\['sqli'\]"):
        await _initialize(fail_on_misconfiguration=True, threat_ban_config=config)


async def test_flag_true_accepts_thresholds_at_the_cap() -> None:
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        await _initialize(fail_on_misconfiguration=True, auto_ban_threshold=CAP)


async def test_flag_false_logs_one_warning_and_starts(
    caplog: pytest.LogCaptureFixture,
) -> None:
    messages = await _startup_warnings(
        caplog, fail_on_misconfiguration=False, auto_ban_threshold=CAP + 1
    )

    assert len(messages) == 1
    assert "fail_on_misconfiguration=False keeps starting" in messages[0]


def _unreachable(messages: list[str]) -> list[str]:
    return [message for message in messages if "can never fire" in message]


class _Messages(logging.Handler):
    def __init__(self) -> None:
        super().__init__(logging.WARNING)
        self.messages: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.messages.append(record.getMessage())


def _problems(config: SecurityConfig, **parts: Any) -> list[str]:
    initializer = HandlerInitializer(config, **parts)
    capture = _Messages()
    package_logger = logging.getLogger("guard_core")
    package_logger.addHandler(capture)
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error")
            initializer._report_unreachable_ban_thresholds()
    finally:
        package_logger.removeHandler(capture)
    return _unreachable(capture.messages)


def _config(**overrides: Any) -> SecurityConfig:
    values: dict[str, Any] = {
        "enable_redis": False,
        "enable_penetration_detection": False,
        "rate_limit": 10,
        "rate_limit_window": 60,
        "auto_ban_threshold": 100_000,
        "fail_on_misconfiguration": False,
    }
    values.update(overrides)
    return SecurityConfig(**values)


def test_default_limit_bound_is_610_and_prints_the_live_values() -> None:
    reported = _problems(_config(auto_ban_threshold=1000))
    assert len(reported) == 1
    assert "auto_ban_threshold is 1000, above the 610 strikes" in reported[0]
    assert "rate_limit=10 per 60 s" in reported[0]
    assert _problems(_config(auto_ban_threshold=600)) == []
    assert _problems(_config(auto_ban_threshold=610)) == []


def test_the_bound_follows_the_live_limit_and_window() -> None:
    assert _problems(_config(rate_limit=100, auto_ban_threshold=6100)) == []
    reported = _problems(_config(rate_limit=100, auto_ban_threshold=6101))
    assert "6,100 strikes" in reported[0]
    assert "rate_limit=100 per 60 s" in reported[0]
    uneven = _problems(_config(rate_limit=10, rate_limit_window=7))
    assert "5,153 strikes" in uneven[0]


def test_a_per_category_entry_above_the_bound_is_reported() -> None:
    config = _config(
        auto_ban_threshold=5,
        threat_ban_config={"xss": ThreatBanConfig(threshold=700, duration=60)},
    )
    reported = _problems(config)
    assert len(reported) == 1
    assert "threat_ban_config['xss'] is 700" in reported[0]


def test_rate_limiting_off_is_silent() -> None:
    assert _problems(_config(enable_rate_limiting=False)) == []


def test_passive_mode_is_silent() -> None:
    assert _problems(_config(passive_mode=True)) == []


def test_exempt_ips_make_the_bound_unknown() -> None:
    assert _problems(_config(exempt_ips=["198.51.100.4"])) == []


def test_a_route_bypassing_rate_limit_is_silent() -> None:
    from guard_core.decorators import SecurityDecorator

    config = _config()
    decorator = SecurityDecorator(config)

    @decorator.bypass(["rate_limit"])
    def route() -> str:
        return "ok"

    assert _problems(config, guard_decorator=decorator) == []

    plain = SecurityDecorator(config)

    @plain.require_https()
    def other() -> str:
        return "ok"

    assert len(_problems(config, guard_decorator=plain)) == 1


def test_a_route_bypassing_every_check_is_silent() -> None:
    from guard_core.decorators import SecurityDecorator

    config = _config()
    decorator = SecurityDecorator(config)

    @decorator.bypass(["all"])
    def route() -> str:
        return "ok"

    assert _problems(config, guard_decorator=decorator) == []


def test_excluded_paths_that_reach_detection_without_rate_limiting_are_silent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from guard_core.core.checks.implementations.suspicious_activity import (
        SuspiciousActivityCheck,
    )

    assert len(_problems(_config())) == 1
    monkeypatch.setattr(SuspiciousActivityCheck, "enforced_on_excluded_paths", True)

    assert _problems(_config()) == []


def test_the_rate_limit_feed_entry_is_never_reported() -> None:
    config = _config(
        auto_ban_threshold=1,
        threat_ban_config={"rate_limit": ThreatBanConfig(threshold=900, duration=60)},
    )
    assert _problems(config) == []


def test_hostile_signal_sources_before_rate_limiting_silence_the_flat_threshold() -> (
    None
):
    config = _config(ban_on_hostile_signals=True, blocked_user_agents=["badbot"])
    assert _problems(config) == []


def test_hostile_signal_sources_silence_their_categories_only() -> None:
    config = _config(
        ban_on_hostile_signals=True,
        blocked_user_agents=["badbot"],
        threat_ban_config={
            "user_agent": ThreatBanConfig(threshold=900, duration=60),
            "xss": ThreatBanConfig(threshold=900, duration=60),
        },
    )
    reported = _problems(config)
    assert len(reported) == 1
    assert "threat_ban_config['xss']" in reported[0]


def test_hostile_signal_flag_without_configured_sources_still_reports() -> None:
    config = _config(ban_on_hostile_signals=True, auto_ban_threshold=1000)
    assert len(_problems(config)) == 1


def test_a_route_with_its_own_ip_rule_counts_as_a_source_before_rate_limiting() -> None:
    from guard_core.decorators import SecurityDecorator

    config = _config(ban_on_hostile_signals=True)
    decorator = SecurityDecorator(config)

    @decorator.require_ip(blacklist=["198.51.100.9"])
    def route() -> str:
        return "ok"

    assert _problems(config, guard_decorator=decorator) == []


def test_redis_on_with_the_defaults_still_reports() -> None:
    config = _config(enable_redis=True, redis_url="redis://localhost:1")

    assert len(_problems(config, redis_handler=MagicMock())) == 1


def test_redis_fail_open_makes_the_bound_unknown() -> None:
    config = _config(
        enable_redis=True, redis_url="redis://localhost:1", redis_fail_open=True
    )

    assert _problems(config, redis_handler=MagicMock()) == []
    assert len(_problems(config)) == 1


def test_fail_secure_off_makes_the_bound_unknown_with_redis() -> None:
    config = _config(
        enable_redis=True, redis_url="redis://localhost:1", fail_secure=False
    )

    assert _problems(config, redis_handler=MagicMock()) == []


async def _stopped_redis_pipeline(**fields: Any) -> tuple[Any, Any, str]:
    from guard_core.handlers.redis_handler import RedisManager
    from tests.test_core.conftest import build_route_pipeline

    config = SecurityConfig(
        enable_redis=True,
        redis_url="redis://127.0.0.1:1",
        enable_penetration_detection=True,
        enable_ip_banning=True,
        enable_rate_limiting=True,
        rate_limit=100,
        rate_limit_window=60,
        **fields,
    )
    pipeline, middleware, route_id = build_route_pipeline(
        config, lambda d: d.suspicious_detection(True)
    )
    middleware.rate_limit_handler.redis_handler = RedisManager(config)
    return pipeline, middleware, route_id


async def _attack(pipeline: Any, route_id: str) -> Any:
    from tests.conftest import MockGuardRequest

    request = MockGuardRequest(
        path="/x",
        client_host="203.0.113.50",
        query_params={"q": "<script>alert(1)</script>"},
    )
    request.state.guard_route_id = route_id
    return await pipeline.execute(request)


async def test_stopped_redis_on_the_defaults_answers_500_and_records_no_strike() -> (
    None
):
    pipeline, middleware, route_id = await _stopped_redis_pipeline()

    response = await _attack(pipeline, route_id)

    assert response is not None
    assert response.status_code == 500
    assert middleware.suspicious_request_counts == {}


async def test_stopped_redis_with_fail_open_lets_the_request_reach_detection() -> None:
    pipeline, middleware, route_id = await _stopped_redis_pipeline(redis_fail_open=True)

    response = await _attack(pipeline, route_id)

    assert response is not None
    assert response.status_code == 400
    assert middleware.suspicious_request_counts["203.0.113.50"]["xss"] == 1


async def test_a_dynamic_rule_that_lowers_the_limit_logs_and_never_raises(
    caplog: pytest.LogCaptureFixture,
) -> None:
    from datetime import datetime, timezone

    from guard_core.handlers.dynamic_rule_handler import DynamicRuleManager
    from guard_core.models import DynamicRules

    DynamicRuleManager._instance = None
    config = _config(auto_ban_threshold=200, fail_on_misconfiguration=True)
    HandlerInitializer(config)._report_unreachable_ban_thresholds()
    manager = DynamicRuleManager(config)
    rules = DynamicRules(
        rule_id="lower",
        version=1,
        timestamp=datetime.now(timezone.utc),
        global_rate_limit=2,
        global_rate_window=60,
    )
    try:
        with caplog.at_level(logging.WARNING):
            await manager._apply_rules(rules)
    finally:
        DynamicRuleManager._instance = None

    logged = [
        r.getMessage() for r in caplog.records if "can never fire" in r.getMessage()
    ]
    assert len(logged) == 1
    assert "Dynamic rule:" in logged[0]
    assert "auto_ban_threshold is 200, above the 122 strikes" in logged[0]
    assert config.rate_limit == 2
