import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any
from unittest.mock import MagicMock, Mock

import pytest

from guard_core.models import DynamicRules, SyncSecurityConfig
from guard_core.sync._utils.app_scope import (
    _current_app_scope,
    app_scope_of,
    hold_app_scope,
    in_app_scope,
    release_app_scope,
)
from guard_core.sync._utils.scan_config_scope import (
    _scan_config_scope,
    scan_config_scope_of,
)
from guard_core.sync.core.checks.base import SecurityCheck
from guard_core.sync.core.checks.pipeline import SecurityCheckPipeline
from guard_core.sync.core.initialization.handler_initializer import HandlerInitializer
from guard_core.sync.handlers import _ipban_sharing
from guard_core.sync.handlers.dynamic_rule_handler import DynamicRuleManager
from guard_core.sync.handlers.ipban_handler import ip_ban_manager_for
from guard_core.sync.handlers.suspatterns_handler import sus_patterns_manager_for
from tests.test_sync.conftest import SyncMockGuardRequest

ONE = "redis://user:hunter2@one.invalid:6379/0"
TWO = "redis://user:hunter2@two.invalid:6379/0"
PROXY = "10.0.0.1"


@dataclass
class _App:
    config: SyncSecurityConfig
    redis: MagicMock
    agent: MagicMock
    initializer: HandlerInitializer


def _agent() -> MagicMock:
    agent = MagicMock()
    for name in ("initialize_redis", "start", "flush_buffer", "send_event"):
        setattr(agent, name, MagicMock())
    return agent


def _redis() -> MagicMock:
    redis = MagicMock()
    redis.initialize = MagicMock()
    redis.initialize_agent = MagicMock()
    redis.get_key = MagicMock(return_value=None)
    return redis


def _start(prefix: str, url: str, proxies: list[str]) -> _App:
    config = SyncSecurityConfig(
        enable_redis=True,
        redis_url=url,
        redis_prefix=prefix,
        trusted_proxies=proxies,
        enable_agent=False,
    )
    redis, agent = _redis(), _agent()
    initializer = HandlerInitializer(config, redis_handler=redis, agent_handler=agent)
    initializer.initialize_redis_handlers()
    initializer.initialize_agent_integrations()
    return _App(config, redis, agent, initializer)


class _SeesManagers(SecurityCheck):
    check_name = "sees_managers"

    def __init__(self, middleware: Any, seen: dict[str, Any]) -> None:
        super().__init__(middleware)
        self.seen = seen

    def check(self, request: Any) -> None:
        ban = ip_ban_manager_for(self.config)
        patterns = sus_patterns_manager_for(self.config)
        self.seen["ban"] = (ban.redis_handler, ban.agent_handler, ban.config)
        self.seen["patterns"] = (patterns.redis_handler, patterns.agent_handler)
        self.seen["refusal"] = ban._self_dos_refusal_reason(PROXY)
        return None


def _run_request(app: _App) -> dict[str, Any]:
    seen: dict[str, Any] = {}
    middleware = Mock(config=app.config)
    pipeline = SecurityCheckPipeline(
        [_SeesManagers(middleware, seen)], config=app.config
    )
    request = SyncMockGuardRequest(client_host="203.0.113.5", path="/")
    assert pipeline.execute(request) is None
    return seen


def _telemetry(app: _App) -> Any:
    return app.initializer.composite_handler or app.initializer.agent_handler


def test_same_prefix_and_connection_each_app_routes_its_own_handlers() -> None:
    first = _start("wp136-same:", ONE, [PROXY])
    second = _start("wp136-same:", ONE, [])
    assert ip_ban_manager_for(first.config) is ip_ban_manager_for(second.config)
    assert sus_patterns_manager_for(first.config) is sus_patterns_manager_for(
        second.config
    )

    seen_first = _run_request(first)
    seen_second = _run_request(second)

    assert seen_first["ban"][0] is first.redis
    assert seen_first["ban"][1] is _telemetry(first)
    assert seen_first["ban"][2] is first.config
    assert seen_first["patterns"] == (first.redis, _telemetry(first))
    assert seen_second["ban"][0] is second.redis
    assert seen_second["ban"][1] is _telemetry(second)
    assert seen_second["ban"][2] is second.config
    assert seen_second["patterns"] == (second.redis, _telemetry(second))
    assert _telemetry(first) is not _telemetry(second)


def test_first_app_refuses_its_proxy_ban_though_the_second_bound_last() -> None:
    first = _start("wp136-proxy:", ONE, [PROXY])
    _start("wp136-proxy:", ONE, [])

    assert (_run_request(first))["refusal"] == "trusted_proxy"
    manager = ip_ban_manager_for(first.config)
    assert manager.ban_ip(PROXY, 60) is False
    assert manager.ban_ip(PROXY, 60, config=first.config) is False


def test_second_app_without_proxies_is_not_refused() -> None:
    _start("wp136-noproxy:", ONE, [PROXY])
    second = _start("wp136-noproxy:", ONE, [])
    assert (_run_request(second))["refusal"] is None


def test_the_scope_ends_with_the_request() -> None:
    first = _start("wp136-outside:", ONE, [PROXY])
    _start("wp136-outside:", ONE, [])
    _run_request(first)
    assert _current_app_scope.get() is None


def test_different_prefixes_keep_separate_managers_control() -> None:
    first = _start("wp136-a:", ONE, [PROXY])
    second = _start("wp136-b:", ONE, [])
    assert ip_ban_manager_for(first.config) is not ip_ban_manager_for(second.config)
    assert (_run_request(first))["ban"][0] is first.redis
    assert (_run_request(second))["ban"][0] is second.redis


def test_same_prefix_on_two_urls_gives_two_managers_and_one_redacted_warning(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.WARNING):
        first = _start("wp136-urls:", ONE, [PROXY])
        second = _start("wp136-urls:", TWO, [])

    assert ip_ban_manager_for(first.config) is not ip_ban_manager_for(second.config)
    assert sus_patterns_manager_for(first.config) is not sus_patterns_manager_for(
        second.config
    )
    warnings = [r for r in caplog.records if r.name.endswith("app_managers")]
    assert len(warnings) == 1
    text = warnings[0].getMessage()
    assert "wp136-urls:" in text
    assert "one.invalid:6379" in text and "two.invalid:6379" in text
    assert "hunter2" not in text
    assert (_run_request(first))["ban"][2] is first.config
    assert (_run_request(second))["ban"][2] is second.config


def test_same_prefix_and_connection_logs_no_split_warning(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.WARNING):
        _start("wp136-quiet:", ONE, [])
        _start("wp136-quiet:", ONE, [])
    assert not [r for r in caplog.records if r.name.endswith("app_managers")]


def test_a_dynamic_rule_ban_from_the_second_app_uses_its_own_handlers() -> None:
    first = _start("wp136-rules:", ONE, [PROXY])
    second = _start("wp136-rules:", ONE, [])
    object.__setattr__(first.config, "enable_dynamic_rules", True)
    object.__setattr__(second.config, "enable_dynamic_rules", True)
    first_rules = DynamicRuleManager(first.config)
    second_rules = DynamicRuleManager(second.config)
    assert first_rules is not second_rules
    assert second_rules.config is second.config
    ban_manager = ip_ban_manager_for(second.config)
    assert ban_manager is ip_ban_manager_for(first.config)
    now = datetime.now(timezone.utc)
    answer = DynamicRules(
        rule_id="wp136:rules",
        version=1,
        timestamp=now,
        expires_at=now + timedelta(hours=1),
        ip_blacklist=["198.51.100.9"],
        ip_ban_duration=60,
    )
    second_rules.agent_handler = Mock(get_dynamic_rules=MagicMock(return_value=answer))
    seen: dict[str, Any] = {}

    def not_banned(*args: Any, **kwargs: Any) -> bool:
        return False

    def record_ban(*args: Any, **kwargs: Any) -> bool:
        seen["redis"] = ban_manager.redis_handler
        seen["agent"] = ban_manager.agent_handler
        seen["config"] = ban_manager.config
        return True

    object.__setattr__(ban_manager, "is_ip_banned", not_banned)
    object.__setattr__(ban_manager, "ban_ip", record_ban)
    try:
        second_rules.force_update()
    finally:
        del ban_manager.__dict__["ban_ip"], ban_manager.__dict__["is_ip_banned"]

    assert seen["redis"] is second.redis
    assert seen["agent"] is _telemetry(second)
    assert seen["config"] is second.config


def test_a_scan_handed_a_config_outside_the_pipeline_reads_its_apps() -> None:
    first = _start("wp136-scan:", ONE, [PROXY])
    second = _start("wp136-scan:", ONE, [])
    manager = sus_patterns_manager_for(first.config)
    assert manager is sus_patterns_manager_for(second.config)
    scope = scan_config_scope_of(first.config, manager)
    token = _scan_config_scope.set(scope)
    try:
        assert _current_app_scope.get() is None
        assert manager.agent_handler is _telemetry(first)
        assert manager.redis_handler is first.redis
    finally:
        _scan_config_scope.reset(token)


def test_a_shared_manager_with_no_scope_answers_no_apps_handlers() -> None:
    first = _start("wp136-bare:", ONE, [PROXY])
    _start("wp136-bare:", ONE, [])
    manager = sus_patterns_manager_for(first.config)
    ban_manager = ip_ban_manager_for(first.config)
    assert _current_app_scope.get() is None
    for shared in (manager, ban_manager):
        assert shared.agent_handler is None
        assert shared.redis_handler is None


def test_a_manager_one_app_owns_answers_its_handlers_with_no_scope() -> None:
    only = _start("wp136-owner:", ONE, [])
    manager = ip_ban_manager_for(only.config)
    assert manager.redis_handler is only.redis
    assert manager.agent_handler is _telemetry(only)


def test_a_hand_built_pipeline_without_config_still_sets_its_apps_scope() -> None:
    first = _start("wp136-built:", ONE, [PROXY])
    second = _start("wp136-built:", ONE, [])
    seen: dict[str, Any] = {}
    middleware = Mock(config=first.config)
    pipeline = SecurityCheckPipeline([_SeesManagers(middleware, seen)])
    request = SyncMockGuardRequest(client_host="203.0.113.5", path="/")
    assert pipeline.execute(request) is None
    assert seen["ban"][0] is first.redis
    assert seen["ban"][2] is first.config
    assert first.redis is not second.redis


def test_the_split_warning_fires_with_a_redis_url_and_enable_redis_left_default(
    caplog: pytest.LogCaptureFixture,
) -> None:
    def build(url: str) -> HandlerInitializer:
        config = SyncSecurityConfig(
            redis_url=url, redis_prefix="wp136-default:", enable_agent=False
        )
        assert "enable_redis" not in config.model_fields_set
        return HandlerInitializer(
            config, redis_handler=_redis(), agent_handler=_agent()
        )

    with caplog.at_level(logging.WARNING):
        first, second = build(ONE), build(TWO)

    assert ip_ban_manager_for(first.config) is not ip_ban_manager_for(second.config)
    warnings = [r for r in caplog.records if r.name.endswith("app_managers")]
    assert len(warnings) == 1
    assert "hunter2" not in warnings[0].getMessage()


EXEMPT = "203.0.113.7"


def _whitelist_rules(rule_id: str, whitelist: list[str], version: int = 1) -> Any:
    now = datetime.now(timezone.utc)
    return DynamicRules(
        rule_id=rule_id,
        version=version,
        timestamp=now,
        expires_at=now + timedelta(hours=1),
        ip_whitelist=whitelist,
    )


def _refresh(app: _App, rules: Any) -> None:
    object.__setattr__(app.config, "enable_dynamic_rules", True)
    manager = DynamicRuleManager(app.config)
    manager.agent_handler = Mock(get_dynamic_rules=MagicMock(return_value=rules))
    manager.force_update()


@pytest.mark.parametrize("a_first", [True, False])
def test_a_rule_whitelist_exempts_only_the_app_whose_rules_name_it(
    a_first: bool,
) -> None:
    first = _start(f"wp136-exempt{a_first}:", ONE, [])
    second = _start(f"wp136-exempt{a_first}:", ONE, [])
    ban = ip_ban_manager_for(first.config)
    assert ban is ip_ban_manager_for(second.config)
    mine, theirs = _whitelist_rules("a", [EXEMPT]), _whitelist_rules("b", [])
    if a_first:
        _refresh(first, mine)
        _refresh(second, theirs)
    else:
        _refresh(second, theirs)
        _refresh(first, mine)

    with in_app_scope(app_scope_of(first.config)):
        assert ban._refuse_rule_exempt_target(EXEMPT) is True
        assert ban.rule_exempt_networks
    with in_app_scope(app_scope_of(second.config)):
        assert ban._refuse_rule_exempt_target(EXEMPT) is False
        assert not ban.rule_exempt_networks


def test_the_app_without_the_whitelist_still_denies_a_banned_address() -> None:
    first = _start("wp136-denies:", ONE, [])
    second = _start("wp136-denies:", ONE, [])
    ban = ip_ban_manager_for(first.config)
    _refresh(first, _whitelist_rules("a", [EXEMPT]))
    _refresh(second, _whitelist_rules("b", []))
    ban.banned_ips[EXEMPT] = 10**12

    with in_app_scope(app_scope_of(second.config)):
        assert ban.is_ip_banned(EXEMPT) is True
    with in_app_scope(app_scope_of(first.config)):
        assert ban.is_ip_banned(EXEMPT) is False
        assert ban.ban_ip(EXEMPT, 60) is False


def test_a_rule_revert_clears_only_its_own_apps_exempt_set() -> None:
    first = _start("wp136-revert:", ONE, [])
    second = _start("wp136-revert:", ONE, [])
    ban = ip_ban_manager_for(first.config)
    _refresh(first, _whitelist_rules("a", [EXEMPT]))
    _refresh(second, _whitelist_rules("b", ["203.0.113.8"]))
    second_rules = DynamicRuleManager(second.config)
    with in_app_scope(app_scope_of(second.config)):
        second_rules._revert_to_base_config()
        assert not ban.rule_exempt_networks
    with in_app_scope(app_scope_of(first.config)):
        assert ban._refuse_rule_exempt_target(EXEMPT) is True


V6 = "2001:db8:1:2::9"


def _record_store_ban(manager: Any, seen: list[tuple[str, str, Any, Any]]) -> None:
    def store_ban(namespace: str, key: str, *args: Any, **kwargs: Any) -> None:
        seen.append((namespace, key, manager.redis_handler, manager.agent_handler))

    object.__setattr__(manager, "_store_ban", store_ban)


def _two_apps(prefix: str, **second_settings: Any) -> tuple[_App, _App, Any]:
    first = _start(prefix, ONE, [PROXY])
    second = _start(prefix, ONE, [])
    return first, second, ip_ban_manager_for(first.config)


def test_a_ban_with_config_runs_as_that_app_with_one_write_and_one_event() -> None:
    first, second, ban = _two_apps("wp136-m2:")
    writes: list[tuple[str, str, Any, Any]] = []
    _record_store_ban(ban, writes)
    assert ban.ban_ip(PROXY, 60, config=first.config) is False
    assert writes == []
    assert ban.ban_ip("198.51.100.20", 60, config=second.config) is True
    assert writes == [("banned_ips", "198.51.100.20", second.redis, _telemetry(second))]


def test_an_unban_with_config_removes_only_that_apps_identity() -> None:
    first = _start("wp136-m2u:", ONE, [])
    second = _start("wp136-m2u:", ONE, [])
    object.__setattr__(first.config, "ipv6_prefix_length", 64)
    object.__setattr__(second.config, "ipv6_prefix_length", 48)
    ban = ip_ban_manager_for(first.config)
    identity_a = ban._grouped_identity_of(V6, first.config)
    identity_b = ban._grouped_identity_of(V6, second.config)
    assert identity_a and identity_b and identity_a != identity_b
    for key in (V6, identity_a, identity_b):
        ban.banned_ips[key] = 10**12
    object.__setattr__(ban, "_write_with_version_bump", MagicMock())
    object.__setattr__(ban, "_forget_strikes", MagicMock())

    ban.unban_ip(V6, config=second.config)

    assert V6 not in ban.banned_ips and identity_b not in ban.banned_ips
    assert identity_a in ban.banned_ips


def test_an_unscoped_ban_on_a_shared_manager_is_refused_when_any_app_refuses(
    caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(_ipban_sharing, "_warned_about_unscoped_calls", False)
    _, _, ban = _two_apps("wp136-m3r:")
    with caplog.at_level(logging.WARNING):
        assert ban.ban_ip(PROXY, 60) is False
        assert ban.ban_ip(PROXY, 60) is False
    warnings = [
        r.getMessage() for r in caplog.records if "no app in scope" in r.getMessage()
    ]
    assert len(warnings) == 1
    assert "wp136-m3r:" in warnings[0] and "one.invalid:6379" in warnings[0]
    assert "hunter2" not in warnings[0] and "config=" in warnings[0]


def test_an_unscoped_ban_writes_every_distinct_identity_without_an_event() -> None:
    first, second, ban = _two_apps("wp136-m3w:")
    object.__setattr__(first.config, "ipv6_prefix_length", 64)
    object.__setattr__(second.config, "ipv6_prefix_length", 48)
    writes: list[tuple[str, str, Any, Any]] = []
    _record_store_ban(ban, writes)

    assert ban.ban_ip(V6, 60, grouped=True) is True

    assert {(n, k) for n, k, _, _ in writes} == {
        ("banned_identities", str(ban._grouped_identity_of(V6, first.config))),
        ("banned_identities", str(ban._grouped_identity_of(V6, second.config))),
    }
    assert all(agent is None for *_, agent in writes)


def test_an_unscoped_unban_removes_every_identity_and_a_lookup_checks_each() -> None:
    first, second, ban = _two_apps("wp136-m3u:")
    object.__setattr__(first.config, "ipv6_prefix_length", 64)
    object.__setattr__(second.config, "ipv6_prefix_length", 48)
    identity_a = ban._grouped_identity_of(V6, first.config)
    identity_b = ban._grouped_identity_of(V6, second.config)
    ban.banned_ips[identity_a] = 10**12
    ban.banned_ips[identity_b] = 10**12
    assert ban.is_ip_banned(V6) is True
    object.__setattr__(ban, "_write_with_version_bump", MagicMock())
    object.__setattr__(ban, "_forget_strikes", MagicMock())

    ban.unban_ip(V6)

    assert identity_a not in ban.banned_ips and identity_b not in ban.banned_ips


def test_an_unscoped_ban_reaches_redis_through_a_live_sharing_app() -> None:
    first, second, ban = _two_apps("wp136-m3l:")
    first.redis._closed = True
    writes: list[tuple[str, str, Any, Any]] = []
    _record_store_ban(ban, writes)

    assert ban.ban_ip("198.51.100.30", 60) is True

    assert writes[0][2] is second.redis
    second.redis._closed = True
    writes.clear()
    assert ban.ban_ip("198.51.100.31", 60) is True
    assert writes[0][2] is None


def test_a_single_app_manager_answers_its_own_handlers_unscoped() -> None:
    only = _start("wp136-m3s:", ONE, [])
    ban = ip_ban_manager_for(only.config)
    writes: list[tuple[str, str, Any, Any]] = []
    _record_store_ban(ban, writes)
    assert ban.ban_ip("198.51.100.40", 60) is True
    assert writes == [("banned_ips", "198.51.100.40", only.redis, _telemetry(only))]


def test_a_nested_hold_restores_the_outer_scope_and_never_sets_none() -> None:
    first = _start("wp136-hold:", ONE, [])
    second = _start("wp136-hold:", ONE, [])
    outer = hold_app_scope(first.config)
    assert _current_app_scope.get() is app_scope_of(first.config)
    inner = hold_app_scope(second.config)
    assert _current_app_scope.get() is app_scope_of(second.config)
    release_app_scope(inner)
    assert _current_app_scope.get() is app_scope_of(first.config)
    assert hold_app_scope(SyncSecurityConfig(enable_agent=False)) is None
    assert _current_app_scope.get() is app_scope_of(first.config)
    release_app_scope(outer)
    assert _current_app_scope.get() is None
