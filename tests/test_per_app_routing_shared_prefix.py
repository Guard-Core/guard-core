import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any
from unittest.mock import AsyncMock, MagicMock, Mock

import pytest

from guard_core._utils.app_scope import (
    _current_app_scope,
    app_scope_of,
    hold_app_scope,
    in_app_scope,
    release_app_scope,
)
from guard_core._utils.sampling import PerApp, WarnedKeys
from guard_core._utils.scan_config_scope import _scan_config_scope, scan_config_scope_of
from guard_core.core.checks.base import SecurityCheck
from guard_core.core.checks.pipeline import SecurityCheckPipeline
from guard_core.core.initialization.handler_initializer import HandlerInitializer
from guard_core.handlers import _ipban_sharing, ratelimit_handler
from guard_core.handlers.dynamic_rule_handler import DynamicRuleManager
from guard_core.handlers.ipban_handler import ip_ban_manager_for
from guard_core.handlers.redis_handler import RedisManager
from guard_core.handlers.suspatterns_handler import sus_patterns_manager_for
from guard_core.models import DynamicRules, SecurityConfig
from tests.conftest import MockGuardRequest
from tests.protocol_only_redis import REDIS_URL

ONE = "redis://user:hunter2@one.invalid:6379/0"
TWO = "redis://user:hunter2@two.invalid:6379/0"
PROXY = "10.0.0.1"


@dataclass
class _App:
    config: SecurityConfig
    redis: Any
    agent: MagicMock
    initializer: HandlerInitializer


def _agent() -> MagicMock:
    agent = MagicMock()
    for name in ("initialize_redis", "start", "flush_buffer", "send_event"):
        setattr(agent, name, AsyncMock())
    return agent


def _redis() -> MagicMock:
    redis = MagicMock()
    redis.initialize = AsyncMock()
    redis.initialize_agent = AsyncMock()
    redis.get_key = AsyncMock(return_value=None)
    return redis


async def _start(prefix: str, url: str, proxies: list[str]) -> _App:
    config = SecurityConfig(
        enable_redis=True,
        redis_url=url,
        redis_prefix=prefix,
        trusted_proxies=proxies,
        enable_agent=False,
    )
    redis, agent = _redis(), _agent()
    initializer = HandlerInitializer(config, redis_handler=redis, agent_handler=agent)
    await initializer.initialize_redis_handlers()
    await initializer.initialize_agent_integrations()
    return _App(config, redis, agent, initializer)


class _SeesManagers(SecurityCheck):
    check_name = "sees_managers"

    def __init__(self, middleware: Any, seen: dict[str, Any]) -> None:
        super().__init__(middleware)
        self.seen = seen

    async def check(self, request: Any) -> None:
        ban = ip_ban_manager_for(self.config)
        patterns = sus_patterns_manager_for(self.config)
        self.seen["ban"] = (ban.redis_handler, ban.agent_handler, ban.config)
        self.seen["patterns"] = (patterns.redis_handler, patterns.agent_handler)
        self.seen["refusal"] = ban._self_dos_refusal_reason(PROXY)
        return None


async def _run_request(app: _App) -> dict[str, Any]:
    seen: dict[str, Any] = {}
    middleware = Mock(config=app.config)
    pipeline = SecurityCheckPipeline(
        [_SeesManagers(middleware, seen)], config=app.config
    )
    request = MockGuardRequest(client_host="203.0.113.5", path="/")
    assert await pipeline.execute(request) is None
    return seen


def _telemetry(app: _App) -> Any:
    return app.initializer.composite_handler or app.initializer.agent_handler


async def test_same_prefix_and_connection_each_app_routes_its_own_handlers() -> None:
    first = await _start("wp136-same:", ONE, [PROXY])
    second = await _start("wp136-same:", ONE, [])
    assert ip_ban_manager_for(first.config) is ip_ban_manager_for(second.config)
    assert sus_patterns_manager_for(first.config) is sus_patterns_manager_for(
        second.config
    )

    seen_first = await _run_request(first)
    seen_second = await _run_request(second)

    assert seen_first["ban"][0] is first.redis
    assert seen_first["ban"][1] is _telemetry(first)
    assert seen_first["ban"][2] is first.config
    assert seen_first["patterns"] == (first.redis, _telemetry(first))
    assert seen_second["ban"][0] is second.redis
    assert seen_second["ban"][1] is _telemetry(second)
    assert seen_second["ban"][2] is second.config
    assert seen_second["patterns"] == (second.redis, _telemetry(second))
    assert _telemetry(first) is not _telemetry(second)


async def test_first_app_refuses_its_proxy_ban_though_the_second_bound_last() -> None:
    first = await _start("wp136-proxy:", ONE, [PROXY])
    await _start("wp136-proxy:", ONE, [])

    assert (await _run_request(first))["refusal"] == "trusted_proxy"
    manager = ip_ban_manager_for(first.config)
    assert await manager.ban_ip(PROXY, 60) is False
    assert await manager.ban_ip(PROXY, 60, config=first.config) is False


async def test_second_app_without_proxies_is_not_refused() -> None:
    await _start("wp136-noproxy:", ONE, [PROXY])
    second = await _start("wp136-noproxy:", ONE, [])
    assert (await _run_request(second))["refusal"] is None


async def test_the_scope_ends_with_the_request() -> None:
    first = await _start("wp136-outside:", ONE, [PROXY])
    await _start("wp136-outside:", ONE, [])
    await _run_request(first)
    assert _current_app_scope.get() is None


async def test_different_prefixes_keep_separate_managers_control() -> None:
    first = await _start("wp136-a:", ONE, [PROXY])
    second = await _start("wp136-b:", ONE, [])
    assert ip_ban_manager_for(first.config) is not ip_ban_manager_for(second.config)
    assert (await _run_request(first))["ban"][0] is first.redis
    assert (await _run_request(second))["ban"][0] is second.redis


async def test_same_prefix_on_two_urls_gives_two_managers_and_one_redacted_warning(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.WARNING):
        first = await _start("wp136-urls:", ONE, [PROXY])
        second = await _start("wp136-urls:", TWO, [])

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
    assert (await _run_request(first))["ban"][2] is first.config
    assert (await _run_request(second))["ban"][2] is second.config


async def test_same_prefix_and_connection_logs_no_split_warning(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.WARNING):
        await _start("wp136-quiet:", ONE, [])
        await _start("wp136-quiet:", ONE, [])
    assert not [r for r in caplog.records if r.name.endswith("app_managers")]


async def test_a_dynamic_rule_ban_from_the_second_app_uses_its_own_handlers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first = await _start("wp136-rules:", ONE, [PROXY])
    second = await _start("wp136-rules:", ONE, [])
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
    second_rules.agent_handler = Mock(get_dynamic_rules=AsyncMock(return_value=answer))
    seen: dict[str, Any] = {}

    async def not_banned(*args: Any, **kwargs: Any) -> bool:
        return False

    async def record_ban(*args: Any, **kwargs: Any) -> bool:
        seen["redis"] = ban_manager.redis_handler
        seen["agent"] = ban_manager.agent_handler
        seen["config"] = ban_manager.config
        return True

    monkeypatch.setattr(ban_manager, "is_ip_banned", not_banned)
    monkeypatch.setattr(ban_manager, "ban_ip", record_ban)
    await second_rules.force_update()

    assert seen["redis"] is second.redis
    assert seen["agent"] is _telemetry(second)
    assert seen["config"] is second.config


async def test_a_scan_handed_a_config_outside_the_pipeline_reads_its_apps() -> None:
    first = await _start("wp136-scan:", ONE, [PROXY])
    second = await _start("wp136-scan:", ONE, [])
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


async def test_a_shared_manager_with_no_scope_answers_no_apps_handlers() -> None:
    first = await _start("wp136-bare:", ONE, [PROXY])
    await _start("wp136-bare:", ONE, [])
    manager = sus_patterns_manager_for(first.config)
    ban_manager = ip_ban_manager_for(first.config)
    assert _current_app_scope.get() is None
    for shared in (manager, ban_manager):
        assert shared.agent_handler is None
        assert shared.redis_handler is None


async def test_a_manager_one_app_owns_answers_its_handlers_with_no_scope() -> None:
    only = await _start("wp136-owner:", ONE, [])
    manager = ip_ban_manager_for(only.config)
    assert manager.redis_handler is only.redis
    assert manager.agent_handler is _telemetry(only)


async def test_a_hand_built_pipeline_without_config_still_sets_its_apps_scope() -> None:
    first = await _start("wp136-built:", ONE, [PROXY])
    second = await _start("wp136-built:", ONE, [])
    seen: dict[str, Any] = {}
    middleware = Mock(config=first.config)
    pipeline = SecurityCheckPipeline([_SeesManagers(middleware, seen)])
    request = MockGuardRequest(client_host="203.0.113.5", path="/")
    assert await pipeline.execute(request) is None
    assert seen["ban"][0] is first.redis
    assert seen["ban"][2] is first.config
    assert first.redis is not second.redis


async def test_the_split_warning_fires_with_a_redis_url_and_enable_redis_left_default(
    caplog: pytest.LogCaptureFixture,
) -> None:
    def build(url: str) -> HandlerInitializer:
        config = SecurityConfig(
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


async def _refresh(app: _App, rules: Any) -> None:
    object.__setattr__(app.config, "enable_dynamic_rules", True)
    manager = DynamicRuleManager(app.config)
    manager.agent_handler = Mock(get_dynamic_rules=AsyncMock(return_value=rules))
    await manager.force_update()


@pytest.mark.parametrize("a_first", [True, False])
async def test_a_rule_whitelist_exempts_only_the_app_whose_rules_name_it(
    a_first: bool,
) -> None:
    first = await _start(f"wp136-exempt{a_first}:", ONE, [])
    second = await _start(f"wp136-exempt{a_first}:", ONE, [])
    ban = ip_ban_manager_for(first.config)
    assert ban is ip_ban_manager_for(second.config)
    mine, theirs = _whitelist_rules("a", [EXEMPT]), _whitelist_rules("b", [])
    if a_first:
        await _refresh(first, mine)
        await _refresh(second, theirs)
    else:
        await _refresh(second, theirs)
        await _refresh(first, mine)

    with in_app_scope(app_scope_of(first.config)):
        assert ban._refuse_rule_exempt_target(EXEMPT) is True
        assert ban.rule_exempt_networks
    with in_app_scope(app_scope_of(second.config)):
        assert ban._refuse_rule_exempt_target(EXEMPT) is False
        assert not ban.rule_exempt_networks


async def test_the_app_without_the_whitelist_still_denies_a_banned_address() -> None:
    first = await _start("wp136-denies:", ONE, [])
    second = await _start("wp136-denies:", ONE, [])
    ban = ip_ban_manager_for(first.config)
    await _refresh(first, _whitelist_rules("a", [EXEMPT]))
    await _refresh(second, _whitelist_rules("b", []))
    ban.banned_ips[EXEMPT] = 10**12

    with in_app_scope(app_scope_of(second.config)):
        assert await ban.is_ip_banned(EXEMPT) is True
    with in_app_scope(app_scope_of(first.config)):
        assert await ban.is_ip_banned(EXEMPT) is False
        assert await ban.ban_ip(EXEMPT, 60) is False


async def test_a_rule_revert_clears_only_its_own_apps_exempt_set() -> None:
    first = await _start("wp136-revert:", ONE, [])
    second = await _start("wp136-revert:", ONE, [])
    ban = ip_ban_manager_for(first.config)
    await _refresh(first, _whitelist_rules("a", [EXEMPT]))
    await _refresh(second, _whitelist_rules("b", ["203.0.113.8"]))
    second_rules = DynamicRuleManager(second.config)
    with in_app_scope(app_scope_of(second.config)):
        second_rules._revert_to_base_config()
        assert not ban.rule_exempt_networks
    with in_app_scope(app_scope_of(first.config)):
        assert ban._refuse_rule_exempt_target(EXEMPT) is True


V6 = "2001:db8:1:2::9"


def _record_store_ban(
    monkeypatch: pytest.MonkeyPatch,
    manager: Any,
    seen: list[tuple[str, str, Any, Any]],
) -> None:
    async def store_ban(namespace: str, key: str, *args: Any, **kwargs: Any) -> None:
        seen.append((namespace, key, manager.redis_handler, manager.agent_handler))

    monkeypatch.setattr(manager, "_store_ban", store_ban)


async def _two_apps(prefix: str) -> tuple[_App, _App, Any]:
    first = await _start(prefix, ONE, [PROXY])
    second = await _start(prefix, ONE, [])
    return first, second, ip_ban_manager_for(first.config)


async def test_a_ban_with_config_runs_as_that_app_with_one_write_and_one_event(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first, second, ban = await _two_apps("wp136-m2:")
    writes: list[tuple[str, str, Any, Any]] = []
    _record_store_ban(monkeypatch, ban, writes)
    assert await ban.ban_ip(PROXY, 60, config=first.config) is False
    assert writes == []
    assert await ban.ban_ip("198.51.100.20", 60, config=second.config) is True
    assert writes == [("banned_ips", "198.51.100.20", second.redis, _telemetry(second))]


async def test_an_unban_with_config_removes_only_that_apps_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first = await _start("wp136-m2u:", ONE, [])
    second = await _start("wp136-m2u:", ONE, [])
    object.__setattr__(first.config, "ipv6_prefix_length", 64)
    object.__setattr__(second.config, "ipv6_prefix_length", 48)
    ban = ip_ban_manager_for(first.config)
    identity_a = ban._grouped_identity_of(V6, first.config)
    identity_b = ban._grouped_identity_of(V6, second.config)
    assert identity_a and identity_b and identity_a != identity_b
    for key in (V6, identity_a, identity_b):
        ban.banned_ips[key] = 10**12
    monkeypatch.setattr(ban, "_write_with_version_bump", AsyncMock())
    monkeypatch.setattr(ban, "_forget_strikes", AsyncMock())

    await ban.unban_ip(V6, config=second.config)

    assert V6 not in ban.banned_ips and identity_b not in ban.banned_ips
    assert identity_a in ban.banned_ips


async def test_an_unscoped_ban_on_a_shared_manager_is_refused_when_any_app_refuses(
    caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(_ipban_sharing, "_warned_about_unscoped_calls", False)
    _, _, ban = await _two_apps("wp136-m3r:")
    with caplog.at_level(logging.WARNING):
        assert await ban.ban_ip(PROXY, 60) is False
        assert await ban.ban_ip(PROXY, 60) is False
    warnings = [
        r.getMessage() for r in caplog.records if "no app in scope" in r.getMessage()
    ]
    assert len(warnings) == 1
    assert "wp136-m3r:" in warnings[0] and "one.invalid:6379" in warnings[0]
    assert "hunter2" not in warnings[0] and "config=" in warnings[0]


async def test_an_unscoped_ban_writes_every_distinct_identity_without_an_event(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first, second, ban = await _two_apps("wp136-m3w:")
    object.__setattr__(first.config, "ipv6_prefix_length", 64)
    object.__setattr__(second.config, "ipv6_prefix_length", 48)
    writes: list[tuple[str, str, Any, Any]] = []
    _record_store_ban(monkeypatch, ban, writes)

    assert await ban.ban_ip(V6, 60, grouped=True) is True

    assert {(n, k) for n, k, _, _ in writes} == {
        ("banned_identities", str(ban._grouped_identity_of(V6, first.config))),
        ("banned_identities", str(ban._grouped_identity_of(V6, second.config))),
    }
    assert all(agent is None for *_, agent in writes)


async def test_an_unscoped_unban_removes_every_identity_and_a_lookup_checks_each(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first, second, ban = await _two_apps("wp136-m3u:")
    object.__setattr__(first.config, "ipv6_prefix_length", 64)
    object.__setattr__(second.config, "ipv6_prefix_length", 48)
    identity_a = ban._grouped_identity_of(V6, first.config)
    identity_b = ban._grouped_identity_of(V6, second.config)
    ban.banned_ips[identity_a] = 10**12
    ban.banned_ips[identity_b] = 10**12
    assert await ban.is_ip_banned(V6) is True
    monkeypatch.setattr(ban, "_write_with_version_bump", AsyncMock())
    monkeypatch.setattr(ban, "_forget_strikes", AsyncMock())

    await ban.unban_ip(V6)

    assert identity_a not in ban.banned_ips and identity_b not in ban.banned_ips


async def test_an_unscoped_ban_reaches_redis_through_a_live_sharing_app(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first, second, ban = await _two_apps("wp136-m3l:")
    first.redis._closed = True
    writes: list[tuple[str, str, Any, Any]] = []
    _record_store_ban(monkeypatch, ban, writes)

    assert await ban.ban_ip("198.51.100.30", 60) is True

    assert writes[0][2] is second.redis
    second.redis._closed = True
    writes.clear()
    assert await ban.ban_ip("198.51.100.31", 60) is True
    assert writes[0][2] is None


async def test_a_single_app_manager_answers_its_own_handlers_unscoped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    only = await _start("wp136-m3s:", ONE, [])
    ban = ip_ban_manager_for(only.config)
    writes: list[tuple[str, str, Any, Any]] = []
    _record_store_ban(monkeypatch, ban, writes)
    assert await ban.ban_ip("198.51.100.40", 60) is True
    assert writes == [("banned_ips", "198.51.100.40", only.redis, _telemetry(only))]


async def test_a_nested_hold_restores_the_outer_scope_and_never_sets_none() -> None:
    first = await _start("wp136-hold:", ONE, [])
    second = await _start("wp136-hold:", ONE, [])
    outer = hold_app_scope(first.config)
    assert _current_app_scope.get() is app_scope_of(first.config)
    inner = hold_app_scope(second.config)
    assert _current_app_scope.get() is app_scope_of(second.config)
    release_app_scope(inner)
    assert _current_app_scope.get() is app_scope_of(first.config)
    assert hold_app_scope(SecurityConfig(enable_agent=False)) is None
    assert _current_app_scope.get() is app_scope_of(first.config)
    release_app_scope(outer)
    assert _current_app_scope.get() is None


class _ReadsScope(SecurityCheck):
    check_name = "reads_scope"

    def __init__(self, middleware: Any, seen: list[Any]) -> None:
        super().__init__(middleware)
        self.seen = seen

    async def check(self, request: Any) -> None:
        self.seen.append(_current_app_scope.get())
        return None


async def test_a_pipeline_whose_app_has_no_scope_leaves_the_held_scope_in_force() -> (
    None
):
    held = await _start("wp136-nest:", ONE, [])
    unbound = SecurityConfig(enable_agent=False)
    seen: list[Any] = []
    pipeline = SecurityCheckPipeline(
        [_ReadsScope(Mock(config=unbound), seen)], config=unbound
    )
    token = hold_app_scope(held.config)
    try:
        assert await pipeline.execute(MockGuardRequest(path="/")) is None
        assert _current_app_scope.get() is app_scope_of(held.config)
    finally:
        release_app_scope(token)
    assert seen == [app_scope_of(held.config)]
    assert _current_app_scope.get() is None


async def _live_app(prefix: str, proxies: list[str]) -> _App:
    config = SecurityConfig(
        enable_redis=True,
        redis_url=REDIS_URL,
        redis_prefix=prefix,
        trusted_proxies=proxies,
        enable_agent=False,
        enable_dynamic_rules=False,
        enable_rate_limit_auto_ban=True,
        enable_ip_banning=True,
    )
    redis = RedisManager(config)
    initializer = HandlerInitializer(config, redis_handler=redis)
    await initializer.initialize_redis_handlers()
    return _App(config, redis, _agent(), initializer)


async def _live_pair(prefix: str) -> tuple[_App, _App, Any]:
    first = await _live_app(prefix, [PROXY])
    second = await _live_app(prefix, [])
    ban = ip_ban_manager_for(first.config)
    assert ban is ip_ban_manager_for(second.config)
    return first, second, ban


def _forget_local_bans(ban: Any) -> None:
    ban.banned_ips.clear()
    ban.banned_networks.clear()


async def test_a_redis_ban_on_a_trusted_proxy_is_not_enforced_for_its_app(
    caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        _ipban_sharing, "_warned_unenforced_bans", PerApp("unenforced_bans", WarnedKeys)
    )
    prefix = f"wp136-d178-{id(caplog)}:"
    first, second, ban = await _live_pair(prefix)
    try:
        assert await ban.ban_ip(PROXY, 3600, config=second.config) is True
        assert await ban.ban_ip("198.51.100.50", 3600, config=second.config) is True
        _forget_local_bans(ban)

        with caplog.at_level(logging.WARNING):
            assert await ban.is_ip_banned(PROXY, config=first.config) is False
            assert await ban.is_ip_banned(PROXY, config=first.config) is False
        assert await ban.is_ip_banned(PROXY, config=second.config) is True
        assert await ban.is_ip_banned("198.51.100.50", config=first.config) is True
        assert await ban.is_ip_banned(PROXY) is True
        warnings = [
            r.getMessage() for r in caplog.records if "not enforced" in r.getMessage()
        ]
        assert len(warnings) == 1
        assert PROXY in warnings[0] and prefix in warnings[0]
    finally:
        await ban.unban_ip(PROXY, config=second.config)
        await ban.unban_ip("198.51.100.50", config=second.config)
        await first.redis.close()
        await second.redis.close()


async def test_a_network_ban_covering_the_proxy_answers_like_an_address_ban() -> None:
    first, second, ban = await _live_pair(f"wp136-d178n-{id(PROXY)}:")
    try:
        assert await ban.ban_ip("10.0.0.0/24", 3600, config=second.config) is True
        _forget_local_bans(ban)

        assert await ban.is_ip_banned(PROXY, config=first.config) is False
        assert await ban.is_ip_banned(PROXY, config=second.config) is True
        assert await ban.is_ip_banned("10.0.0.9", config=first.config) is True
    finally:
        await ban.unban_ip("10.0.0.0/24", config=second.config)
        await first.redis.close()
        await second.redis.close()


async def test_the_rate_limit_feed_uses_the_callers_config_for_a_stored_ban() -> None:
    first, second, ban = await _live_pair(f"wp136-d178r-{id(PROXY)}:")
    first_counts = ratelimit_handler._by_ip_autoban_counts.for_app(first.config)
    second_counts = ratelimit_handler._by_ip_autoban_counts.for_app(second.config)
    try:
        assert await ban.ban_ip(PROXY, 3600, config=second.config) is True
        _forget_local_bans(ban)

        await ratelimit_handler._feed_rate_limit_autoban(PROXY, first.config)
        assert first_counts
        await ratelimit_handler._feed_rate_limit_autoban(PROXY, second.config)
        assert not second_counts
    finally:
        await ban.unban_ip(PROXY, config=second.config)
        await first.redis.close()
        await second.redis.close()
