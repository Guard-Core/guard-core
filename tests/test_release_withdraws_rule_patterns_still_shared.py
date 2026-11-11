from collections.abc import Iterator
from unittest.mock import Mock

import pytest

from guard_core._utils.app_managers import release_app
from guard_core._utils.rule_attribution_shared import _APP_RULE_MANAGERS
from guard_core.core.initialization.handler_initializer import HandlerInitializer
from guard_core.handlers import ipban_handler as ipban_module
from guard_core.handlers import suspatterns_handler as patterns_module
from guard_core.handlers.dynamic_rule_handler import DynamicRuleManager
from guard_core.handlers.ipban_handler import ip_ban_manager_for
from guard_core.handlers.suspatterns_handler import sus_patterns_manager_for
from guard_core.models import SecurityConfig
from guard_core.utils import detect_penetration_attempt
from tests.conftest import MockGuardRequest
from tests.protocol_only_redis import REDIS_URL

_PATTERN = r"zzrulepatternzz"
_OTHER = r"zzotherrulezz"
_BANNED = "203.0.113.97"


@pytest.fixture(autouse=True)
def _defaults_unserved(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    for managers in (
        ipban_module._APP_BAN_MANAGERS,
        patterns_module._APP_PATTERN_MANAGERS,
        _APP_RULE_MANAGERS,
    ):
        managers.forget_default()
    monkeypatch.setattr(DynamicRuleManager, "_instance", None)
    yield
    for managers in (
        ipban_module._APP_BAN_MANAGERS,
        patterns_module._APP_PATTERN_MANAGERS,
        _APP_RULE_MANAGERS,
    ):
        managers.forget_default()
    ipban_module.ip_ban_manager.banned_ips.clear()


def _shared_config() -> SecurityConfig:
    return SecurityConfig(
        enable_redis=True,
        redis_url=REDIS_URL,
        redis_prefix="wp616:r6-shared:",
        enable_ip_banning=True,
    )


def _scan(config: SecurityConfig, marker: str) -> MockGuardRequest:
    return MockGuardRequest(path=f"/s?q={marker}", client_host="203.0.113.9")


class _Apps:
    def __init__(self) -> None:
        self.first = _shared_config()
        self.second = _shared_config()
        HandlerInitializer(self.first)
        HandlerInitializer(self.second)
        self.patterns = sus_patterns_manager_for(self.first)
        assert self.patterns is sus_patterns_manager_for(self.second)
        self.first_rules = DynamicRuleManager(self.first)
        self.second_rules = DynamicRuleManager(self.second)
        assert self.first_rules is not self.second_rules


async def _a_rule_adds(apps: _Apps, pattern: str) -> None:
    created: list[str] = []
    await apps.first_rules._apply_pattern_rules([pattern], created)
    assert created == [pattern]
    apps.first_rules._owned_patterns = created


async def test_a_released_apps_rule_pattern_stops_matching_for_the_sharing_app() -> (
    None
):
    apps = _Apps()
    await _a_rule_adds(apps, _PATTERN)
    request = _scan(apps.second, _PATTERN)
    assert (await detect_penetration_attempt(request, apps.second)).is_threat
    release_app(apps.first)
    assert not (await detect_penetration_attempt(request, apps.second)).is_threat


async def test_the_sharing_apps_own_rule_patterns_stay() -> None:
    apps = _Apps()
    await _a_rule_adds(apps, _PATTERN)
    created: list[str] = []
    await apps.second_rules._apply_pattern_rules([_OTHER], created)
    apps.second_rules._owned_patterns = created
    release_app(apps.first)
    assert (
        await detect_penetration_attempt(_scan(apps.second, _OTHER), apps.second)
    ).is_threat


async def test_a_pattern_both_rule_sets_hold_stays() -> None:
    apps = _Apps()
    await _a_rule_adds(apps, _PATTERN)
    held = Mock()
    held.suspicious_patterns = [_PATTERN]
    apps.second_rules.current_rules = held
    release_app(apps.first)
    request = _scan(apps.second, _PATTERN)
    assert (await detect_penetration_attempt(request, apps.second)).is_threat
    apps.second_rules.current_rules = None
    assert (await detect_penetration_attempt(request, apps.second)).is_threat


async def test_a_rule_pattern_equal_to_a_built_in_row_is_never_removed() -> None:
    apps = _Apps()
    built_in = apps.patterns.patterns[0]
    created: list[str] = []
    await apps.first_rules._apply_pattern_rules([built_in], created)
    assert created == []
    apps.first_rules._owned_patterns = created
    release_app(apps.first)
    assert built_in in apps.patterns.patterns


async def test_a_released_apps_rule_ban_still_refuses_on_the_sharing_app() -> None:
    apps = _Apps()
    manager = ip_ban_manager_for(apps.first)
    assert await manager.ban_ip(_BANNED, 600, config=apps.first)
    release_app(apps.first)
    assert await ip_ban_manager_for(apps.second).is_ip_banned(
        _BANNED, config=apps.second
    )


def test_a_default_pattern_without_a_compiled_row_is_removed_and_reported_false() -> (
    None
):
    from types import SimpleNamespace

    from guard_core.handlers._suspatterns_registry import remove_default_pattern_rows

    rows = SimpleNamespace(patterns=[_PATTERN], compiled_patterns=[])
    assert remove_default_pattern_rows(rows, _PATTERN) is False
    assert rows.patterns == []
