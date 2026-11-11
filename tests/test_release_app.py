import gc
import logging
from collections.abc import Iterator
from unittest.mock import Mock

import pytest

from guard_core._utils.app_managers import release_app
from guard_core._utils.rule_attribution_shared import _APP_RULE_MANAGERS
from guard_core.core.checks.implementations.ip_security import IpSecurityCheck
from guard_core.handlers import cloud_handler as cloud_module
from guard_core.handlers import ipban_handler as ipban_module
from guard_core.handlers import suspatterns_handler as patterns_module
from guard_core.handlers.cloud_handler import cloud_handler_for
from guard_core.handlers.dynamic_rule_handler import DynamicRuleManager
from guard_core.handlers.ipban_handler import ip_ban_manager_for
from guard_core.handlers.suspatterns_handler import sus_patterns_manager_for
from guard_core.models import SecurityConfig
from guard_core.utils import detect_penetration_attempt
from tests.conftest import MockGuardRequest
from tests.protocol_only_redis import REDIS_URL

_KINDS = ("ipban", "cloud", "suspatterns")
_RUNS = 20
_BANNED_IP = "203.0.113.5"
_ATTACK = "/search?q=1' UNION SELECT password FROM users--"


def _forget_every_default() -> None:
    ipban_module._APP_BAN_MANAGERS.forget_default()
    cloud_module._APP_CLOUD_MANAGERS.forget_default()
    patterns_module._APP_PATTERN_MANAGERS.forget_default()
    _APP_RULE_MANAGERS.forget_default()


@pytest.fixture(autouse=True)
def _every_default_unserved(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    _forget_every_default()
    monkeypatch.setattr(DynamicRuleManager, "_instance", None)
    yield
    _forget_every_default()
    ipban_module.ip_ban_manager.banned_ips.clear()


def _no_redis_config() -> SecurityConfig:
    return SecurityConfig(enable_redis=False)


def _redis_config(prefix: str) -> SecurityConfig:
    return SecurityConfig(enable_redis=True, redis_url=REDIS_URL, redis_prefix=prefix)


def _bind_every_kind(config: SecurityConfig) -> dict[str, object]:
    return {
        "ipban": ip_ban_manager_for(config, bind=True),
        "cloud": cloud_handler_for(config, bind=True),
        "suspatterns": sus_patterns_manager_for(config, bind=True),
    }


def _the_defaults() -> dict[str, object]:
    return {
        "ipban": ipban_module.ip_ban_manager,
        "cloud": cloud_module.cloud_handler,
        "suspatterns": patterns_module.sus_patterns_handler,
    }


def _which_each_kind_got(config: SecurityConfig) -> dict[str, str]:
    defaults = _the_defaults()
    bound = _bind_every_kind(config)
    return {k: "default" if bound[k] is defaults[k] else "own" for k in _KINDS}


def _bind_an_app_and_drop_it(released: bool) -> None:
    """A framework app is cyclic, so it is freed only when the collector runs."""
    config = _no_redis_config()
    _bind_every_kind(config)
    app: dict[str, object] = {"config": config}
    app["self"] = app
    if released:
        release_app(config)


def _next_app_after_a_dropped_one(mode: str, released: bool) -> dict[str, str]:
    _forget_every_default()
    _bind_an_app_and_drop_it(released)
    if mode == "gc_collect":
        gc.collect()
    junk = [[] for _ in range(len(_KINDS) * 400)]
    del junk
    return _which_each_kind_got(_no_redis_config())


@pytest.mark.parametrize("mode", ["gc_disabled", "gc_collect", "gc_default"])
def test_the_next_app_gets_the_default_after_a_release_in_every_gc_mode(
    mode: str,
) -> None:
    was_enabled = gc.isenabled()
    try:
        if mode == "gc_disabled":
            gc.disable()
        for _ in range(_RUNS):
            outcome = _next_app_after_a_dropped_one(mode, released=True)
            assert outcome == dict.fromkeys(_KINDS, "default")
    finally:
        if was_enabled:
            gc.enable()


def test_an_unreleased_app_keeps_the_handoff_that_waits_for_the_collector() -> None:
    was_enabled = gc.isenabled()
    try:
        gc.disable()
        for _ in range(_RUNS):
            outcome = _next_app_after_a_dropped_one("gc_disabled", released=False)
            assert outcome == dict.fromkeys(_KINDS, "own")
        for _ in range(_RUNS):
            outcome = _next_app_after_a_dropped_one("gc_collect", released=False)
            assert outcome == dict.fromkeys(_KINDS, "default")
    finally:
        if was_enabled:
            gc.enable()


def test_a_release_forgets_the_handlers_left_on_the_default() -> None:
    config = _no_redis_config()
    _bind_every_kind(config)
    default = ipban_module.ip_ban_manager
    default.__dict__["redis_handler"] = Mock()
    default.__dict__["agent_handler"] = Mock()
    release_app(config)
    assert default.redis_handler is None
    assert default.agent_handler is None


def test_a_release_forgets_the_released_apps_own_managers() -> None:
    first, second = _no_redis_config(), _no_redis_config()
    _bind_every_kind(first)
    own = _bind_every_kind(second)
    assert own["ipban"] is not ipban_module.ip_ban_manager
    release_app(second)
    assert ipban_module._APP_BAN_MANAGERS.own(second) is None
    assert cloud_module._APP_CLOUD_MANAGERS.own(second) is None
    assert patterns_module._APP_PATTERN_MANAGERS.own(second) is None
    assert ip_ban_manager_for(second) is ipban_module.ip_ban_manager


async def test_releasing_one_sharing_app_keeps_the_default_for_the_other() -> None:
    first, second = _redis_config("wp616:shared:"), _redis_config("wp616:shared:")
    _bind_every_kind(first)
    shared = _bind_every_kind(second)
    assert shared == _the_defaults()
    await ipban_module.ip_ban_manager.ban_ip(_BANNED_IP, 60, config=second)
    release_app(first)
    for kind, bound in _bind_every_kind(second).items():
        assert bound is _the_defaults()[kind]
    assert await ipban_module.ip_ban_manager.is_ip_banned(_BANNED_IP, config=second)
    third = _redis_config("wp616:shared:")
    assert _bind_every_kind(third) == _the_defaults()
    elsewhere = _redis_config("wp616:elsewhere:")
    assert _bind_every_kind(elsewhere)["ipban"] is not ipban_module.ip_ban_manager


async def test_releasing_both_sharing_apps_hands_the_default_back() -> None:
    first, second = _redis_config("wp616:pair:"), _redis_config("wp616:pair:")
    _bind_every_kind(first)
    _bind_every_kind(second)
    release_app(first)
    release_app(second)
    assert _which_each_kind_got(_redis_config("wp616:other:")) == dict.fromkeys(
        _KINDS, "default"
    )


def test_releasing_twice_or_a_config_no_app_was_bound_to_changes_nothing() -> None:
    never_bound = _no_redis_config()
    release_app(never_bound)
    config = _no_redis_config()
    _bind_every_kind(config)
    release_app(config)
    release_app(config)
    release_app(never_bound)
    assert _which_each_kind_got(_no_redis_config()) == dict.fromkeys(_KINDS, "default")


def test_a_released_app_binds_again_as_a_new_app() -> None:
    config = _no_redis_config()
    _bind_every_kind(config)
    release_app(config)
    assert _which_each_kind_got(config) == dict.fromkeys(_KINDS, "default")


async def test_a_late_request_on_an_app_with_own_managers_is_still_refused() -> None:
    first, late = _no_redis_config(), _no_redis_config()
    _bind_every_kind(first)
    _bind_every_kind(late)
    middleware = Mock()
    middleware.config = late
    middleware.logger = logging.getLogger("wp616_late_request")
    check = IpSecurityCheck(middleware)
    held = check.ip_ban_manager
    assert held is not ipban_module.ip_ban_manager
    assert await held.ban_ip(_BANNED_IP, 60)
    request = MockGuardRequest(path=_ATTACK, client_host="203.0.113.9")
    assert (await detect_penetration_attempt(request, late)).is_threat
    release_app(late)
    assert check.ip_ban_manager is held
    assert await held.is_ip_banned(_BANNED_IP)
    assert (await detect_penetration_attempt(request, late)).is_threat
    assert not await ipban_module.ip_ban_manager.is_ip_banned(_BANNED_IP)
    assert ip_ban_manager_for(late) is ipban_module.ip_ban_manager


async def test_a_late_request_on_the_default_holder_is_still_scanned() -> None:
    config = _no_redis_config()
    _bind_every_kind(config)
    request = MockGuardRequest(path=_ATTACK, client_host="203.0.113.9")
    assert (await detect_penetration_attempt(request, config)).is_threat
    release_app(config)
    assert (await detect_penetration_attempt(request, config)).is_threat


def _bind_the_dynamic_rules_default_and_drop_the_app(released: bool) -> None:
    config = _no_redis_config()
    DynamicRuleManager(config)
    app: dict[str, object] = {"config": config}
    app["self"] = app
    if released:
        release_app(config)


@pytest.mark.parametrize("mode", ["gc_disabled", "gc_collect"])
def test_the_dynamic_rules_default_goes_to_the_next_app_after_a_release(
    mode: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    was_enabled = gc.isenabled()
    try:
        if mode == "gc_disabled":
            gc.disable()
        for _ in range(_RUNS):
            monkeypatch.setattr(DynamicRuleManager, "_instance", None)
            _APP_RULE_MANAGERS.forget_default()
            _bind_the_dynamic_rules_default_and_drop_the_app(released=True)
            if mode == "gc_collect":
                gc.collect()
            second = _no_redis_config()
            manager = DynamicRuleManager(second)
            assert manager is DynamicRuleManager._instance
            assert manager.config is second
    finally:
        if was_enabled:
            gc.enable()


def test_the_dynamic_rules_default_stays_with_an_app_that_is_never_released() -> None:
    gc.collect()
    _bind_the_dynamic_rules_default_and_drop_the_app(released=False)
    gc.collect()
    manager = DynamicRuleManager(_no_redis_config())
    assert manager is not DynamicRuleManager._instance
