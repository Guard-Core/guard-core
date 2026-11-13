import logging
import os
import uuid
from collections.abc import Iterator
from typing import Any

import pytest

from guard_core.exceptions import DownloaderNotInstalledError, MisconfigurationError
from guard_core.models import SyncSecurityConfig
from guard_core.sync._utils.app_scope import app_scope_of
from guard_core.sync.core.initialization.handler_initializer import HandlerInitializer
from guard_core.sync.decorators import SecurityDecorator
from guard_core.sync.decorators.base import BaseSecurityDecorator
from guard_core.sync.handlers.behavior_handler import BehaviorRule, BehaviorTracker
from guard_core.sync.handlers.ipban_handler import ip_ban_manager, ip_ban_manager_for
from guard_core.sync.handlers.redis_handler import RedisManager

REDIS_URL = os.getenv("REDIS_URL") or "redis://localhost:6379"
_RATE_LIMIT_LINE = "the rate limits of these routes stay on"


class _FakeAgent:
    def start(self) -> None:
        return None

    def stop(self) -> None:
        return None

    def send_event(self, _: object) -> None:
        return None

    def send_metric(self, _: object) -> None:
        return None

    def initialize_redis(self, _: object) -> None:
        return None

    def flush_buffer(self) -> None:
        return None

    def get_dynamic_rules(self) -> None:
        return None

    def health_check(self) -> bool:
        return True

    def get_stats(self) -> dict[str, Any]:
        return {}


def _app_config(with_agent: bool = False) -> SyncSecurityConfig:
    return SyncSecurityConfig(
        enable_redis=True,
        redis_url=REDIS_URL,
        redis_prefix=f"adopt-{uuid.uuid4().hex[:8]}:",
        enable_rate_limiting=False,
        enable_agent=with_agent,
        agent_api_key="a" * 10 if with_agent else None,
        enable_enrichment=with_agent,
    )


def _tracker_of(initializer: HandlerInitializer) -> BehaviorTracker | None:
    return initializer.behavior_tracker


def _decorator_with_a_limited_route() -> SecurityDecorator:
    decorator = SecurityDecorator(SyncSecurityConfig())

    def limited() -> None:
        return None

    decorator.rate_limit(5, 60)(limited)
    return decorator


def _decorator_with_a_country_rule() -> SecurityDecorator:
    decorator = SecurityDecorator(SyncSecurityConfig(fail_on_misconfiguration=False))

    def by_country() -> None:
        return None

    decorator.block_countries(["XX"])(by_country)
    return decorator


def _start(
    config: SyncSecurityConfig,
    redis: RedisManager,
    decorator: BaseSecurityDecorator | None,
    with_agent: bool,
) -> HandlerInitializer:
    initializer = HandlerInitializer(
        config,
        redis_handler=redis,
        agent_handler=_FakeAgent() if with_agent else None,
        guard_decorator=decorator,
    )
    initializer.initialize_redis_handlers()
    initializer.initialize_agent_integrations()
    return initializer


def _config_of_the_variant(with_agent: bool) -> SyncSecurityConfig:
    return _app_config(with_agent)


def _state_of(
    initializer: HandlerInitializer, decorator: BaseSecurityDecorator
) -> dict[str, object]:
    tracker = decorator.behavior_tracker
    enricher = initializer.enricher
    return {
        "decorator_tracker_ban_manager_is_the_apps": tracker.bound_ban_manager
        is ip_ban_manager_for(initializer.config),
        "decorator_tracker_redis_is_the_apps": tracker.redis_handler
        is initializer.redis_handler,
        "initializer_tracker": (
            "none"
            if initializer.behavior_tracker is None
            else "the decorator's"
            if initializer.behavior_tracker is tracker
            else "another"
        ),
        "enricher_tracker": (
            "no enricher"
            if enricher is None
            else "the decorator's"
            if enricher._context.behavior_tracker is tracker
            else "another"
        ),
        "decorator_agent_is_the_telemetry": decorator.agent_handler
        is initializer.composite_handler
        if initializer.composite_handler is not None
        else decorator.agent_handler is None,
    }


@pytest.fixture
def redis_managers() -> Iterator[list[RedisManager]]:
    managers: list[RedisManager] = []
    yield managers
    for manager in managers:
        manager.close()


def _redis_of(config: SyncSecurityConfig, managers: list[RedisManager]) -> RedisManager:
    manager = RedisManager(config)
    managers.append(manager)
    return manager


@pytest.mark.parametrize("with_agent", [False, True], ids=["defaults", "agent-on"])
def test_a_decorator_adopted_late_ends_as_one_given_at_construction(
    with_agent: bool, redis_managers: list[RedisManager]
) -> None:
    config_built_with = _config_of_the_variant(with_agent)
    built_with = BaseSecurityDecorator(SyncSecurityConfig())
    initializer_built_with = _start(
        config_built_with,
        _redis_of(config_built_with, redis_managers),
        built_with,
        with_agent,
    )

    config_adopting = _config_of_the_variant(with_agent)
    adopted = BaseSecurityDecorator(SyncSecurityConfig())
    initializer_adopting = _start(
        config_adopting,
        _redis_of(config_adopting, redis_managers),
        None,
        with_agent,
    )
    initializer_adopting.adopt_decorator(adopted)
    initializer_adopting.complete_decorator_adoption()

    assert initializer_adopting.guard_decorator is adopted
    assert _state_of(initializer_adopting, adopted) == _state_of(
        initializer_built_with, built_with
    )


def test_a_decorator_adopted_before_the_apps_startup_is_started_with_it(
    redis_managers: list[RedisManager],
) -> None:
    config = _app_config()
    adopted = BaseSecurityDecorator(SyncSecurityConfig())
    initializer = HandlerInitializer(
        config, redis_handler=_redis_of(config, redis_managers)
    )
    initializer.adopt_decorator(adopted)
    initializer.complete_decorator_adoption()
    assert adopted.behavior_tracker.redis_handler is None

    initializer.initialize_redis_handlers()

    assert adopted.behavior_tracker.redis_handler is initializer.redis_handler
    assert initializer.behavior_tracker is None


def test_adopting_a_decorator_drops_the_initializers_own_tracker(
    redis_managers: list[RedisManager],
) -> None:
    config = _app_config()
    initializer = _start(config, _redis_of(config, redis_managers), None, False)
    own_tracker = initializer.behavior_tracker
    assert own_tracker is not None
    adopted = BaseSecurityDecorator(SyncSecurityConfig())

    initializer.adopt_decorator(adopted)

    assert initializer.behavior_tracker is None
    assert adopted.behavior_tracker.bound_ban_manager is ip_ban_manager_for(config)


def test_a_behavior_ban_of_a_late_decorator_reaches_the_apps_ban_manager(
    redis_managers: list[RedisManager],
) -> None:
    first_config = _app_config()
    first = HandlerInitializer(first_config)
    config = _app_config()
    initializer = HandlerInitializer(
        config, redis_handler=_redis_of(config, redis_managers)
    )
    apps_manager = ip_ban_manager_for(config)
    assert apps_manager is not ip_ban_manager
    decorator = BaseSecurityDecorator(SyncSecurityConfig())

    initializer.adopt_decorator(decorator)
    rule = BehaviorRule(rule_type="usage", threshold=1, action="ban")
    decorator.behavior_tracker._execute_ban_action("203.0.113.7", "d", rule)

    assert apps_manager.is_ip_banned("203.0.113.7")
    assert first.config is first_config


def test_a_request_after_a_late_adoption_sees_the_decorators_redis_once_completed(
    redis_managers: list[RedisManager],
) -> None:
    config = _app_config()
    initializer = _start(config, _redis_of(config, redis_managers), None, False)
    adopted = BaseSecurityDecorator(SyncSecurityConfig())

    initializer.adopt_decorator(adopted)
    assert adopted.behavior_tracker.redis_handler is None
    initializer.complete_decorator_adoption()

    assert adopted.behavior_tracker.redis_handler is initializer.redis_handler


def test_adopting_none_gives_the_initializer_its_own_tracker(
    redis_managers: list[RedisManager],
) -> None:
    config = _app_config()
    decorator = BaseSecurityDecorator(SyncSecurityConfig())
    initializer = _start(config, _redis_of(config, redis_managers), decorator, False)
    assert _tracker_of(initializer) is None

    initializer.adopt_decorator(None)
    initializer.complete_decorator_adoption()

    own = _tracker_of(initializer)
    assert initializer.guard_decorator is None
    assert isinstance(own, BehaviorTracker)
    assert own.bound_ban_manager is ip_ban_manager_for(config)
    assert own.redis_handler is initializer.redis_handler
    initializer.adopt_decorator(None)
    assert _tracker_of(initializer) is own


@pytest.mark.parametrize("started_first", [False, True], ids=["before", "after"])
def test_a_route_misconfiguration_is_reported_once_across_adopt_and_startup(
    started_first: bool,
    caplog: pytest.LogCaptureFixture,
    redis_managers: list[RedisManager],
) -> None:
    config = _app_config()
    redis = _redis_of(config, redis_managers)
    caplog.set_level(logging.INFO, logger="guard_core.sync.core.initialization")
    if started_first:
        initializer = _start(config, redis, None, False)
    else:
        initializer = HandlerInitializer(config, redis_handler=redis)

    initializer.adopt_decorator(_decorator_with_a_limited_route())
    initializer.complete_decorator_adoption()
    if not started_first:
        initializer.initialize_redis_handlers()

    assert sum(_RATE_LIMIT_LINE in m for m in caplog.messages) == 1


def test_a_raising_report_keeps_the_previous_decorator_and_reports_again_on_retry(
    redis_managers: list[RedisManager],
) -> None:
    config = _app_config()
    previous = BaseSecurityDecorator(SyncSecurityConfig())
    initializer = HandlerInitializer(
        config,
        redis_handler=_redis_of(config, redis_managers),
        guard_decorator=previous,
    )
    candidate = _decorator_with_a_country_rule()
    candidate.config.fail_on_misconfiguration = True

    for _ in range(2):
        with pytest.raises(MisconfigurationError):
            initializer.adopt_decorator(candidate)
        assert initializer.guard_decorator is previous
        assert initializer.behavior_tracker is None
        assert candidate.behavior_tracker.bound_ban_manager is None


def test_a_missing_downloader_with_a_country_rule_keeps_the_previous_decorator(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = SyncSecurityConfig(ipinfo_token="token")
    previous = BaseSecurityDecorator(SyncSecurityConfig())
    initializer = HandlerInitializer(config, guard_decorator=previous)
    candidate = _decorator_with_a_country_rule()

    def downloader_missing(*_: object, **__: object) -> None:
        raise DownloaderNotInstalledError("no downloader")

    monkeypatch.setattr(
        "guard_core.sync.handlers._downloader.require_downloader_installed",
        downloader_missing,
    )

    with pytest.raises(DownloaderNotInstalledError):
        initializer.adopt_decorator(candidate)

    assert initializer.guard_decorator is previous
    assert initializer.geo_ip_handler is None
    assert candidate.behavior_tracker.bound_ban_manager is None


def test_a_late_decorator_with_a_country_rule_gets_the_geo_handler_built() -> None:
    config = SyncSecurityConfig(ipinfo_token="token")
    built_with = HandlerInitializer(
        config, guard_decorator=_decorator_with_a_country_rule()
    )
    built_with.report_route_misconfigurations()
    adopting = HandlerInitializer(SyncSecurityConfig(ipinfo_token="token"))
    assert adopting.geo_ip_handler is None

    adopting.adopt_decorator(_decorator_with_a_country_rule())

    assert type(adopting.geo_ip_handler) is type(built_with.geo_ip_handler)
    assert adopting.geo_ip_handler is not None


def test_complete_raising_once_stays_pending_and_succeeds_on_the_next_call(
    monkeypatch: pytest.MonkeyPatch, redis_managers: list[RedisManager]
) -> None:
    config = _app_config()
    initializer = _start(config, _redis_of(config, redis_managers), None, False)
    adopted = BaseSecurityDecorator(SyncSecurityConfig())
    calls: list[int] = []
    real = adopted.initialize_behavior_tracking

    def fails_once(redis_handler: RedisManager | None = None) -> None:
        calls.append(1)
        if len(calls) == 1:
            raise RuntimeError("redis step failed")
        real(redis_handler)

    monkeypatch.setattr(adopted, "initialize_behavior_tracking", fails_once)
    initializer.adopt_decorator(adopted)

    with pytest.raises(RuntimeError, match="redis step failed"):
        initializer.complete_decorator_adoption()
    initializer.complete_decorator_adoption()
    initializer.complete_decorator_adoption()

    assert len(calls) == 2
    assert adopted.behavior_tracker.redis_handler is initializer.redis_handler


def test_two_adoptions_before_a_completion_complete_only_the_last(
    redis_managers: list[RedisManager],
) -> None:
    config = _app_config()
    initializer = _start(config, _redis_of(config, redis_managers), None, False)
    first = BaseSecurityDecorator(SyncSecurityConfig())
    last = BaseSecurityDecorator(SyncSecurityConfig())

    initializer.adopt_decorator(first)
    initializer.adopt_decorator(last)
    initializer.complete_decorator_adoption()

    assert first.behavior_tracker.redis_handler is None
    assert last.behavior_tracker.redis_handler is initializer.redis_handler


def test_completing_with_nothing_pending_runs_no_step(
    monkeypatch: pytest.MonkeyPatch, redis_managers: list[RedisManager]
) -> None:
    config = _app_config()
    decorator = BaseSecurityDecorator(SyncSecurityConfig())
    initializer = _start(config, _redis_of(config, redis_managers), decorator, False)
    calls: list[int] = []

    def counted(_: object = None) -> None:
        calls.append(1)

    monkeypatch.setattr(decorator, "initialize_behavior_tracking", counted)

    initializer.complete_decorator_adoption()

    assert calls == []


def test_a_release_and_reinitialization_leaves_no_adoption_pending(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = SyncSecurityConfig()
    initializer = HandlerInitializer(config)
    adopted = BaseSecurityDecorator(SyncSecurityConfig())
    calls: list[int] = []

    def counted(_: object = None) -> None:
        calls.append(1)

    monkeypatch.setattr(adopted, "initialize_behavior_tracking", counted)
    initializer.adopt_decorator(adopted)

    initializer.reinitialize_after_release()
    monkeypatch.setattr(app_scope_of(config), "redis_handler", object())
    initializer.complete_decorator_adoption()

    assert calls == []


def test_an_adoption_during_a_reinitialization_stays_pending(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = SyncSecurityConfig()
    late = BaseSecurityDecorator(SyncSecurityConfig())
    calls: list[int] = []

    def counted(_: object = None) -> None:
        calls.append(1)

    monkeypatch.setattr(late, "initialize_behavior_tracking", counted)

    class _AdoptingDuringStartup(HandlerInitializer):
        def initialize_redis_handlers(self) -> None:
            super().initialize_redis_handlers()
            self.adopt_decorator(late)

    initializer = _AdoptingDuringStartup(config)

    initializer.reinitialize_after_release()
    monkeypatch.setattr(app_scope_of(config), "redis_handler", object())
    initializer.complete_decorator_adoption()

    assert calls == [1]
