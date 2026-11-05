import copy
import pickle
import sys
import threading
from collections.abc import Callable
from ipaddress import IPv6Network
from typing import Any
from unittest.mock import AsyncMock, MagicMock, Mock

import pytest

from guard_core._utils.app_managers import held_for_app, hold_for_app
from guard_core._utils.app_scope import app_scope_of, existing_app_scope_of
from guard_core._utils.nat64 import (
    DEFAULT_NAT64_TABLE,
    configure_nat64_prefixes,
    nat64_table_of,
)
from guard_core.core.checks.base import SecurityCheck
from guard_core.core.checks.pipeline import SecurityCheckPipeline
from guard_core.core.initialization.handler_initializer import HandlerInitializer
from guard_core.handlers.ipban_handler import ip_ban_manager_for
from guard_core.handlers.redis_handler import RedisManager
from guard_core.handlers.suspatterns_handler import sus_patterns_manager_for
from guard_core.models import SecurityConfig
from guard_core.protocols.middleware_protocol import GuardMiddlewareProtocol
from tests.conftest import MockGuardRequest, suite_redis_prefix
from tests.protocol_only_redis import REDIS_URL as LIVE_REDIS_URL

URL = "redis://user:hunter2@one.invalid:6379/0"
PREFIX = "wp460-copy:"
NAT64 = IPv6Network("2001:db8:64::/96")
PARKED_BY_THE_ENGINE = (
    "_guard_app_scope",
    "_guard_app_managers",
    "_guard_pattern_manager",
)

COPY_FORMS: dict[str, Callable[[SecurityConfig], SecurityConfig]] = {
    "model_copy": lambda config: config.model_copy(),
    "model_copy_update": lambda config: config.model_copy(update={"rate_limit": 7}),
    "model_copy_deep": lambda config: config.model_copy(deep=True),
    "copy.copy": copy.copy,
    "deepcopy": copy.deepcopy,
    "pickle": lambda config: pickle.loads(pickle.dumps(config)),
}
if sys.version_info >= (3, 13):
    COPY_FORMS["copy.replace"] = lambda config: copy.replace(config, rate_limit=7)


def _base_config() -> SecurityConfig:
    return SecurityConfig(
        enable_redis=True,
        redis_url=URL,
        redis_prefix=PREFIX,
        trusted_proxies=["10.0.0.1"],
        enable_agent=False,
    )


async def _start(config: SecurityConfig) -> tuple[Any, HandlerInitializer]:
    redis = MagicMock()
    redis.initialize = AsyncMock()
    redis.initialize_agent = AsyncMock()
    redis.get_key = AsyncMock(return_value=None)
    agent = MagicMock()
    for name in ("initialize_redis", "start", "flush_buffer", "send_event"):
        setattr(agent, name, AsyncMock())
    initializer = HandlerInitializer(config, redis_handler=redis, agent_handler=agent)
    await initializer.initialize_redis_handlers()
    await initializer.initialize_agent_integrations()
    return redis, initializer


class _SeesManagers(SecurityCheck):
    check_name = "sees_managers"

    def __init__(
        self, middleware: GuardMiddlewareProtocol, seen: dict[str, Any]
    ) -> None:
        super().__init__(middleware)
        self.seen = seen

    async def check(self, request: object) -> None:
        ban = ip_ban_manager_for(self.config)
        self.seen["redis"] = ban.redis_handler
        self.seen["config"] = ban.config
        self.seen["refusal"] = ban._self_dos_refusal_reason("10.0.0.1")
        return None


async def _run_request(config: SecurityConfig) -> dict[str, Any]:
    seen: dict[str, Any] = {}
    middleware = Mock(config=config)
    pipeline = SecurityCheckPipeline([_SeesManagers(middleware, seen)], config=config)
    request = MockGuardRequest(client_host="203.0.113.5", path="/")
    assert await pipeline.execute(request) is None
    return seen


async def test_an_app_built_from_a_copied_config_routes_its_own_handlers() -> None:
    base = _base_config()
    base_redis, _ = await _start(base)
    copied = base.model_copy(update={"trusted_proxies": []})
    copied_redis, _ = await _start(copied)

    seen_base = await _run_request(base)
    seen_copied = await _run_request(copied)

    assert seen_base["redis"] is base_redis
    assert seen_base["config"] is base
    assert seen_base["refusal"] == "trusted_proxy"
    assert seen_copied["redis"] is copied_redis
    assert seen_copied["config"] is copied
    assert seen_copied["refusal"] is None


@pytest.mark.parametrize("form", COPY_FORMS)
async def test_a_copy_gets_an_app_scope_of_its_own(form: str) -> None:
    base = _base_config()
    await _start(base)
    scope = app_scope_of(base)
    scope.rule_exempt_networks = ()
    scope.redis_handler = MagicMock()

    clone = COPY_FORMS[form](base)

    assert existing_app_scope_of(clone) is None
    clone_scope = app_scope_of(clone)
    assert clone_scope is not scope
    assert clone_scope.config is clone
    assert clone_scope.redis_handler is None
    assert app_scope_of(base) is scope
    assert scope.config is base


@pytest.mark.parametrize("form", COPY_FORMS)
def test_a_copy_gets_the_managers_held_of_its_own(form: str) -> None:
    base = SecurityConfig(enable_redis=False)
    table = configure_nat64_prefixes(base, [NAT64])
    manager = object()
    hold_for_app(base, "wp460-kind", manager)

    clone = COPY_FORMS[form](base)

    assert nat64_table_of(clone) is DEFAULT_NAT64_TABLE
    assert held_for_app(clone, "wp460-kind") is None
    clone_table = configure_nat64_prefixes(clone, [])
    assert hold_for_app(clone, "wp460-kind", object())
    assert nat64_table_of(clone) is clone_table
    assert nat64_table_of(base) is table
    assert held_for_app(base, "wp460-kind") is manager


@pytest.mark.parametrize("form", COPY_FORMS)
async def test_a_copy_gets_the_pattern_manager_of_its_own(form: str) -> None:
    base = SecurityConfig(enable_redis=False, enable_agent=False)
    manager = sus_patterns_manager_for(base, bind=True)
    manager.configure(base)
    assert base.__dict__["_guard_pattern_manager"] is manager

    clone = COPY_FORMS[form](base)

    assert "_guard_pattern_manager" not in clone.__dict__
    assert base.__dict__["_guard_pattern_manager"] is manager


@pytest.mark.parametrize("form", COPY_FORMS)
def test_a_copy_drops_every_record_the_engine_parks(form: str) -> None:
    base = SecurityConfig(enable_redis=False, enable_agent=False)
    app_scope_of(base)
    hold_for_app(base, "wp460-kind", object())
    sus_patterns_manager_for(base, bind=True).configure(base)
    assert all(name in base.__dict__ for name in PARKED_BY_THE_ENGINE)

    clone = COPY_FORMS[form](base)

    assert not [name for name in PARKED_BY_THE_ENGINE if name in clone.__dict__]
    assert all(name in base.__dict__ for name in PARKED_BY_THE_ENGINE)


@pytest.mark.parametrize("form", COPY_FORMS)
def test_the_revision_is_a_value_and_travels_with_a_copy(form: str) -> None:
    base = SecurityConfig(enable_redis=False)
    base.rate_limit = 9
    assert COPY_FORMS[form](base).revision >= base.revision


@pytest.mark.parametrize("form", COPY_FORMS)
def test_an_adapter_registers_a_record_and_a_copy_drops_it(
    form: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    from guard_core import _parked_records

    monkeypatch.setattr(
        _parked_records, "_PER_APP_RECORDS", _parked_records._PER_APP_RECORDS
    )
    _parked_records.register_per_app_record("_wp460_adapter_record")
    base = SecurityConfig(enable_redis=False)
    object.__setattr__(base, "_wp460_adapter_record", threading.Lock())

    clone = COPY_FORMS[form](base)

    assert "_wp460_adapter_record" not in clone.__dict__
    assert "_wp460_adapter_record" in base.__dict__


def test_a_config_that_was_not_copied_keeps_every_record() -> None:
    base = SecurityConfig(enable_redis=False)
    scope = app_scope_of(base)
    assert app_scope_of(base) is scope
    assert existing_app_scope_of(base) is scope
    assert configure_nat64_prefixes(base, [NAT64]) is nat64_table_of(base)


def test_a_lookup_refuses_a_record_whose_owner_is_another_config() -> None:
    base = SecurityConfig(enable_redis=False)
    scope = app_scope_of(base)
    table = configure_nat64_prefixes(base, [NAT64])
    hold_for_app(base, "wp460-kind", object())
    other = SecurityConfig(enable_redis=False)
    for name in ("_guard_app_scope", "_guard_app_managers"):
        other.__dict__[name] = base.__dict__[name]

    assert existing_app_scope_of(other) is None
    assert app_scope_of(other) is not scope
    assert app_scope_of(other).config is other
    assert nat64_table_of(other) is DEFAULT_NAT64_TABLE
    assert held_for_app(other, "wp460-kind") is None
    assert nat64_table_of(base) is table
    assert held_for_app(base, "wp460-kind") is not None


@pytest.mark.parametrize("form", ["deepcopy", "model_copy_deep", "pickle"])
async def test_the_config_of_an_app_started_on_a_real_redis_manager_can_be_copied(
    form: str,
) -> None:
    config = SecurityConfig(
        enable_redis=True,
        redis_url=LIVE_REDIS_URL,
        redis_prefix=suite_redis_prefix("wp460-live"),
        enable_agent=False,
    )
    manager = RedisManager(config)
    initializer = HandlerInitializer(config, redis_handler=manager)
    try:
        await initializer.initialize_redis_handlers()
        sus_patterns_manager_for(config, bind=True).configure(config)
        assert app_scope_of(config).redis_handler is manager

        clone = COPY_FORMS[form](config)

        assert existing_app_scope_of(clone) is None
        assert app_scope_of(clone).redis_handler is None
        assert app_scope_of(config).redis_handler is manager
        assert clone.redis_prefix == config.redis_prefix
    finally:
        await manager.close()


@pytest.mark.parametrize("form", ["deepcopy", "model_copy_deep", "pickle"])
def test_the_config_of_an_app_that_holds_tables_can_be_copied_without_redis(
    form: str,
) -> None:
    from guard_core.handlers.ratelimit_handler import _by_ip_request_timestamps

    config = SecurityConfig(enable_redis=False)
    _by_ip_request_timestamps.for_app(config)
    configure_nat64_prefixes(config, [NAT64])

    clone = COPY_FORMS[form](config)

    assert nat64_table_of(clone) is DEFAULT_NAT64_TABLE
    assert _by_ip_request_timestamps.for_app(clone) is not (
        _by_ip_request_timestamps.for_app(config)
    )
