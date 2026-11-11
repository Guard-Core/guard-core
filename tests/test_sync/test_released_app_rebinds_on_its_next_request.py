import uuid
from collections.abc import Iterator
from typing import TypeVar
from unittest.mock import MagicMock, Mock

import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.sync._utils.app_managers import release_app
from guard_core.sync._utils.app_scope import app_scope_of, in_app_scope
from guard_core.sync.core.checks import build_default_pipeline
from guard_core.sync.core.checks.base import SecurityCheck
from guard_core.sync.core.checks.implementations.ip_security import IpSecurityCheck
from guard_core.sync.core.checks.implementations.rate_limit import RateLimitCheck
from guard_core.sync.core.checks.pipeline import SecurityCheckPipeline
from guard_core.sync.core.initialization.handler_initializer import HandlerInitializer
from guard_core.sync.handlers import ipban_handler as ipban_module
from guard_core.sync.handlers import suspatterns_handler as patterns_module
from guard_core.sync.handlers.ipban_handler import IPBanManager, ip_ban_manager_for
from guard_core.sync.handlers.ratelimit_handler import RateLimitBlock
from guard_core.sync.handlers.redis_handler import RedisManager
from guard_core.sync.handlers.suspatterns_handler import sus_patterns_manager_for
from guard_core.sync.utils import detect_penetration_attempt
from tests.test_sync.conftest import SyncMockGuardRequest
from tests.test_sync.protocol_only_redis import REDIS_URL

_CheckT = TypeVar("_CheckT", bound=SecurityCheck)
_IP = "203.0.113.90"
_OTHER_WORKER_IP = "203.0.113.91"


@pytest.fixture(autouse=True)
def _defaults_unserved() -> Iterator[None]:
    ipban_module._APP_BAN_MANAGERS.forget_default()
    patterns_module._APP_PATTERN_MANAGERS.forget_default()
    yield
    ipban_module._APP_BAN_MANAGERS.forget_default()
    patterns_module._APP_PATTERN_MANAGERS.forget_default()
    ipban_module.ip_ban_manager.banned_ips.clear()


def _config(prefix: str, **settings: object) -> SyncSecurityConfig:
    return SyncSecurityConfig(
        enable_redis=True,
        redis_url=REDIS_URL,
        redis_prefix=prefix,
        enable_ip_banning=True,
        enable_rate_limiting=True,
        rate_limit=1,
        rate_limit_window=60,
        enable_rate_limit_auto_ban=True,
        auto_ban_threshold=2,
        **settings,
    )


def _middleware(config: SyncSecurityConfig, initializer: HandlerInitializer) -> Mock:
    middleware = Mock()
    middleware.config = config
    middleware.logger = Mock()
    middleware.handler_initializer = initializer
    middleware.guard_decorator = None
    middleware.event_bus = Mock()
    middleware.event_bus.send_middleware_event = MagicMock()
    middleware.create_error_response = MagicMock(return_value=Mock(status_code=403))
    middleware.route_resolver = Mock()
    middleware.route_resolver.should_bypass_check = Mock(return_value=False)
    middleware.geo_ip_handler = None
    middleware.suspicious_request_counts = {}
    middleware.rate_limit_handler = Mock(redis_handler=None)
    middleware.rate_limit_handler.report_rate_limit_block = MagicMock()
    middleware.rate_limit_handler.check_rate_limit_tiers = MagicMock(
        return_value=RateLimitBlock(0, 2, Mock(status_code=429))
    )
    return middleware


def _request(client_ip: str, path: str = "/api/test") -> MagicMock:
    request = MagicMock()
    request.state.client_ip = client_ip
    request.state.route_config = None
    request.state.is_whitelisted = False
    request.url_path = path
    request.url_full = f"https://test{path}"
    return request


def _check_of(pipeline: SecurityCheckPipeline, kind: type[_CheckT]) -> _CheckT:
    for check in pipeline.checks:
        if isinstance(check, kind):
            return check
    raise AssertionError(f"the pipeline has no {kind.__name__}")


def test_a_late_ban_after_another_app_took_the_default_lands_on_the_rebind() -> None:
    first = _config("wp616:r4-late-a:")
    initializer = HandlerInitializer(first)
    pipeline = build_default_pipeline(_middleware(first, initializer))
    release_app(first)
    second = _config("wp616:r4-late-b:")
    HandlerInitializer(second)
    default = ip_ban_manager_for(second)
    assert default is ipban_module.ip_ban_manager
    request = _request(_IP)
    assert pipeline._rebuild_response(request) is None
    own = ip_ban_manager_for(first)
    assert own is not default
    limiter = _check_of(pipeline, RateLimitCheck)
    limiter.check(request)
    limiter.check(request)
    assert limiter.ip_ban_manager is own
    assert own.is_ip_banned(_IP, config=first)
    assert not default.is_ip_banned(_IP, config=second)


def test_a_redis_ban_of_another_worker_is_refused_after_release() -> None:
    prefix = f"wp616:r4-redis-{uuid.uuid4().hex[:8]}:"
    config = _config(prefix)
    redis = RedisManager(config)
    initializer = HandlerInitializer(config, redis_handler=redis)
    initializer.initialize_redis_handlers()
    pipeline = build_default_pipeline(_middleware(config, initializer))
    other_redis = RedisManager(_config(prefix))
    other_redis.initialize()
    other_worker = IPBanManager._fresh()
    other_worker.initialize_redis(other_redis)
    try:
        release_app(config)
        assert other_worker.ban_ip(_OTHER_WORKER_IP, 120)
        request = _request(_OTHER_WORKER_IP)
        assert pipeline._rebuild_response(request) is None
        with in_app_scope(app_scope_of(config)):
            refused = _check_of(pipeline, IpSecurityCheck).check(request)
        assert refused is not None and refused.status_code == 403
    finally:
        other_redis.delete_pattern("*")
        redis.close()
        other_redis.close()


def test_config_state_is_enforced_and_a_runtime_pattern_is_gone() -> None:
    config = _config("wp616:r4-declared:", blacklist=[_IP])
    initializer = HandlerInitializer(config)
    initializer.initialize_redis_handlers()
    pipeline = build_default_pipeline(_middleware(config, initializer))
    assert sus_patterns_manager_for(config).add_pattern(r"zzcustomzz", custom=True)
    runtime = SyncMockGuardRequest(path="/s?q=zzcustomzz", client_host="203.0.113.9")
    assert (detect_penetration_attempt(runtime, config)).is_threat
    release_app(config)
    request = _request(_IP)
    assert pipeline._rebuild_response(request) is None
    assert not (detect_penetration_attempt(runtime, config)).is_threat
    with in_app_scope(app_scope_of(config)):
        refused = _check_of(pipeline, IpSecurityCheck).check(request)
    assert refused is not None and refused.status_code == 403
