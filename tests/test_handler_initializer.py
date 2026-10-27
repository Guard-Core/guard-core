from guard_core.core.initialization.handler_initializer import HandlerInitializer
from guard_core.handlers.behavior_handler import BehaviorTracker
from guard_core.models import SecurityConfig
from guard_core.protocols.agent_protocol import JsonValue


class _Agent:
    async def start(self) -> None:
        return None

    async def stop(self) -> None:
        return None

    async def send_event(self, _: object) -> None:
        return None

    async def send_metric(self, _: object) -> None:
        return None

    async def initialize_redis(self, _: object) -> None:
        return None

    async def flush_buffer(self) -> None:
        return None

    async def get_dynamic_rules(self) -> None:
        return None

    async def health_check(self) -> bool:
        return True

    def get_stats(self) -> dict[str, JsonValue]:
        return {}


async def test_build_enricher_uses_decorator_tracker_when_present() -> None:
    config = SecurityConfig(
        enable_agent=True,
        agent_api_key="k" * 10,
        agent_project_id="p",
        enable_enrichment=True,
    )
    tracker = object()
    decorator = type("D", (), {"behavior_tracker": tracker})()
    init = HandlerInitializer(
        config=config,
        redis_handler=None,
        agent_handler=_Agent(),
        geo_ip_handler=None,
        rate_limit_handler=None,
        guard_decorator=decorator,
    )
    enricher = init.build_enricher()
    assert enricher is not None
    assert enricher._context.behavior_tracker is tracker


async def test_build_enricher_builds_owned_tracker_when_decorator_missing() -> None:
    config = SecurityConfig(
        enable_agent=True,
        agent_api_key="k" * 10,
        agent_project_id="p",
        enable_enrichment=True,
    )
    init = HandlerInitializer(
        config=config,
        redis_handler=None,
        agent_handler=_Agent(),
        geo_ip_handler=None,
        rate_limit_handler=None,
        guard_decorator=None,
    )
    enricher = init.build_enricher()
    assert enricher is not None
    assert isinstance(enricher._context.behavior_tracker, BehaviorTracker)


async def test_build_enricher_builds_owned_tracker_when_decorator_has_none() -> None:
    config = SecurityConfig(
        enable_agent=True,
        agent_api_key="k" * 10,
        agent_project_id="p",
        enable_enrichment=True,
    )
    decorator = type("D", (), {"behavior_tracker": None})()
    init = HandlerInitializer(
        config=config,
        redis_handler=None,
        agent_handler=_Agent(),
        geo_ip_handler=None,
        rate_limit_handler=None,
        guard_decorator=decorator,
    )
    enricher = init.build_enricher()
    assert enricher is not None
    assert isinstance(enricher._context.behavior_tracker, BehaviorTracker)


async def test_build_enricher_stores_owned_tracker_on_initializer() -> None:
    config = SecurityConfig(
        enable_agent=True,
        agent_api_key="k" * 10,
        agent_project_id="p",
        enable_enrichment=True,
    )
    init = HandlerInitializer(
        config=config,
        redis_handler=None,
        agent_handler=_Agent(),
        geo_ip_handler=None,
        rate_limit_handler=None,
        guard_decorator=None,
    )
    standalone_tracker = init.behavior_tracker
    assert isinstance(standalone_tracker, BehaviorTracker)
    init.build_enricher()
    assert init.behavior_tracker is standalone_tracker
