from ipaddress import ip_network

from guard_core._utils.access_control import check_ip_access
from guard_core.handlers import cloud_handler as cloud_module
from guard_core.handlers.cloud_handler import cloud_handler_for
from guard_core.handlers.suspatterns_handler import sus_patterns_manager_for
from guard_core.models import SecurityConfig
from guard_core.utils import detect_penetration_attempt
from tests.conftest import MockGuardRequest

CLOUD_RANGE = "198.51.100.0/24"
CLOUD_IP = "198.51.100.77"
CUSTOM_PATTERN = r"acmehouse_[0-9]{3}"


def _app(**settings: object) -> SecurityConfig:
    return SecurityConfig(
        enable_redis=False,
        enable_dynamic_rules=False,
        enable_penetration_detection=True,
        lazy_init=False,
        **settings,
    )


async def test_cloud_detail_comes_from_the_manager_that_decides() -> None:
    first = _app(block_cloud_providers={"AWS"})
    cloud_handler_for(first, bind=True)
    config = _app(block_cloud_providers={"AWS"})
    manager = cloud_handler_for(config, bind=True)
    assert manager is not cloud_module.cloud_handler
    manager.ip_ranges = {"AWS": {ip_network(CLOUD_RANGE)}}
    manager.network_regions = {"AWS": {CLOUD_RANGE: "region-1"}}
    assert not cloud_module.cloud_handler.is_cloud_ip(CLOUD_IP, {"AWS"})

    result = await check_ip_access(CLOUD_IP, config)

    assert not result.allowed
    assert result.cloud_provider == "AWS"
    assert result.network == CLOUD_RANGE


async def test_sensitive_names_of_one_app_do_not_redact_another_apps_patterns() -> None:
    first = _app()
    sus_patterns_manager_for(first, bind=True)
    app_a = _app(log_sensitive_params=frozenset({"acmehouse"}))
    app_b = _app()
    manager_a = sus_patterns_manager_for(app_a, bind=True)
    manager_b = sus_patterns_manager_for(app_b, bind=True)
    assert manager_a is not manager_b
    assert await manager_a.add_pattern(CUSTOM_PATTERN, custom=True)
    assert await manager_b.add_pattern(CUSTOM_PATTERN, custom=True)
    request = MockGuardRequest(path="/q?v=acmehouse_123", client_host="203.0.113.9")

    result_a = await detect_penetration_attempt(request, app_a)
    result_b = await detect_penetration_attempt(request, app_b)

    assert result_a.is_threat
    assert result_b.is_threat
    assert CUSTOM_PATTERN not in result_a.trigger_info
    assert CUSTOM_PATTERN in result_b.trigger_info
