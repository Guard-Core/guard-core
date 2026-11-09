import gc

from guard_core.core.initialization.handler_initializer import HandlerInitializer
from guard_core.handlers.suspatterns_handler import (
    sus_patterns_handler,
    sus_patterns_manager_for,
)
from guard_core.models import SecurityConfig

_GONE_APPS_ROW = "[xyz]7gone"
_GONE_APPS_PROBE = "abcxyz7gonedef"
_OWN_ROW = "[uvw]8own"
_OWN_PROBE = "abcuvw8owndef"


def _config(flag_bare_union_select: bool = True) -> SecurityConfig:
    return SecurityConfig(
        enable_redis=False,
        enable_rate_limiting=False,
        enable_ip_banning=False,
        flag_bare_union_select=flag_bare_union_select,
    )


async def _run_an_app_with_a_custom_pattern_and_let_it_go() -> None:
    config = _config(flag_bare_union_select=False)
    await HandlerInitializer(config).initialize_redis_handlers()
    await sus_patterns_manager_for(config).add_pattern(_GONE_APPS_ROW, custom=True)
    assert sus_patterns_handler.custom_patterns == {_GONE_APPS_ROW}


async def test_a_new_app_does_not_inherit_the_custom_patterns_of_a_gone_app() -> None:
    await _run_an_app_with_a_custom_pattern_and_let_it_go()
    gc.collect()
    second = _config()
    HandlerInitializer(second)
    patterns = sus_patterns_manager_for(second)
    assert patterns is sus_patterns_handler
    assert patterns.custom_patterns == set()
    assert patterns.compiled_custom_patterns == set()
    assert patterns._disabled_row_sources == frozenset()
    assert patterns._compiler is None
    assert patterns._preprocessor is None

    await HandlerInitializer(second).initialize_redis_handlers()
    try:
        scan = await patterns.detect(_GONE_APPS_PROBE, "1.2.3.4", "query_param")
        assert not any(t.get("pattern") == _GONE_APPS_ROW for t in scan["threats"])

        assert await patterns.add_pattern(_OWN_ROW, custom=True)
        own_scan = await patterns.detect(_OWN_PROBE, "1.2.3.4", "query_param")
        assert any(t.get("pattern") == _OWN_ROW for t in own_scan["threats"])
        assert patterns.custom_patterns == {_OWN_ROW}
    finally:
        await patterns.remove_pattern(_OWN_ROW, custom=True)


_STARTUP_ROW = "[qrs]9startup"
_STARTUP_PROBE = "abcqrs9startupdef"


async def test_a_custom_pattern_added_before_any_app_outlives_a_gone_app() -> None:
    assert await sus_patterns_handler.add_pattern(_STARTUP_ROW, custom=True)
    await _run_an_app_with_a_custom_pattern_and_let_it_go_keeping(_STARTUP_ROW)
    gc.collect()
    second = _config()
    await HandlerInitializer(second).initialize_redis_handlers()
    patterns = sus_patterns_manager_for(second)
    try:
        assert patterns is sus_patterns_handler
        assert patterns.custom_patterns == {_STARTUP_ROW}
        scan = await patterns.detect(_STARTUP_PROBE, "1.2.3.4", "query_param")
        assert any(t.get("pattern") == _STARTUP_ROW for t in scan["threats"])
        gone_scan = await patterns.detect(_GONE_APPS_PROBE, "1.2.3.4", "query_param")
        assert not any(t.get("pattern") == _GONE_APPS_ROW for t in gone_scan["threats"])
    finally:
        await patterns.remove_pattern(_STARTUP_ROW, custom=True)


async def _run_an_app_with_a_custom_pattern_and_let_it_go_keeping(row: str) -> None:
    config = _config()
    await HandlerInitializer(config).initialize_redis_handlers()
    await sus_patterns_manager_for(config).add_pattern(_GONE_APPS_ROW, custom=True)
    assert sus_patterns_handler.custom_patterns == {row, _GONE_APPS_ROW}
