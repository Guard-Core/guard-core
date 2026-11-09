import gc
from collections.abc import Iterator

import pytest

from guard_core.core.initialization.handler_initializer import HandlerInitializer
from guard_core.handlers import suspatterns_handler as suspatterns_module
from guard_core.handlers.suspatterns_handler import (
    SusPatternsManager,
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
    assert _GONE_APPS_ROW in sus_patterns_handler.custom_patterns


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
        await SusPatternsManager.reset()


async def _run_an_app_with_a_custom_pattern_and_let_it_go_keeping(row: str) -> None:
    config = _config()
    await HandlerInitializer(config).initialize_redis_handlers()
    await sus_patterns_manager_for(config).add_pattern(_GONE_APPS_ROW, custom=True)
    assert {row, _GONE_APPS_ROW} <= sus_patterns_handler.custom_patterns


_BUILT_IN_SCRIPT_ROW = r"<script[^>]*>[^<]*<\/script\s*>"
_BUILT_IN_SCRIPT_PROBE = "<script>alert(1)</script>"
_ADDED_DEFAULT_ROW = "[ab]c1d2default"
_ADDED_DEFAULT_PROBE = "xabc1d2defaultx"


@pytest.fixture
def default_built_in_rows_restored() -> Iterator[None]:
    patterns = list(sus_patterns_handler.patterns)
    compiled = sus_patterns_handler.__dict__.get("compiled_patterns")
    compiled_rows = None if compiled is None else list(compiled)
    sus_patterns_handler.__dict__.pop("compiled_patterns", None)
    yield
    sus_patterns_handler.__dict__.pop("_rows_before_the_first_app", None)
    sus_patterns_handler.custom_patterns.clear()
    sus_patterns_handler.compiled_custom_patterns.clear()
    sus_patterns_handler.patterns[:] = patterns
    if compiled_rows is None:
        sus_patterns_handler.__dict__.pop("compiled_patterns", None)
    else:
        sus_patterns_handler.__dict__["compiled_patterns"] = compiled_rows


async def _hits(manager: SusPatternsManager, probe: str) -> bool:
    scan = await manager.detect(probe, "1.2.3.4", "query_param")
    return bool(scan["is_threat"])


async def _run_an_app_that_edits_built_in_rows_and_let_it_go() -> None:
    config = _config()
    await HandlerInitializer(config).initialize_redis_handlers()
    patterns = sus_patterns_manager_for(config)
    await patterns.remove_pattern(_BUILT_IN_SCRIPT_ROW, custom=False)
    assert await patterns.add_pattern(_ADDED_DEFAULT_ROW, custom=False)
    assert _BUILT_IN_SCRIPT_ROW not in patterns.patterns
    assert not await _hits(patterns, _BUILT_IN_SCRIPT_PROBE)
    assert await _hits(patterns, _ADDED_DEFAULT_PROBE)


@pytest.mark.usefixtures("default_built_in_rows_restored")
async def test_a_new_app_does_not_inherit_the_built_in_row_edits_of_a_gone_app() -> (
    None
):
    await _run_an_app_that_edits_built_in_rows_and_let_it_go()
    gc.collect()
    second = _config()
    await HandlerInitializer(second).initialize_redis_handlers()
    patterns = sus_patterns_manager_for(second)
    assert patterns is sus_patterns_handler
    assert await _hits(patterns, _BUILT_IN_SCRIPT_PROBE)
    assert not await _hits(patterns, _ADDED_DEFAULT_PROBE)
    assert _BUILT_IN_SCRIPT_ROW in patterns.patterns
    assert _ADDED_DEFAULT_ROW not in patterns.patterns


@pytest.mark.usefixtures("default_built_in_rows_restored")
async def test_a_built_in_row_edit_made_before_any_app_outlives_a_gone_app() -> None:
    assert await sus_patterns_handler.remove_pattern(_BUILT_IN_SCRIPT_ROW, custom=False)
    assert await sus_patterns_handler.add_pattern(_STARTUP_ROW, custom=False)
    await _run_an_app_that_edits_built_in_rows_and_let_it_go()
    gc.collect()
    second = _config()
    await HandlerInitializer(second).initialize_redis_handlers()
    patterns = sus_patterns_manager_for(second)
    assert patterns is sus_patterns_handler
    assert not await _hits(patterns, _BUILT_IN_SCRIPT_PROBE)
    assert await _hits(patterns, _STARTUP_PROBE)
    assert not await _hits(patterns, _ADDED_DEFAULT_PROBE)


@pytest.mark.usefixtures("default_built_in_rows_restored")
async def test_forgetting_the_default_of_a_gone_app_leaves_no_rows_to_record() -> None:
    await _run_an_app_with_a_custom_pattern_and_let_it_go()
    await _run_an_app_that_edits_built_in_rows_and_let_it_go()
    gc.collect()
    suspatterns_module._APP_PATTERN_MANAGERS.forget_default()
    assert sus_patterns_handler.custom_patterns == set()
    assert _BUILT_IN_SCRIPT_ROW in sus_patterns_handler.patterns
    second = _config()
    await HandlerInitializer(second).initialize_redis_handlers()
    patterns = sus_patterns_manager_for(second)
    assert patterns is sus_patterns_handler
    assert await _hits(patterns, _BUILT_IN_SCRIPT_PROBE)
    assert patterns.custom_patterns == set()
    assert _ADDED_DEFAULT_ROW not in patterns.patterns


async def test_reset_forgets_the_rows_recorded_before_the_first_app() -> None:
    assert await sus_patterns_handler.add_pattern(_STARTUP_ROW, custom=True)
    await _run_an_app_with_a_custom_pattern_and_let_it_go()
    await SusPatternsManager.reset()
    gc.collect()
    second = _config()
    await HandlerInitializer(second).initialize_redis_handlers()
    assert sus_patterns_manager_for(second).custom_patterns == set()
