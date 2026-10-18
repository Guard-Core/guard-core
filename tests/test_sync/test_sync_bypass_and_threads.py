import threading
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import MagicMock

import pytest

from guard_core.models import SecurityConfig
from guard_core.scripts import detection_strikes_lua as manager_detection_strikes_lua
from guard_core.scripts import rule_hit_index_lua as manager_rule_hit_index_lua
from guard_core.scripts.behavior_throttle_lua import (
    BEHAVIOR_THROTTLE_SCRIPT as TRACKER_THROTTLE_SCRIPT,
)
from guard_core.scripts.sliding_window_lua import (
    SLIDING_WINDOW_HIT_SCRIPT as MANAGER_SLIDING_WINDOW_SCRIPT,
)
from guard_core.sync.core.bypass.context import BypassContext
from guard_core.sync.core.bypass.handler import BypassHandler
from guard_core.sync.handlers.dynamic_rule_handler import DynamicRuleManager
from guard_core.sync.scripts import detection_strikes_lua, rule_hit_index_lua
from guard_core.sync.scripts.behavior_throttle_lua import BEHAVIOR_THROTTLE_SCRIPT
from guard_core.sync.scripts.rate_lua import RATE_LIMIT_SCRIPT
from guard_core.sync.scripts.sliding_window_lua import SLIDING_WINDOW_HIT_SCRIPT


def test_rate_lua_script_exists() -> None:
    assert isinstance(RATE_LIMIT_SCRIPT, str)
    assert "ZADD" in RATE_LIMIT_SCRIPT


def test_generated_sync_throttle_script_matches_the_script_trackers_load() -> None:
    assert BEHAVIOR_THROTTLE_SCRIPT == TRACKER_THROTTLE_SCRIPT


def test_generated_sync_detection_strike_scripts_match_the_ones_the_manager_loads() -> (
    None
):
    assert (
        detection_strikes_lua.RECORD_DETECTION_STRIKES_SCRIPT
        == manager_detection_strikes_lua.RECORD_DETECTION_STRIKES_SCRIPT
    )
    assert (
        detection_strikes_lua.FORGET_DETECTION_STRIKES_SCRIPT
        == manager_detection_strikes_lua.FORGET_DETECTION_STRIKES_SCRIPT
    )


def test_generated_sync_sliding_window_script_matches_the_redis_manager_one() -> None:
    assert SLIDING_WINDOW_HIT_SCRIPT == MANAGER_SLIDING_WINDOW_SCRIPT


def test_generated_sync_rule_hit_index_scripts_match_the_ones_the_manager_loads() -> (
    None
):
    assert (
        rule_hit_index_lua.ADD_TO_RULE_HIT_INDEX
        == manager_rule_hit_index_lua.ADD_TO_RULE_HIT_INDEX
    )
    assert (
        rule_hit_index_lua.SUM_INDEXED_WINDOW_HITS_SCRIPT
        == manager_rule_hit_index_lua.SUM_INDEXED_WINDOW_HITS_SCRIPT
    )


def _make_bypass_handler() -> BypassHandler:
    config = SecurityConfig(enable_redis=False, enable_penetration_detection=False)
    context = BypassContext(
        config=config,
        logger=MagicMock(),
        event_bus=MagicMock(),
        route_resolver=MagicMock(),
        response_factory=MagicMock(),
        validator=MagicMock(is_path_excluded=MagicMock(return_value=False)),
    )
    return BypassHandler(context)


def test_bypass_passthrough_no_client_fail_secure_rejects() -> None:
    handler = _make_bypass_handler()
    mock_request = MagicMock()
    mock_request.client_host = None
    mock_request.state = SimpleNamespace()
    mock_call_next = MagicMock(return_value=MagicMock())

    result = handler.handle_passthrough(mock_request, call_next=mock_call_next)
    assert result is not None
    assert mock_request.state.client_ip == "unknown"
    mock_call_next.assert_not_called()


def test_bypass_passthrough_no_client_fail_open_runs_pipeline_as_unknown() -> None:
    handler = _make_bypass_handler()
    handler.context.config.fail_secure = False
    mock_request = MagicMock()
    mock_request.client_host = None
    mock_request.state = SimpleNamespace()
    mock_call_next = MagicMock(return_value=MagicMock())

    result = handler.handle_passthrough(mock_request, call_next=mock_call_next)
    assert result is None
    assert mock_request.state.client_ip == "unknown"
    mock_call_next.assert_not_called()


def test_bypass_passthrough_excluded_path_falls_through_and_marks_request() -> None:
    handler = _make_bypass_handler()
    mock_request = MagicMock()
    mock_request.client_host = "127.0.0.1"
    cast(Any, handler.context.validator).is_path_excluded = MagicMock(return_value=True)
    mock_call_next = MagicMock(return_value=MagicMock())

    result = handler.handle_passthrough(mock_request, call_next=mock_call_next)
    assert result is None
    assert mock_request.state.guard_exclusion_scoped is True
    mock_call_next.assert_not_called()


def test_bypass_passthrough_no_client_omitting_call_next_raises() -> None:
    handler = _make_bypass_handler()
    mock_request = MagicMock()
    mock_request.client_host = None

    with pytest.raises(TypeError):
        cast(Any, handler.handle_passthrough)(mock_request)


def test_bypass_passthrough_excluded_path_omitting_call_next_raises() -> None:
    handler = _make_bypass_handler()
    mock_request = MagicMock()
    mock_request.client_host = "127.0.0.1"
    cast(Any, handler.context.validator).is_path_excluded = MagicMock(return_value=True)

    with pytest.raises(TypeError):
        cast(Any, handler.handle_passthrough)(mock_request)


def test_bypass_security_bypass_without_call_next() -> None:
    handler = _make_bypass_handler()
    mock_request = MagicMock()
    mock_request.url_path = "/test"
    mock_route_config = MagicMock()
    mock_route_config.bypassed_checks = {"all"}

    handler.context.config.passive_mode = False
    cast(Any, handler.context.route_resolver).should_bypass_check = MagicMock(
        return_value=True
    )

    result = handler.handle_security_bypass(
        mock_request, route_config=mock_route_config
    )
    assert result is None


def test_bypass_security_bypass_with_call_next() -> None:
    handler = _make_bypass_handler()
    mock_request = MagicMock()
    mock_request.url_path = "/test"
    mock_route_config = MagicMock()
    mock_route_config.bypassed_checks = {"all"}

    handler.context.config.passive_mode = False
    cast(Any, handler.context.route_resolver).should_bypass_check = MagicMock(
        return_value=True
    )
    mock_call_next = MagicMock(return_value=MagicMock())
    cast(Any, handler.context.response_factory).apply_modifier = MagicMock(
        side_effect=lambda r: r
    )

    result = handler.handle_security_bypass(
        mock_request,
        call_next=mock_call_next,
        route_config=mock_route_config,
    )
    assert result is not None
    mock_call_next.assert_called_once_with(mock_request)


def test_dynamic_rule_manager_stop_with_active_thread() -> None:
    DynamicRuleManager._instance = None
    config = SecurityConfig(enable_redis=False, enable_penetration_detection=False)
    manager = DynamicRuleManager(config)

    stop_flag = threading.Event()

    def fake_loop() -> None:
        stop_flag.wait(timeout=10)

    manager.update_task = threading.Thread(target=fake_loop, daemon=True)
    manager.update_task.start()

    assert manager.update_task.is_alive()

    stop_flag.set()
    manager.stop()

    DynamicRuleManager._instance = None
    assert manager.update_task is None
