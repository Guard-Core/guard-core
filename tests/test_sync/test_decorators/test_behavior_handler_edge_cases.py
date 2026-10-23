from typing import Any

import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.sync.handlers.behavior_handler import BehaviorTracker


@pytest.fixture
def edge_security_config() -> SyncSecurityConfig:
    return SyncSecurityConfig()


@pytest.fixture
def tracker(edge_security_config: SyncSecurityConfig) -> BehaviorTracker:
    return BehaviorTracker(edge_security_config)


def test_handle_array_match_part_not_in_dict(
    tracker: BehaviorTracker,
) -> None:
    current = {"other_field": [1, 2, 3]}
    part = "missing_field[]"
    expected = "test"

    result = tracker._handle_array_match(current, part, expected)
    assert result is False


def test_handle_array_match_not_a_list(tracker: BehaviorTracker) -> None:
    current = {"items": "not_a_list"}
    part = "items[]"
    expected = "test"

    result = tracker._handle_array_match(current, part, expected)
    assert result is False


def test_handle_array_match_current_not_dict(
    tracker: BehaviorTracker,
) -> None:
    current = ["not", "a", "dict"]
    part = "items[]"
    expected = "test"

    result = tracker._handle_array_match(current, part, expected)
    assert result is False


def test_traverse_json_path_missing_key(tracker: BehaviorTracker) -> None:
    data = {"level1": {"level2": "value"}}
    path = "level1.missing.level3"

    result = tracker._traverse_json_path(data, path)
    assert result is None


def test_traverse_json_path_not_a_dict(tracker: BehaviorTracker) -> None:
    data = {"level1": "string_value"}
    path = "level1.level2"

    result = tracker._traverse_json_path(data, path)
    assert result is None


def test_traverse_json_path_root_not_dict(tracker: BehaviorTracker) -> None:
    data = ["not", "a", "dict"]
    path = "some.path"

    result = tracker._traverse_json_path(data, path)
    assert result is None


def test_traverse_json_path_success(tracker: BehaviorTracker) -> None:
    data = {"level1": {"level2": {"level3": "found"}}}
    path = "level1.level2.level3"

    result = tracker._traverse_json_path(data, path)
    assert result == "found"


def test_match_json_pattern_non_dict_in_path(
    tracker: BehaviorTracker,
) -> None:
    data = {"result": "string_not_dict"}
    pattern = "result.nested==value"

    result = tracker._match_json_pattern(data, pattern)
    assert result is False


def test_match_json_pattern_missing_key_in_path(
    tracker: BehaviorTracker,
) -> None:
    data = {"result": {"status": "win"}}
    pattern = "result.missing.key==value"

    result = tracker._match_json_pattern(data, pattern)
    assert result is False


@pytest.mark.parametrize(
    "data,pattern",
    [
        ({"other": [1, 2, 3]}, "items[]==test"),
        ({"items": "not_a_list"}, "items[]==test"),
        ({"level1": "not_dict"}, "level1.level2==value"),
    ],
)
def test_match_json_pattern_edge_cases(
    tracker: BehaviorTracker, data: dict[str, Any], pattern: str
) -> None:
    result = tracker._match_json_pattern(data, pattern)
    assert result is False
