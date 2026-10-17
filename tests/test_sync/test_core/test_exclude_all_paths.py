import warnings
from typing import Any
from unittest.mock import MagicMock, Mock

import pytest

from guard_core.models import SecurityConfig
from guard_core.sync.core.validation.context import ValidationContext
from guard_core.sync.core.validation.validator import RequestValidator
from tests.test_sync.conftest import SyncMockGuardRequest

WARNING = (
    "exclude_all_paths=True excludes the entire application from all security "
    "checks (IP banning, rate limiting, penetration detection, everything). "
    "Confirm this is intentional."
)


def _validator(config: SecurityConfig) -> RequestValidator:
    event_bus: Any = Mock()
    event_bus.send_middleware_event = MagicMock()
    return RequestValidator(
        ValidationContext(config=config, logger=Mock(), event_bus=event_bus)
    )


def test_the_field_defaults_to_false() -> None:
    assert SecurityConfig(enable_redis=False).exclude_all_paths is False


@pytest.mark.parametrize("path", ["/", "/anything", "/a/b/c", "/docs"])
def test_true_excludes_every_request_like_the_slash_entry(path: str) -> None:
    with pytest.warns(UserWarning, match="exclude_all_paths=True"):
        config = SecurityConfig(enable_redis=False, exclude_all_paths=True)
    request = SyncMockGuardRequest(path=path)

    assert _validator(config).is_path_excluded(request) is True
    with pytest.warns(UserWarning), pytest.warns(DeprecationWarning):
        slash = SecurityConfig(enable_redis=False, exclude_paths=["/"])
    assert _validator(slash).is_path_excluded(request) is True


def test_an_anomalous_path_is_still_never_excluded() -> None:
    with pytest.warns(UserWarning):
        config = SecurityConfig(enable_redis=False, exclude_all_paths=True)

    assert (
        _validator(config).is_path_excluded(SyncMockGuardRequest(path="/a/../b"))
        is False
    )


def test_false_excludes_nothing_beyond_exclude_paths() -> None:
    config = SecurityConfig(enable_redis=False, exclude_all_paths=False)

    assert (
        _validator(config).is_path_excluded(SyncMockGuardRequest(path="/login"))
        is False
    )


def test_flipping_the_field_at_runtime_takes_effect() -> None:
    config = SecurityConfig(enable_redis=False)
    validator = _validator(config)
    request = SyncMockGuardRequest(path="/login")
    assert validator.is_path_excluded(request) is False

    config.exclude_all_paths = True
    assert validator.is_path_excluded(request) is True


def test_true_warns_with_the_v440_slash_warning_text() -> None:
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        SecurityConfig(enable_redis=False, exclude_all_paths=True)

    user = [w for w in caught if w.category is UserWarning]
    assert [str(w.message) for w in user] == [WARNING]


def test_false_never_warns() -> None:
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        SecurityConfig(
            enable_redis=False, exclude_all_paths=False, ban_on_hostile_signals=False
        )


def test_the_slash_entry_message_points_to_the_field() -> None:
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        SecurityConfig(enable_redis=False, exclude_paths=["/"])

    texts = [str(w.message) for w in caught if w.category is DeprecationWarning]
    assert any(
        "will make '/' cover only the root page. Use exclude_all_paths=True to keep "
        "this." in text
        for text in texts
    )
