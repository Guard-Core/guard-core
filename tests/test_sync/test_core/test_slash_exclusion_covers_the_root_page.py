from typing import Any
from unittest.mock import MagicMock, Mock

import pytest

from guard_core.models import SecurityConfig
from guard_core.sync.core.validation.context import ValidationContext
from guard_core.sync.core.validation.path_matching import path_is_excluded
from guard_core.sync.core.validation.validator import RequestValidator
from tests.test_sync.conftest import SyncMockGuardRequest


def _validator(config: SecurityConfig) -> RequestValidator:
    event_bus: Any = Mock()
    event_bus.send_middleware_event = MagicMock()
    return RequestValidator(
        ValidationContext(config=config, logger=Mock(), event_bus=event_bus)
    )


def _config(**settings: Any) -> SecurityConfig:
    return SecurityConfig(enable_redis=False, **settings)


@pytest.mark.parametrize(
    ("path", "excluded"),
    [("/", True), ("/login", False), ("/a/b/c", False), ("/docs", False)],
)
def test_the_slash_entry_matches_only_the_root_page(path: str, excluded: bool) -> None:
    assert path_is_excluded(path, ["/"]) is excluded


@pytest.mark.parametrize(
    ("path", "excluded"), [("/", True), ("/login", False), ("/docs", False)]
)
def test_an_unset_exclude_all_paths_leaves_the_rest_of_the_app_checked(
    path: str, excluded: bool
) -> None:
    config = _config(exclude_paths=["/"])
    assert "exclude_all_paths" not in config.model_fields_set

    assert (
        _validator(config).is_path_excluded(SyncMockGuardRequest(path=path)) is excluded
    )


def test_the_slash_entry_is_no_longer_a_misconfiguration() -> None:
    config = _config(exclude_paths=["/"], fail_on_misconfiguration=True)

    assert config.exclude_paths == ["/"]


@pytest.mark.parametrize("path", ["/", "/anything", "/a/b/c", "/docs"])
def test_exclude_all_paths_keeps_the_old_meaning(path: str) -> None:
    with pytest.warns(UserWarning, match="exclude_all_paths=True"):
        config = _config(exclude_all_paths=True)

    assert _validator(config).is_path_excluded(SyncMockGuardRequest(path=path))


def test_exclude_all_paths_still_never_excludes_an_anomalous_path() -> None:
    with pytest.warns(UserWarning):
        config = _config(exclude_all_paths=True)

    assert not _validator(config).is_path_excluded(SyncMockGuardRequest(path="/a/../b"))
