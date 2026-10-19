from typing import Any
from unittest.mock import AsyncMock, Mock

import pytest

from guard_core.core.validation.context import ValidationContext
from guard_core.core.validation.path_matching import path_is_excluded
from guard_core.core.validation.validator import RequestValidator
from guard_core.models import SecurityConfig
from tests.conftest import MockGuardRequest


def _validator(config: SecurityConfig) -> RequestValidator:
    event_bus: Any = Mock()
    event_bus.send_middleware_event = AsyncMock()
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
async def test_an_unset_exclude_all_paths_leaves_the_rest_of_the_app_checked(
    path: str, excluded: bool
) -> None:
    config = _config(exclude_paths=["/"])
    assert "exclude_all_paths" not in config.model_fields_set

    assert (
        await _validator(config).is_path_excluded(MockGuardRequest(path=path))
        is excluded
    )


def test_the_slash_entry_is_no_longer_a_misconfiguration() -> None:
    config = _config(exclude_paths=["/"], fail_on_misconfiguration=True)

    assert config.exclude_paths == ["/"]


@pytest.mark.parametrize("path", ["/", "/anything", "/a/b/c", "/docs"])
async def test_exclude_all_paths_keeps_the_old_meaning(path: str) -> None:
    with pytest.warns(UserWarning, match="exclude_all_paths=True"):
        config = _config(exclude_all_paths=True)

    assert await _validator(config).is_path_excluded(MockGuardRequest(path=path))


async def test_exclude_all_paths_still_never_excludes_an_anomalous_path() -> None:
    with pytest.warns(UserWarning):
        config = _config(exclude_all_paths=True)

    assert not await _validator(config).is_path_excluded(
        MockGuardRequest(path="/a/../b")
    )
