import warnings
from typing import Any
from unittest.mock import AsyncMock, Mock

import pytest

from guard_core.core.validation.context import ValidationContext
from guard_core.core.validation.validator import RequestValidator
from guard_core.models import SecurityConfig
from tests.conftest import MockGuardRequest

WARNING = (
    "exclude_all_paths=True excludes the entire application from all security "
    "checks (IP banning, rate limiting, penetration detection, everything). "
    "Confirm this is intentional."
)


def _validator(config: SecurityConfig) -> RequestValidator:
    event_bus: Any = Mock()
    event_bus.send_middleware_event = AsyncMock()
    return RequestValidator(
        ValidationContext(config=config, logger=Mock(), event_bus=event_bus)
    )


def test_the_field_defaults_to_false() -> None:
    assert SecurityConfig(enable_redis=False).exclude_all_paths is False


@pytest.mark.parametrize("path", ["/", "/anything", "/a/b/c", "/docs"])
async def test_true_excludes_every_request(path: str) -> None:
    with pytest.warns(UserWarning, match="exclude_all_paths=True"):
        config = SecurityConfig(enable_redis=False, exclude_all_paths=True)

    assert await _validator(config).is_path_excluded(MockGuardRequest(path=path))


@pytest.mark.parametrize(
    ("path", "excluded"), [("/", True), ("/anything", False), ("/docs", False)]
)
async def test_the_slash_entry_covers_only_the_root_page(
    path: str, excluded: bool
) -> None:
    config = SecurityConfig(enable_redis=False, exclude_paths=["/"])

    assert (
        await _validator(config).is_path_excluded(MockGuardRequest(path=path))
        is excluded
    )


async def test_an_anomalous_path_is_still_never_excluded() -> None:
    with pytest.warns(UserWarning):
        config = SecurityConfig(enable_redis=False, exclude_all_paths=True)

    assert (
        await _validator(config).is_path_excluded(MockGuardRequest(path="/a/../b"))
        is False
    )


async def test_false_excludes_nothing_beyond_exclude_paths() -> None:
    config = SecurityConfig(enable_redis=False, exclude_all_paths=False)

    assert (
        await _validator(config).is_path_excluded(MockGuardRequest(path="/login"))
        is False
    )


async def test_flipping_the_field_at_runtime_takes_effect() -> None:
    config = SecurityConfig(enable_redis=False)
    validator = _validator(config)
    request = MockGuardRequest(path="/login")
    assert await validator.is_path_excluded(request) is False

    config.exclude_all_paths = True
    assert await validator.is_path_excluded(request) is True


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
