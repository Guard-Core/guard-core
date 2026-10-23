import importlib.util
import logging

import pytest
from pydantic import ValidationError

from guard_core import _staged_defaults
from guard_core.models import SyncSecurityConfig

real_find_spec = importlib.util.find_spec


def _without_the_redis_package(name: str, package: str | None = None) -> object:
    return None if name == "redis" else real_find_spec(name, package)


@pytest.fixture(autouse=True)
def _prefix_warning_not_yet_given(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_staged_defaults, "_default_prefix_warned", False)


def _prefix_warnings(caplog: pytest.LogCaptureFixture) -> list[str]:
    return [r.getMessage() for r in caplog.records if "redis_prefix is" in r.message]


@pytest.mark.parametrize("url", ["", None])
def test_a_falsy_redis_url_gives_no_default_prefix_warning(
    url: str | None, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.WARNING, logger="guard_core"):
        SyncSecurityConfig(enable_redis=True, redis_url=url)

    assert _prefix_warnings(caplog) == []


def test_a_real_redis_url_still_gives_the_default_prefix_warning(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.WARNING, logger="guard_core"):
        SyncSecurityConfig(enable_redis=True, redis_url="redis://localhost:6379")

    assert len(_prefix_warnings(caplog)) == 1


@pytest.mark.parametrize("url", ["", None])
def test_a_falsy_redis_url_needs_no_redis_package(
    url: str | None, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("importlib.util.find_spec", _without_the_redis_package)

    assert SyncSecurityConfig(enable_redis=True, redis_url=url).enable_redis is True


def test_a_real_redis_url_still_needs_the_redis_package(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("importlib.util.find_spec", _without_the_redis_package)

    with pytest.raises(ValidationError, match="guard-core\\[redis\\]"):
        SyncSecurityConfig(enable_redis=True, redis_url="redis://localhost:6379")
