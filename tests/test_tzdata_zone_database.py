import re
import zoneinfo
from collections.abc import Iterator
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from unittest.mock import Mock

import pytest

from guard_core._utils.time_window import time_window_allows
from guard_core.decorators._route_arguments import unknown_time_zone


@pytest.fixture
def no_system_zone_database() -> Iterator[None]:
    zoneinfo.reset_tzpath([])
    zoneinfo.ZoneInfo.clear_cache()
    yield
    zoneinfo.reset_tzpath()
    zoneinfo.ZoneInfo.clear_cache()


def test_tzdata_is_a_runtime_dependency() -> None:
    pyproject = next(
        path / "pyproject.toml"
        for path in Path(__file__).resolve().parents
        if (path / "pyproject.toml").is_file()
    )
    runtime = re.search(
        r"^dependencies = \[(.*?)\]", pyproject.read_text(), re.M | re.S
    )

    assert runtime is not None
    assert '"tzdata"' in runtime.group(1)


@pytest.mark.usefixtures("no_system_zone_database")
def test_a_named_zone_resolves_without_the_system_zone_database() -> None:
    assert zoneinfo.ZoneInfo("US/Eastern").key == "US/Eastern"
    assert unknown_time_zone("US/Eastern") is False
    assert unknown_time_zone("Mars/Olympus") is True


@pytest.mark.usefixtures("no_system_zone_database")
def test_a_time_window_with_a_zone_works_without_the_system_zone_database() -> None:
    seen: list[Any] = []

    def now(zone: Any) -> datetime:
        seen.append(zone)
        return datetime(2026, 7, 1, 12, 0, tzinfo=timezone.utc).astimezone(zone)

    restrictions = {"start": "07:00", "end": "09:00", "timezone": "US/Eastern"}

    assert time_window_allows(restrictions, Mock(), now) is True
    assert [zone.key for zone in seen] == ["US/Eastern"]
