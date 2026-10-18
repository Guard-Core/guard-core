from collections.abc import Mapping
from typing import Any

from guard_core.core.checks.helpers import _resolve_and_apply_threshold_ban
from guard_core.models import SecurityConfig


class _Bans:
    def __init__(self) -> None:
        self.calls: list[tuple[str, int, str]] = []

    async def ban_ip(self, ip: str, duration: int, reason: str = "") -> bool:
        self.calls.append((ip, duration, reason))
        return True


def _config() -> SecurityConfig:
    return SecurityConfig(
        enable_redis=False, auto_ban_threshold=10, auto_ban_duration=3600
    )


async def _resolve(
    counts: Mapping[str, int], categories: tuple[str, ...], reason: str
) -> tuple[Any, _Bans]:
    bans = _Bans()
    result = await _resolve_and_apply_threshold_ban(
        counts, _config(), bans, "198.51.100.60", categories, reason
    )
    return result, bans


async def test_old_detection_hits_do_not_push_a_rate_limit_ban_over() -> None:
    result, bans = await _resolve(
        {"sqli": 9, "rate_limit": 1}, ("rate_limit",), "rate_limit_exceeded"
    )

    assert result is None
    assert bans.calls == []


async def test_rate_limit_violations_do_not_push_a_detection_ban_over() -> None:
    result, bans = await _resolve(
        {"rate_limit": 9, "sqli": 1}, ("sqli",), "penetration_attempt"
    )

    assert result is None
    assert bans.calls == []


async def test_the_rate_limit_ban_still_fires_on_its_own_category() -> None:
    result, bans = await _resolve(
        {"sqli": 3, "rate_limit": 10}, ("rate_limit",), "rate_limit_exceeded"
    )

    assert result == (3600, "rate_limit_exceeded", None)
    assert bans.calls == [("198.51.100.60", 3600, "rate_limit_exceeded")]


async def test_detection_categories_still_add_up_for_the_detection_ban() -> None:
    result, bans = await _resolve(
        {"sqli": 6, "xss": 4}, ("xss",), "penetration_attempt"
    )

    assert result == (3600, "penetration_attempt", None)
    assert bans.calls == [("198.51.100.60", 3600, "penetration_attempt")]
