from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from guard_core.core.checks.implementations.suspicious_activity import (
    SuspiciousActivityCheck,
)
from guard_core.detection_result import DetectionResult
from guard_core.models import SecurityConfig, ThreatBanConfig

CLIENT_IP = "203.0.113.7"


class _Harness:
    def __init__(self, monkeypatch: pytest.MonkeyPatch, config: SecurityConfig) -> None:
        middleware = MagicMock()
        middleware.config = config
        middleware.suspicious_request_counts = {}
        middleware.event_bus.send_middleware_event = AsyncMock()
        middleware.create_error_response = AsyncMock(
            return_value=MagicMock(status_code=403)
        )
        middleware.route_resolver.should_bypass_check = lambda *_: False
        self.check = SuspiciousActivityCheck(middleware)
        self.bans: list[tuple[str, int, str]] = []
        self.categories: list[str] = []

        async def detect(*_args: Any, **_kwargs: Any) -> DetectionResult:
            return DetectionResult(
                is_threat=True,
                trigger_info="probe",
                threat_categories=list(self.categories),
            )

        async def ban(ip: str, duration: int, reason: str) -> bool:
            self.bans.append((ip, duration, reason))
            return True

        monkeypatch.setattr(
            "guard_core.core.checks.implementations.suspicious_activity"
            ".get_cached_detection_result",
            detect,
        )
        monkeypatch.setattr(self.check.ip_ban_manager, "ban_ip", ban)

    async def hit(self, *categories: str) -> None:
        self.categories = list(categories)
        request = MagicMock()
        request.state.is_whitelisted = False
        request.state.client_ip = CLIENT_IP
        request.state.route_config = None
        request.url_full = "https://test/x"
        await self.check.check(request)


def _config(**fields: Any) -> SecurityConfig:
    return SecurityConfig(
        enable_ip_banning=True, enable_redis=False, rate_limit=1000, **fields
    )


async def test_flat_threshold_counts_requests_not_categories(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = _Harness(monkeypatch, _config(auto_ban_threshold=5))

    await harness.hit("xss", "sqli", "dir_traversal", "cmd_injection")
    await harness.hit("xss", "sqli", "dir_traversal", "cmd_injection")

    assert harness.bans == []


async def test_flat_threshold_bans_on_the_threshold_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = _Harness(monkeypatch, _config(auto_ban_threshold=3))

    for _ in range(3):
        await harness.hit("xss", "sqli")

    assert harness.bans == [(CLIENT_IP, 3600, "penetration_attempt")]


async def test_first_hit_with_a_one_strike_entry_bans_for_its_own_duration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = _Harness(
        monkeypatch,
        _config(
            threat_ban_config={
                "xss": ThreatBanConfig(threshold=1, duration=3600),
                "sqli": ThreatBanConfig(threshold=10, duration=30 * 86400),
            }
        ),
    )

    await harness.hit("xss", "sqli")

    assert harness.bans == [(CLIENT_IP, 3600, "penetration_attempt:xss")]


async def test_longest_crossed_entry_without_flat_is_the_sqli_entry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = _Harness(
        monkeypatch,
        _config(
            auto_ban_threshold=1000,
            threat_ban_config={
                "xss": ThreatBanConfig(threshold=3, duration=600),
                "sqli": ThreatBanConfig(threshold=3, duration=1800),
            },
        ),
    )

    for _ in range(3):
        await harness.hit("xss", "sqli")

    assert harness.bans == [(CLIENT_IP, 1800, "penetration_attempt:sqli")]


async def test_flat_joins_the_longest_when_other_requests_did_not_match_the_entry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = _Harness(
        monkeypatch,
        _config(
            auto_ban_threshold=5,
            auto_ban_duration=3600,
            threat_ban_config={"xss": ThreatBanConfig(threshold=3, duration=600)},
        ),
    )

    await harness.hit("sqli")
    await harness.hit("sqli")
    await harness.hit("xss")
    await harness.hit("xss")
    assert harness.bans == []
    await harness.hit("xss")

    assert harness.bans == [(CLIENT_IP, 3600, "penetration_attempt")]


async def test_entry_wins_a_duration_tie_with_flat_and_keeps_its_reason(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = _Harness(
        monkeypatch,
        _config(
            auto_ban_threshold=5,
            auto_ban_duration=3600,
            threat_ban_config={"xss": ThreatBanConfig(threshold=3, duration=3600)},
        ),
    )

    await harness.hit("sqli")
    await harness.hit("sqli")
    for _ in range(3):
        await harness.hit("xss")

    assert harness.bans == [(CLIENT_IP, 3600, "penetration_attempt:xss")]


async def test_mixed_entries_and_flat_choose_the_longest_entry_when_flat_is_equal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = _Harness(
        monkeypatch,
        _config(
            auto_ban_threshold=3,
            auto_ban_duration=3600,
            threat_ban_config={
                "xss": ThreatBanConfig(threshold=3, duration=600),
                "sqli": ThreatBanConfig(threshold=3, duration=1800),
            },
        ),
    )

    for _ in range(3):
        await harness.hit("xss", "sqli")

    assert harness.bans == [(CLIENT_IP, 1800, "penetration_attempt:sqli")]


async def test_duration_tie_between_entries_goes_to_the_earlier_category(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = _Harness(
        monkeypatch,
        _config(
            auto_ban_threshold=1000,
            threat_ban_config={
                "xss": ThreatBanConfig(threshold=1, duration=900),
                "sqli": ThreatBanConfig(threshold=1, duration=900),
            },
        ),
    )

    await harness.hit("sqli", "xss")

    assert harness.bans == [(CLIENT_IP, 900, "penetration_attempt:sqli")]


async def test_a_flat_ban_longer_than_the_entry_uses_the_flat_reason(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = _Harness(
        monkeypatch,
        _config(
            auto_ban_threshold=2,
            auto_ban_duration=7200,
            threat_ban_config={"xss": ThreatBanConfig(threshold=1, duration=600)},
        ),
    )

    await harness.hit("sqli")
    await harness.hit("xss")

    assert harness.bans == [(CLIENT_IP, 7200, "penetration_attempt")]


async def test_rate_limit_feed_entry_governs_when_flat_counts_the_same_violations() -> (
    None
):
    from guard_core.core.checks.helpers import _resolve_and_apply_threshold_ban

    config = _config(
        auto_ban_threshold=10,
        auto_ban_duration=3600,
        threat_ban_config={"rate_limit": ThreatBanConfig(threshold=10, duration=60)},
    )
    bans: list[tuple[str, int, str]] = []

    class _Manager:
        async def ban_ip(self, ip: str, duration: int, reason: str) -> bool:
            bans.append((ip, duration, reason))
            return True

    result = await _resolve_and_apply_threshold_ban(
        {"rate_limit": 10},
        config,
        _Manager(),
        CLIENT_IP,
        ("rate_limit",),
        "rate_limit_exceeded",
    )

    assert result == (60, "rate_limit_exceeded:rate_limit", "rate_limit")
    assert bans == [(CLIENT_IP, 60, "rate_limit_exceeded:rate_limit")]


def test_request_strikes_expire_resize_and_skip_the_rate_limit_feed() -> None:
    from guard_core.core.checks.helpers import (
        _increment_suspicious_counts,
        _WindowedCategoryCounts,
    )

    counts = _WindowedCategoryCounts()
    counts.record_request(1.0, 8)
    counts.record_request(2.0, 8)
    counts.record_request(3.0, 4)
    assert counts.request_total == 3
    counts.expire_before(2.0)
    assert counts.request_total == 1

    adopted = _WindowedCategoryCounts.adopting({"xss": 2, "rate_limit": 5}, 10.0, 8)
    assert adopted.request_total == 2

    middleware = MagicMock()
    middleware.config = _config()
    middleware.suspicious_request_counts = {}
    _increment_suspicious_counts(middleware, CLIENT_IP, "rate_limit")
    assert middleware.suspicious_request_counts[CLIENT_IP].request_total == 0
    _increment_suspicious_counts(middleware, CLIENT_IP, ["xss", "sqli"])
    assert middleware.suspicious_request_counts[CLIENT_IP].request_total == 1


async def test_event_request_count_falls_back_to_the_category_sum_for_plain_counts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = _Harness(monkeypatch, _config())
    harness.check.middleware.suspicious_request_counts[CLIENT_IP] = {
        "xss": 2,
        "sqli": 1,
    }

    assert harness.check._total_count_for_ip(CLIENT_IP) == 3


async def test_passive_mode_never_counts_detection_strikes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config(auto_ban_threshold=3, passive_mode=True)
    harness = _Harness(monkeypatch, config)

    for _ in range(5):
        await harness.hit("xss")

    assert harness.check.middleware.suspicious_request_counts == {}
    assert harness.bans == []

    config.passive_mode = False
    await harness.hit("xss")
    assert harness.bans == []
    await harness.hit("xss")
    await harness.hit("xss")
    assert harness.bans == [(CLIENT_IP, 3600, "penetration_attempt")]
