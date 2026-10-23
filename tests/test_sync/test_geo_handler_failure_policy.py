from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.sync.core.checks.factory import build_default_pipeline
from guard_core.sync.decorators import SecurityDecorator
from guard_core.sync.handlers.ipban_handler import ip_ban_manager
from guard_core.sync.protocols.geo_ip_protocol import SyncGeoIPHandler
from tests.test_sync.conftest import SyncMockGuardRequest
from tests.test_sync.test_core.conftest import build_middleware

CLIENT = "203.0.113.5"


def _raising_geo(error: Exception) -> MagicMock:
    geo = MagicMock(spec=SyncGeoIPHandler)
    geo.is_initialized = True
    geo.initialize = MagicMock()
    geo.get_country.side_effect = error
    return geo


def _run(
    error: Exception | None = None, **settings: Any
) -> tuple[int | None, list[dict[str, Any]]]:
    geo = _raising_geo(error or RuntimeError("lookup exploded"))
    config = SyncSecurityConfig(
        geo_ip_handler=geo,
        enable_redis=False,
        enable_penetration_detection=False,
        enable_rate_limiting=False,
        **{"blocked_countries": ["CN"], **settings},
    )
    middleware = build_middleware(config, SecurityDecorator(config), geo)
    request = SyncMockGuardRequest(path="/x", client_host=CLIENT)
    response = build_default_pipeline(middleware).execute(request)
    events = [
        dict(call.kwargs)
        for call in middleware.event_bus.send_middleware_event.call_args_list
    ]
    return (None if response is None else response.status_code), events


def _failures(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [e for e in events if e["event_type"] == "geo_lookup_failed"]


@pytest.mark.parametrize(
    "rules",
    [
        {"blocked_countries": ["CN"]},
        {"blocked_countries": [], "whitelist_countries": ["US"]},
    ],
)
def test_a_raising_geo_lookup_denies_under_fail_secure(
    rules: dict[str, Any],
) -> None:
    status, events = _run(**rules)

    assert status == 403
    [event] = _failures(events)
    assert event["action_taken"] == "request_blocked"


@pytest.mark.parametrize("error", [RuntimeError("boom"), ValueError("bad value")])
def test_a_raising_geo_lookup_passes_without_fail_secure_but_is_reported(
    error: Exception,
) -> None:
    status, events = _run(error, fail_secure=False)

    assert status is None
    [event] = _failures(events)
    assert event["action_taken"] == "request_allowed"


def test_a_value_error_from_the_geo_handler_follows_the_same_rule() -> None:
    status, _ = _run(ValueError("bad value"))

    assert status == 403


def test_passive_mode_passes_and_reports_logged_only() -> None:
    status, events = _run(passive_mode=True)

    assert status is None
    [event] = _failures(events)
    assert event["action_taken"] == "logged_only"


def test_the_failure_is_logged_in_both_branches(
    caplog: pytest.LogCaptureFixture,
) -> None:
    _run()
    _run(fail_secure=False)

    messages = [r.getMessage() for r in caplog.records if "GeoIP" in r.getMessage()]
    assert len(messages) >= 2


def test_a_geo_failure_never_counts_toward_a_ban() -> None:
    ip_ban_manager.banned_ips.clear()
    for _ in range(4):
        _run(ban_on_hostile_signals=True, auto_ban_threshold=1)

    assert not ip_ban_manager.is_ip_banned(CLIENT)


def test_the_ip_list_result_is_kept_when_the_geo_lookup_would_fail() -> None:
    status, events = _run(blacklist=[CLIENT], fail_secure=False)

    assert status == 403
    assert _failures(events) == []


def test_the_cloud_check_still_runs_after_a_passed_geo_failure() -> None:
    with patch(
        "guard_core.sync.handlers.cloud_handler.cloud_handler.is_cloud_ip",
        return_value=True,
    ):
        status, events = _run(fail_secure=False, block_cloud_providers={"AWS"})

    assert status == 403
    assert len(_failures(events)) == 1


def test_a_whitelisted_client_never_reaches_the_geo_lookup() -> None:
    status, events = _run(whitelist=[CLIENT])

    assert status is None
    assert _failures(events) == []


def test_an_error_outside_the_geo_lookup_is_not_swallowed() -> None:
    from guard_core.sync.utils import check_ip_access

    config = SyncSecurityConfig(enable_redis=False, block_cloud_providers={"AWS"})

    with (
        patch(
            "guard_core.sync.handlers.cloud_handler.cloud_handler.is_cloud_ip",
            side_effect=RuntimeError("cloud lookup exploded"),
        ),
        pytest.raises(RuntimeError, match="cloud lookup exploded"),
    ):
        check_ip_access(CLIENT, config)
