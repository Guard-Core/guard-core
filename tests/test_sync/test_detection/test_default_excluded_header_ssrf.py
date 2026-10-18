import pytest

from guard_core.models import SecurityConfig
from guard_core.sync.utils import detect_penetration_attempt
from tests.test_sync.conftest import SyncMockGuardRequest

INTERNAL_URLS = [
    "http://localhost:3000/chat",
    "http://127.0.0.1:8001/",
    "http://192.168.1.20:3000/",
    "http://[::1]:8080/",
    "http://10.0.0.5/app?x=1",
    "http://172.16.0.9:9000/a",
    "http://169.254.169.254/latest/meta-data/",
]
CLEAN_URLS = ["https://example.com/", "http://printer.local/"]


def _scan(header: str, value: str) -> tuple[bool, list[str]]:
    request = SyncMockGuardRequest(path="/x", headers={header: value})
    result = detect_penetration_attempt(request, SecurityConfig())
    return result.is_threat, result.threat_categories


@pytest.mark.parametrize("value", [*INTERNAL_URLS, *CLEAN_URLS])
def test_a_referer_pointing_at_an_internal_address_is_not_ssrf(
    value: str,
) -> None:
    assert _scan("referer", value) == (False, [])


@pytest.mark.parametrize("value", INTERNAL_URLS)
def test_origin_and_host_with_the_same_addresses_stay_clean(value: str) -> None:
    host = value.split("//", 1)[1].split("/", 1)[0]
    assert _scan("origin", value.split("?", 1)[0].rstrip("/")) == (False, [])
    assert _scan("host", host) == (False, [])


@pytest.mark.parametrize(
    "value",
    [
        "Mozilla/5.0 (compatible; Bot/1.0; +http://localhost:8000/bot.html)",
        "curl/8.0 (http://127.0.0.1:8080)",
    ],
)
def test_a_user_agent_naming_an_internal_address_is_not_ssrf(value: str) -> None:
    assert _scan("user-agent", value) == (False, [])


@pytest.mark.parametrize(
    "header,value",
    [
        ("sec-fetch-site", "same-origin"),
        ("sec-fetch-mode", "navigate"),
        ("sec-fetch-dest", "document"),
        ("sec-ch-ua", '"Chromium";v="126", "Not;A=Brand";v="24"'),
        ("sec-ch-ua-mobile", "?0"),
        ("sec-ch-ua-platform", '"macOS"'),
        ("forwarded", 'for="[2001:db8::1]";host=localhost:3000'),
    ],
)
def test_the_other_default_excluded_headers_stay_clean(header: str, value: str) -> None:
    assert _scan(header, value) == (False, [])


@pytest.mark.parametrize("header", ["referer", "user-agent"])
def test_an_attack_in_a_default_excluded_header_is_still_flagged(
    header: str,
) -> None:
    threat, categories = _scan(header, "http://localhost/<script>alert(1)</script>")

    assert threat is True
    assert "xss" in categories
    assert "ssrf" not in categories
