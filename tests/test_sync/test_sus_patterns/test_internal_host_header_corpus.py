import pytest

from guard_core.sync._utils.detection_config import (
    _excluded_header_effective_categories,
    _host_header_names_an_internal_host,
)
from guard_core.sync.handlers.suspatterns_handler import sus_patterns_handler

_CLIENT_IP = "203.0.113.5"

INTERNAL_BENIGN = [
    ("referer", "http://localhost:3000/chat"),
    ("referer", "http://127.0.0.1:8001/"),
    ("referer", "http://192.168.1.20:3000/"),
    ("referer", "http://[::1]:8080/"),
    ("referer", "http://10.0.0.5/app?x=1"),
    ("referer", "http://printer.local/"),
    ("referer", "http://169.254.169.254/latest/meta-data/iam/security-credentials/"),
    ("referer", "http://127.0.0.1:6379/"),
    ("referer", "http://192.168.0.1/admin"),
    ("user-agent", "curl/8.0 (http://127.0.0.1:8080)"),
    (
        "user-agent",
        "Mozilla/5.0 (compatible; Bot/1.0; +http://localhost:8000/bot.html)",
    ),
]

ATTACKS = [
    ("referer", "https://example.com/../../../../etc/passwd"),
    ("referer", "https://example.com/?x=<svg onload=alert(1)>"),
    ("referer", "https://example.com/?q=1 UNION SELECT user,pass FROM t"),
    ("referer", "https://example.com/?next=${jndi:ldap://x.example/a}"),
]


def _flagged(header: str, value: str, internal_host: bool) -> bool:
    categories = _excluded_header_effective_categories(
        header, value, None, internal_host
    )
    result = sus_patterns_handler.detect(
        content=value,
        ip_address=_CLIENT_IP,
        context="header",
        enabled_categories=categories,
    )
    return bool(result["is_threat"])


@pytest.mark.parametrize(("header", "value"), INTERNAL_BENIGN)
def test_an_internal_address_in_a_header_of_an_internal_server_is_clean(
    header: str, value: str
) -> None:
    assert _flagged(header, value, internal_host=True) is False


@pytest.mark.parametrize(("header", "value"), INTERNAL_BENIGN[6:9])
def test_the_same_address_is_ssrf_when_the_server_is_not_internal(
    header: str, value: str
) -> None:
    assert _flagged(header, value, internal_host=False) is True


@pytest.mark.parametrize("internal_host", [True, False])
@pytest.mark.parametrize(("header", "value"), ATTACKS)
def test_an_attack_in_a_default_excluded_header_is_flagged_either_way(
    header: str, value: str, internal_host: bool
) -> None:
    assert _flagged(header, value, internal_host) is True


@pytest.mark.parametrize(
    "host",
    ["localhost", "LOCALHOST:3000", "127.0.0.1", "[::1]:8000", "[fe80::1]", "0.0.0.0"],
)
def test_a_loopback_or_unspecified_host_is_internal(host: str) -> None:
    assert _host_header_names_an_internal_host(host) is True


@pytest.mark.parametrize(
    "host",
    [
        "10.1.2.3:80",
        "172.16.0.1",
        "192.168.0.9",
        "api.internal",
        "box.lan",
        "mac.local:631",
        "dev.localhost",
        "router.home.arpa",
    ],
)
def test_a_private_or_internal_name_host_is_internal(host: str) -> None:
    assert _host_header_names_an_internal_host(host) is True


@pytest.mark.parametrize(
    "host", ["", "example.com", "api.example.com:8443", "93.184.216.34", "8.8.8.8:53"]
)
def test_a_public_host_is_not_internal(host: str) -> None:
    assert _host_header_names_an_internal_host(host) is False
