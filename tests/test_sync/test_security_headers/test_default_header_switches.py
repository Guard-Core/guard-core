import pytest

from guard_core.models import SecurityConfig
from guard_core.sync.handlers.security_headers_handler import (
    SecurityHeadersManager,
    security_headers_manager,
)

SWITCHES = {
    "frame_options": "X-Frame-Options",
    "content_type_options": "X-Content-Type-Options",
    "xss_protection": "X-XSS-Protection",
    "referrer_policy": "Referrer-Policy",
    "permissions_policy": "Permissions-Policy",
    "permitted_cross_domain_policies": "X-Permitted-Cross-Domain-Policies",
    "download_options": "X-Download-Options",
    "cross_origin_opener_policy": "Cross-Origin-Opener-Policy",
    "cross_origin_resource_policy": "Cross-Origin-Resource-Policy",
}


def _headers(**security_headers: object) -> dict[str, str]:
    config = SecurityConfig(
        enable_redis=False, security_headers={"enabled": True, **security_headers}
    )
    return security_headers_manager.get_headers("/x", config=config)


def test_xss_protection_defaults_to_zero() -> None:
    headers = _headers()

    assert headers["X-XSS-Protection"] == "0"


def test_the_default_config_dict_sends_xss_protection_zero() -> None:
    config = SecurityConfig(enable_redis=False)
    headers = security_headers_manager.get_headers("/x", config=config)

    assert headers["X-XSS-Protection"] == "0"


def test_coep_is_not_sent_unless_opted_in() -> None:
    assert "Cross-Origin-Embedder-Policy" not in _headers()
    default_config = SecurityConfig(enable_redis=False)
    assert "Cross-Origin-Embedder-Policy" not in security_headers_manager.get_headers(
        "/x", config=default_config
    )

    opted_in = _headers(cross_origin_embedder_policy="require-corp")

    assert opted_in["Cross-Origin-Embedder-Policy"] == "require-corp"


def test_corp_defaults_to_same_site() -> None:
    assert (_headers())["Cross-Origin-Resource-Policy"] == "same-site"


def test_coop_keeps_its_default() -> None:
    assert (_headers())["Cross-Origin-Opener-Policy"] == "same-origin"


@pytest.mark.parametrize(("key", "header"), SWITCHES.items())
def test_every_default_header_switches_off_with_none(key: str, header: str) -> None:
    on = _headers()
    off = _headers(**{key: None})

    assert header in on
    assert header not in off
    assert set(on) - set(off) == {header}


def test_an_explicit_value_replaces_the_default() -> None:
    headers = _headers(
        cross_origin_resource_policy="cross-origin", xss_protection="1; mode=block"
    )

    assert headers["Cross-Origin-Resource-Policy"] == "cross-origin"
    assert headers["X-XSS-Protection"] == "1; mode=block"


def test_the_class_defaults_follow_the_decision() -> None:
    defaults = SecurityHeadersManager.default_headers

    assert defaults["X-XSS-Protection"] == "0"
    assert defaults["Cross-Origin-Resource-Policy"] == "same-site"
    assert "Cross-Origin-Embedder-Policy" not in defaults
