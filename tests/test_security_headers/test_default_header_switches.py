import pytest

from guard_core.handlers.security_headers_handler import (
    SecurityHeadersManager,
    security_headers_manager,
)
from guard_core.models import SecurityConfig

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


async def _headers(**security_headers: object) -> dict[str, str]:
    config = SecurityConfig(
        enable_redis=False, security_headers={"enabled": True, **security_headers}
    )
    return await security_headers_manager.get_headers("/x", config=config)


async def test_xss_protection_defaults_to_zero() -> None:
    headers = await _headers()

    assert headers["X-XSS-Protection"] == "0"


async def test_the_default_config_dict_sends_xss_protection_zero() -> None:
    config = SecurityConfig(enable_redis=False)
    headers = await security_headers_manager.get_headers("/x", config=config)

    assert headers["X-XSS-Protection"] == "0"


async def test_coep_is_not_sent_unless_opted_in() -> None:
    assert "Cross-Origin-Embedder-Policy" not in await _headers()
    default_config = SecurityConfig(enable_redis=False)
    assert (
        "Cross-Origin-Embedder-Policy"
        not in await security_headers_manager.get_headers("/x", config=default_config)
    )

    opted_in = await _headers(cross_origin_embedder_policy="require-corp")

    assert opted_in["Cross-Origin-Embedder-Policy"] == "require-corp"


async def test_corp_defaults_to_same_site() -> None:
    assert (await _headers())["Cross-Origin-Resource-Policy"] == "same-site"


async def test_coop_keeps_its_default() -> None:
    assert (await _headers())["Cross-Origin-Opener-Policy"] == "same-origin"


@pytest.mark.parametrize(("key", "header"), SWITCHES.items())
async def test_every_default_header_switches_off_with_none(
    key: str, header: str
) -> None:
    on = await _headers()
    off = await _headers(**{key: None})

    assert header in on
    assert header not in off
    assert set(on) - set(off) == {header}


async def test_an_explicit_value_replaces_the_default() -> None:
    headers = await _headers(
        cross_origin_resource_policy="cross-origin", xss_protection="1; mode=block"
    )

    assert headers["Cross-Origin-Resource-Policy"] == "cross-origin"
    assert headers["X-XSS-Protection"] == "1; mode=block"


def test_the_class_defaults_follow_the_decision() -> None:
    defaults = SecurityHeadersManager.default_headers

    assert defaults["X-XSS-Protection"] == "0"
    assert defaults["Cross-Origin-Resource-Policy"] == "same-site"
    assert "Cross-Origin-Embedder-Policy" not in defaults
