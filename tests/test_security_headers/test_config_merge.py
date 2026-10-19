import logging
from typing import Any

import pytest

from guard_core._misconfiguration import config_misconfigurations
from guard_core._security_headers_defaults import effective_security_headers_config
from guard_core.handlers.security_headers_handler import security_headers_manager
from guard_core.models import SecurityConfig


async def _headers(security_headers: dict | None) -> dict[str, str]:
    config = SecurityConfig(enable_redis=False, security_headers=security_headers)
    return await security_headers_manager.get_headers("/x", config=config)


async def test_a_partial_dict_merges_over_the_defaults() -> None:
    headers = await _headers({"csp": {"default-src": ["'self'"]}})

    assert headers["Content-Security-Policy"] == "default-src 'self'"
    assert headers["Strict-Transport-Security"] == "max-age=31536000; includeSubDomains"
    assert headers["X-Frame-Options"] == "SAMEORIGIN"
    assert headers["X-Content-Type-Options"] == "nosniff"


async def test_a_partial_hsts_merges_over_the_default_hsts() -> None:
    headers = await _headers({"hsts": {"preload": True}})

    assert (
        headers["Strict-Transport-Security"]
        == "max-age=31536000; includeSubDomains; preload"
    )


async def test_hsts_none_switches_hsts_off() -> None:
    headers = await _headers({"hsts": None})

    assert "Strict-Transport-Security" not in headers
    assert headers["X-Frame-Options"] == "SAMEORIGIN"


@pytest.mark.parametrize("value", [None, {"enabled": False}, {}])
async def test_none_enabled_false_and_empty_dict_all_mean_off(
    value: dict[str, Any] | None,
) -> None:
    assert await _headers(value) == {}


async def test_enabled_true_alone_gives_the_full_default_set() -> None:
    headers = await _headers({"enabled": True})

    assert "Strict-Transport-Security" in headers
    assert "X-Frame-Options" in headers


async def test_a_partial_dict_without_enabled_is_on() -> None:
    assert await _headers({"frame_options": "DENY"}) != {}


def _unknown_key_problems(config: SecurityConfig) -> list[str]:
    return [p for p in config_misconfigurations(config) if "security_headers" in p]


def test_an_unknown_key_is_reported_as_misconfiguration(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.WARNING, logger="guard_core.models"):
        config = SecurityConfig(
            enable_redis=False,
            fail_on_misconfiguration=False,
            security_headers={"enabled": True, "frame_option": "DENY"},
        )

    problems = _unknown_key_problems(config)
    assert len(problems) == 1
    assert "'frame_option'" in problems[0]
    assert any("frame_option" in record.getMessage() for record in caplog.records)


def test_an_unknown_key_fails_startup_by_default() -> None:
    with pytest.raises(ValueError, match="frame_option"):
        SecurityConfig(
            enable_redis=False,
            security_headers={"enabled": True, "frame_option": "DENY"},
        )


def test_an_unknown_key_fails_startup_with_the_flag() -> None:
    with pytest.raises(ValueError, match="frame_option"):
        SecurityConfig(
            enable_redis=False,
            fail_on_misconfiguration=True,
            security_headers={"enabled": True, "frame_option": "DENY"},
        )


def test_an_unknown_key_in_the_hsts_dict_is_reported() -> None:
    config = SecurityConfig(
        enable_redis=False,
        fail_on_misconfiguration=False,
        security_headers={"hsts": {"max_ag": 5}},
    )
    assert "max_ag" in _unknown_key_problems(config)[0]


def test_known_keys_and_the_default_dict_report_nothing() -> None:
    config = SecurityConfig(enable_redis=False)
    assert _unknown_key_problems(config) == []
    config = SecurityConfig(
        enable_redis=False,
        security_headers={
            "enabled": True,
            "hsts": {"max_age": 1, "include_subdomains": True, "preload": False},
            "csp": None,
            "frame_options": "DENY",
            "content_type_options": "nosniff",
            "xss_protection": "0",
            "referrer_policy": "no-referrer",
            "permissions_policy": None,
            "custom": None,
            "cross_origin_embedder_policy": "require-corp",
            "cross_origin_opener_policy": "same-origin",
            "cross_origin_resource_policy": "same-site",
            "permitted_cross_domain_policies": "none",
            "download_options": "noopen",
        },
    )
    assert _unknown_key_problems(config) == []


def test_off_values_report_nothing() -> None:
    for value in (None, {}, {"enabled": False}):
        config = SecurityConfig(enable_redis=False, security_headers=value)
        assert _unknown_key_problems(config) == []


def test_the_effective_config_is_none_when_headers_are_off() -> None:
    for value in (None, {}, {"enabled": False}):
        assert effective_security_headers_config(value) is None
    merged = effective_security_headers_config({"hsts": {"preload": True}})
    assert merged is not None
    assert merged["hsts"] == {
        "max_age": 31536000,
        "include_subdomains": True,
        "preload": True,
    }
