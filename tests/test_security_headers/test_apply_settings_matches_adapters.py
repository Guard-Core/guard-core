from typing import Any

import pytest

from guard_core.handlers._security_headers_apply import (
    apply_security_headers_settings,
)
from guard_core.handlers.security_headers_handler import SecurityHeadersManager
from guard_core.models import SecurityConfig

# The one intended difference from the adapters' reader: a block that leaves
# xss_protection out takes the default "0" (decisions 5.12 and 5.18), where the
# adapters fell back to "1; mode=block".
XSS_DEFAULT = "0"


def adapter_copy(manager: SecurityHeadersManager, config: SecurityConfig) -> None:
    # The settings reader every adapter carried (fastapi-guard middleware.py).
    headers_config: dict[str, Any] | None = config.security_headers
    if not headers_config:
        manager.enabled = False
        return

    if not headers_config.get("enabled", True):
        manager.enabled = False
        return

    manager.enabled = True
    hsts_config = headers_config.get("hsts") or {}

    manager.configure(
        enabled=headers_config.get("enabled", True),
        csp=headers_config.get("csp"),
        hsts_max_age=hsts_config.get("max_age"),
        hsts_include_subdomains=hsts_config.get("include_subdomains", True),
        hsts_preload=hsts_config.get("preload", False),
        frame_options=headers_config.get("frame_options", "SAMEORIGIN"),
        content_type_options=headers_config.get("content_type_options", "nosniff"),
        xss_protection=headers_config.get("xss_protection", XSS_DEFAULT),
        referrer_policy=headers_config.get(
            "referrer_policy", "strict-origin-when-cross-origin"
        ),
        permissions_policy=headers_config.get("permissions_policy", "UNSET"),
        custom_headers=headers_config.get("custom"),
        cors_origins=config.cors_allow_origins if config.enable_cors else None,
        cors_allow_credentials=config.cors_allow_credentials,
        cors_allow_methods=config.cors_allow_methods,
        cors_allow_headers=config.cors_allow_headers,
    )


def _state(manager: SecurityHeadersManager) -> dict[str, object]:
    return {
        "enabled": manager.enabled,
        "csp": manager.csp_config,
        "hsts": manager.hsts_config,
        "cors": manager.cors_config,
        "default_headers": manager.default_headers,
        "custom_headers": manager.custom_headers,
    }


FULL_BLOCK: dict[str, object] = {
    "enabled": True,
    "csp": {"default-src": ["'self'"], "img-src": ["'self'", "data:"]},
    "hsts": {"max_age": 63072000, "include_subdomains": False, "preload": False},
    "frame_options": "DENY",
    "content_type_options": "nosniff",
    "xss_protection": "0",
    "referrer_policy": "no-referrer",
    "permissions_policy": "geolocation=()",
    "custom": {"X-Custom": "value"},
}

CASES: dict[str, dict[str, object]] = {
    "defaults": {},
    "full": {"security_headers": FULL_BLOCK},
    "partial": {"security_headers": {"csp": {"default-src": ["'self'"]}}},
    "hsts_none": {"security_headers": {"hsts": None}},
    "hsts_preload": {
        "security_headers": {
            "hsts": {"max_age": 31536000, "include_subdomains": True, "preload": True}
        }
    },
    "permissions_policy_empty": {"security_headers": {"permissions_policy": ""}},
    "permissions_policy_none": {"security_headers": {"permissions_policy": None}},
    "disabled": {"security_headers": {"enabled": False, "frame_options": "DENY"}},
    "none": {"security_headers": None},
    "empty": {"security_headers": {}},
    "cors_on": {
        "security_headers": FULL_BLOCK,
        "enable_cors": True,
        "cors_allow_origins": ["https://a.example/", "https://b.example"],
        "cors_allow_credentials": True,
        "cors_allow_methods": ["GET", "PUT"],
        "cors_allow_headers": ["X-One", "X-Two"],
    },
    "cors_off_with_origins": {
        "enable_cors": False,
        "cors_allow_origins": ["https://a.example"],
    },
}


@pytest.mark.parametrize("case", CASES)
def test_the_manager_gets_the_state_each_adapter_copy_gave_it(case: str) -> None:
    config = SecurityConfig(enable_redis=False, **CASES[case])
    adapter, engine = SecurityHeadersManager(), SecurityHeadersManager()

    adapter_copy(adapter, config)
    apply_security_headers_settings(engine, config)

    assert _state(engine) == _state(adapter)


def test_a_disabled_block_leaves_the_manager_off_and_unconfigured() -> None:
    config = SecurityConfig(
        enable_redis=False, security_headers={"enabled": False, "csp": {"a": ["b"]}}
    )
    manager = SecurityHeadersManager()

    apply_security_headers_settings(manager, config)

    assert manager.enabled is False
    assert manager.csp_config is None


REFUSED_AFTER_CONFIG_TIME: dict[str, tuple[dict[str, object], str]] = {
    "hsts_not_a_mapping": ({"hsts": "x"}, "the hsts setting must be a mapping"),
    "hsts_max_age_not_an_int": ({"hsts": {"max_age": "x"}}, "max_age setting must"),
    "csp_not_a_dict": ({"csp": "x"}, "the csp setting must map"),
    "custom_not_a_dict": ({"custom": "x"}, "the custom setting must map"),
    "named_not_a_string": ({"frame_options": 5}, "the frame_options setting must"),
}


@pytest.mark.parametrize("case", REFUSED_AFTER_CONFIG_TIME)
def test_a_setting_of_the_wrong_shape_assigned_around_validation_is_refused(
    case: str,
) -> None:
    settings, message = REFUSED_AFTER_CONFIG_TIME[case]
    config = SecurityConfig.model_construct(security_headers=settings)

    with pytest.raises(TypeError, match=message):
        apply_security_headers_settings(SecurityHeadersManager(), config)


async def test_a_partial_block_sends_the_default_x_xss_protection() -> None:
    config = SecurityConfig(
        enable_redis=False, security_headers={"enabled": True, "frame_options": "DENY"}
    )
    manager = SecurityHeadersManager()

    apply_security_headers_settings(manager, config)
    headers = await manager.get_headers("/x")

    assert headers["X-XSS-Protection"] == "0"
    assert headers["X-Frame-Options"] == "DENY"
