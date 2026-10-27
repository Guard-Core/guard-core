from collections.abc import Mapping

from guard_core.handlers.security_headers_handler import SecurityHeadersManager
from guard_core.models import SecurityConfig


def _text_setting(settings: Mapping[str, object], key: str, default: str) -> str | None:
    value = settings.get(key, default)
    if value is None or isinstance(value, str):
        return value
    raise TypeError(f"the {key} setting must be a string")


def _csp_setting(value: object) -> dict[str, list[str]] | None:
    if not value:
        return None
    if isinstance(value, dict):
        return value
    raise TypeError("the csp setting must map each directive to its sources")


def _custom_setting(value: object) -> dict[str, str] | None:
    if not value:
        return None
    if isinstance(value, dict):
        return value
    raise TypeError("the custom setting must map header names to values")


def _hsts_settings(settings: Mapping[str, object]) -> Mapping[str, object]:
    hsts = settings.get("hsts") or {}
    if isinstance(hsts, Mapping):
        return hsts
    raise TypeError("the hsts setting must be a mapping of its options")


def _hsts_max_age(hsts: Mapping[str, object]) -> int | None:
    max_age = hsts.get("max_age")
    if max_age is None or isinstance(max_age, int):
        return max_age
    raise TypeError("the hsts max_age setting must be an integer")


def apply_security_headers_settings(
    manager: SecurityHeadersManager, config: SecurityConfig
) -> None:
    settings = config.security_headers
    if not settings or not settings.get("enabled", True):
        manager.enabled = False
        return

    manager.enabled = True
    hsts = _hsts_settings(settings)
    manager.configure(
        enabled=True,
        csp=_csp_setting(settings.get("csp")),
        hsts_max_age=_hsts_max_age(hsts),
        hsts_include_subdomains=bool(hsts.get("include_subdomains", True)),
        hsts_preload=bool(hsts.get("preload", False)),
        frame_options=_text_setting(settings, "frame_options", "SAMEORIGIN"),
        content_type_options=_text_setting(settings, "content_type_options", "nosniff"),
        xss_protection=_text_setting(settings, "xss_protection", "1; mode=block"),
        referrer_policy=_text_setting(
            settings, "referrer_policy", "strict-origin-when-cross-origin"
        ),
        permissions_policy=_text_setting(settings, "permissions_policy", "UNSET"),
        custom_headers=_custom_setting(settings.get("custom")),
        cors_origins=config.cors_allow_origins if config.enable_cors else None,
        cors_allow_credentials=config.cors_allow_credentials,
        cors_allow_methods=config.cors_allow_methods,
        cors_allow_headers=config.cors_allow_headers,
    )
