from collections.abc import Mapping

SECURITY_HEADER_NAMES: dict[str, str] = {
    "content_type_options": "X-Content-Type-Options",
    "frame_options": "X-Frame-Options",
    "xss_protection": "X-XSS-Protection",
    "referrer_policy": "Referrer-Policy",
    "permissions_policy": "Permissions-Policy",
    "permitted_cross_domain_policies": "X-Permitted-Cross-Domain-Policies",
    "download_options": "X-Download-Options",
    "cross_origin_embedder_policy": "Cross-Origin-Embedder-Policy",
    "cross_origin_opener_policy": "Cross-Origin-Opener-Policy",
    "cross_origin_resource_policy": "Cross-Origin-Resource-Policy",
}

KNOWN_SECURITY_HEADERS_KEYS: frozenset[str] = frozenset(
    {"enabled", "hsts", "csp", "custom", *SECURITY_HEADER_NAMES}
)

KNOWN_HSTS_KEYS: frozenset[str] = frozenset(
    {"max_age", "include_subdomains", "preload"}
)

_DEFAULT_HSTS: dict[str, object] = {
    "max_age": 31536000,
    "include_subdomains": True,
    "preload": False,
}

_DEFAULT_SECURITY_HEADERS_CONFIG: dict[str, object] = {
    "enabled": True,
    "hsts": _DEFAULT_HSTS,
    "csp": None,
    "frame_options": "SAMEORIGIN",
    "content_type_options": "nosniff",
    "xss_protection": "0",
    "referrer_policy": "strict-origin-when-cross-origin",
    "permissions_policy": "geolocation=(), microphone=(), camera=()",
    "custom": None,
    "permitted_cross_domain_policies": "none",
    "download_options": "noopen",
    "cross_origin_embedder_policy": None,
    "cross_origin_opener_policy": "same-origin",
    "cross_origin_resource_policy": "same-site",
}


def default_security_headers_config() -> dict[str, object]:
    return {**_DEFAULT_SECURITY_HEADERS_CONFIG, "hsts": dict(_DEFAULT_HSTS)}


def security_headers_are_off(raw: Mapping[str, object] | None) -> bool:
    return not raw or not raw.get("enabled", True)


def effective_security_headers_config(
    raw: Mapping[str, object] | None,
) -> dict[str, object] | None:
    if not raw or security_headers_are_off(raw):
        return None
    effective = default_security_headers_config()
    for key, value in raw.items():
        if key == "hsts" and isinstance(value, dict):
            effective["hsts"] = {**_DEFAULT_HSTS, **value}
        else:
            effective[key] = value
    return effective


def unknown_security_headers_keys(raw: Mapping[str, object] | None) -> list[str]:
    if not raw or security_headers_are_off(raw):
        return []
    unknown = [str(key) for key in raw if key not in KNOWN_SECURITY_HEADERS_KEYS]
    hsts = raw.get("hsts")
    if isinstance(hsts, dict):
        unknown.extend(f"hsts.{key}" for key in hsts if key not in KNOWN_HSTS_KEYS)
    return sorted(unknown)
