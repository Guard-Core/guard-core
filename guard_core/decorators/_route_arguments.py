from datetime import datetime
from ipaddress import ip_network
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from guard_core.models import VALID_CLOUD_PROVIDERS

_CANONICAL_CLOUD_PROVIDERS = {name.casefold(): name for name in VALID_CLOUD_PROVIDERS}


BUILT_IN_AUTH_SCHEMES = ("bearer", "basic")


def canonical_auth_scheme(scheme: str) -> str:
    # RFC 9110 section 11.1: auth scheme names are case-insensitive.
    folded = scheme.lower()
    return folded if folded in BUILT_IN_AUTH_SCHEMES else scheme


def whole_header_verifier_note(declared: str, scheme: str) -> str:
    return (
        f"require_auth(type={declared!r}) uses the built-in {scheme!r} scheme, as "
        "HTTP auth scheme names are case-insensitive, and its verifier still "
        "receives the whole Authorization header, as in guard-core 4.4.0. "
        "guard-core 5.0.0 passes the verifier only the credential, as for "
        f"type={scheme!r}; use type={scheme!r} to get that now."
    )


def canonical_cloud_selector(selector: str) -> str | None:
    name, separator, region = selector.partition(":!")
    canonical = _CANONICAL_CLOUD_PROVIDERS.get(name.casefold())
    return None if canonical is None else f"{canonical}{separator}{region}"


def invalid_ip_entries(entries: list[str] | None) -> list[str]:
    invalid = []
    for entry in entries or []:
        try:
            ip_network(entry, strict=False)
        except ValueError:
            invalid.append(entry)
    return invalid


def invalid_time_of_day(value: str) -> bool:
    try:
        datetime.strptime(value, "%H:%M")
    except ValueError:
        return True
    return False


def unknown_time_zone(name: str) -> bool:
    try:
        ZoneInfo(name)
    except (ZoneInfoNotFoundError, ValueError, OSError):
        return True
    return False
