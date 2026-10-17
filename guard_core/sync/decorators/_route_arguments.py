from datetime import datetime
from ipaddress import ip_network
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

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
