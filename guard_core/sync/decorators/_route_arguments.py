from ipaddress import ip_network

from guard_core.models import VALID_CLOUD_PROVIDERS

_CANONICAL_CLOUD_PROVIDERS = {name.casefold(): name for name in VALID_CLOUD_PROVIDERS}


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
