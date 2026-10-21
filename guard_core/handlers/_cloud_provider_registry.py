import ipaddress
from collections.abc import Collection

_ALL_PROVIDERS = set({"AWS", "GCP", "Azure", "DigitalOcean", "Linode", "Vultr"})


def _parse_cloud_selectors(
    selectors: set[str],
) -> tuple[set[str], dict[str, set[str]]]:
    blocked: set[str] = set()
    carveouts: dict[str, set[str]] = {}
    for selector in selectors:
        provider, marker, region = selector.partition(":!")
        blocked.add(provider)
        if marker and region:
            carveouts.setdefault(provider, set()).add(region)
    return blocked, carveouts


def merge_cloud_selectors(*sources: Collection[str] | None) -> set[str]:
    """Union what the sources block: a provider is blocked when any source
    blocks it, and its carve-outs are those every blocking source shares."""
    blocked: set[str] = set()
    shared: dict[str, set[str]] = {}
    for source in sources:
        source_blocked, source_carveouts = _parse_cloud_selectors(set(source or ()))
        for provider in source_blocked:
            regions = source_carveouts.get(provider, set())
            shared[provider] = (
                shared[provider] & regions if provider in blocked else set(regions)
            )
            blocked.add(provider)
    return {
        selector
        for provider in blocked
        for selector in (
            [f"{provider}:!{region}" for region in sorted(shared[provider])]
            or [provider]
        )
    }


def _bare_provider_names(providers: Collection[str]) -> set[str]:
    return {provider.partition(":!")[0] for provider in providers}


def _encode_cached(
    ranges: set[ipaddress.IPv4Network | ipaddress.IPv6Network],
    regions: dict[str, str],
) -> set[str]:
    encoded: set[str] = set()
    for network in ranges:
        key = str(network)
        region = regions.get(key)
        encoded.add(f"{key}|{region}" if region else key)
    return encoded


def _decode_cached(
    entries: set[str],
) -> tuple[set[ipaddress.IPv4Network | ipaddress.IPv6Network], dict[str, str]]:
    networks: set[ipaddress.IPv4Network | ipaddress.IPv6Network] = set()
    regions: dict[str, str] = {}
    for entry in entries:
        prefix, separator, region = entry.partition("|")
        network = ipaddress.ip_network(prefix)
        networks.add(network)
        if separator and region:
            regions[str(network)] = region
    return networks, regions
