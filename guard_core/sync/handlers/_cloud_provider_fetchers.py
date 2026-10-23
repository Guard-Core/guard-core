import ipaddress
import logging

logger = logging.getLogger("guard_core.sync.handlers.cloud")


def fetch_aws_ip_ranges() -> tuple[
    set[ipaddress.IPv4Network | ipaddress.IPv6Network], dict[str, str]
]:
    import requests

    try:
        with requests.Session() as session:
            response = session.get(
                "https://ip-ranges.amazonaws.com/ip-ranges.json",
                timeout=10,
            )
            response.raise_for_status()
            data = response.json()
        networks: set[ipaddress.IPv4Network | ipaddress.IPv6Network] = set()
        regions: dict[str, str] = {}
        for ip_range in data["prefixes"]:
            if ip_range["service"] != "AMAZON":
                continue
            network = ipaddress.ip_network(ip_range["ip_prefix"])
            networks.add(network)
            region = ip_range.get("region")
            if region:
                regions[str(network)] = region
        return networks, regions
    except Exception as e:
        logger.error(f"Failed to fetch AWS IP ranges: {str(e)}")
        return set(), {}


def fetch_gcp_ip_ranges() -> tuple[
    set[ipaddress.IPv4Network | ipaddress.IPv6Network], dict[str, str]
]:
    import requests

    try:
        with requests.Session() as session:
            response = session.get(
                "https://www.gstatic.com/ipranges/cloud.json",
                timeout=10,
            )
            response.raise_for_status()
            data = response.json()
        networks: set[ipaddress.IPv4Network | ipaddress.IPv6Network] = set()
        regions: dict[str, str] = {}
        for ip_range in data["prefixes"]:
            prefix = ip_range.get("ipv4Prefix") or ip_range.get("ipv6Prefix")
            if not prefix:
                continue
            network = ipaddress.ip_network(prefix)
            networks.add(network)
            scope = ip_range.get("scope")
            if scope:
                regions[str(network)] = scope
        return networks, regions
    except Exception as e:
        logger.error(f"Failed to fetch GCP IP ranges: {str(e)}")
        return set(), {}


def _fetch_csv_prefix_networks(
    url: str,
) -> set[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    import requests

    with requests.Session() as session:
        response = session.get(
            url,
            timeout=10,
        )
        response.raise_for_status()
        body = response.text

    networks: set[ipaddress.IPv4Network | ipaddress.IPv6Network] = set()
    for raw_line in body.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        prefix = line.split(",", 1)[0].strip()
        if not prefix:
            continue
        try:
            networks.add(ipaddress.ip_network(prefix))
        except ValueError:
            continue
    return networks


def fetch_digitalocean_ip_ranges() -> set[
    ipaddress.IPv4Network | ipaddress.IPv6Network
]:
    try:
        return _fetch_csv_prefix_networks(
            "https://www.digitalocean.com/geo/google.csv"
        )
    except Exception as e:
        logger.error(f"Failed to fetch DigitalOcean IP ranges: {str(e)}")
        return set()


def fetch_linode_ip_ranges() -> set[
    ipaddress.IPv4Network | ipaddress.IPv6Network
]:
    try:
        return _fetch_csv_prefix_networks("https://geoip.linode.com/")
    except Exception as e:
        logger.error(f"Failed to fetch Linode IP ranges: {str(e)}")
        return set()


def fetch_vultr_ip_ranges() -> set[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    import requests

    try:
        with requests.Session() as session:
            response = session.get(
                "https://geofeed.constant.com/?json",
                timeout=10,
            )
            response.raise_for_status()
            data = response.json()

        networks: set[ipaddress.IPv4Network | ipaddress.IPv6Network] = set()
        for entry in data.get("subnets", []):
            prefix = entry.get("ip_prefix")
            if not prefix:
                continue
            try:
                networks.add(ipaddress.ip_network(prefix))
            except ValueError:
                continue
        return networks
    except Exception as e:
        logger.error(f"Failed to fetch Vultr IP ranges: {str(e)}")
        return set()
