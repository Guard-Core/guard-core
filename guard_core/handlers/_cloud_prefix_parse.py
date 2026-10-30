import ipaddress
import logging

logger = logging.getLogger("guard_core.handlers.cloud")


def parse_prefix_or_note(
    prefix: str, provider: str, rejected: list[str]
) -> ipaddress.IPv4Network | ipaddress.IPv6Network | None:
    """One bad prefix must not discard the provider's other ranges."""
    try:
        return ipaddress.ip_network(prefix)
    except ValueError:
        rejected.append(prefix)
        return None


def log_rejected_prefixes(provider: str, rejected: list[str]) -> None:
    if rejected:
        logger.warning(
            f"{provider} IP ranges: skipped {len(rejected)} invalid prefix(es), "
            f"the first is {rejected[0]!r}; the valid ones were kept"
        )
