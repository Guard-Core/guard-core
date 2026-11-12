import logging
from ipaddress import IPv6Network, ip_network
from typing import TYPE_CHECKING

from guard_core._misconfiguration import report_misconfigurations
from guard_core._misconfiguration_kinds import K_NAT64_INVALID_ENTRY, Problem
from guard_core.sync._utils.nat64 import (
    NAT64_PREFIX_LENGTHS,
    configure_nat64_prefixes,
)

if TYPE_CHECKING:
    from guard_core.models import SyncSecurityConfig

_LENGTHS = ", ".join(f"/{length}" for length in sorted(NAT64_PREFIX_LENGTHS))


def _valid_prefix(entry: str) -> IPv6Network | None:
    try:
        network = ip_network(entry, strict=False)
    except ValueError:
        return None
    if isinstance(network, IPv6Network) and network.prefixlen in NAT64_PREFIX_LENGTHS:
        return network
    return None


def apply_nat64_prefixes(config: "SyncSecurityConfig", logger: logging.Logger) -> None:
    valid: list[IPv6Network] = []
    problems: list[Problem] = []
    for entry in config.nat64_prefixes:
        network = _valid_prefix(entry)
        if network is None:
            problems.append(
                Problem(
                    f"nat64_prefixes entry {entry!r} is not an IPv6 prefix of "
                    f"length {_LENGTHS} (RFC 6052), so it is ignored.",
                    kind=K_NAT64_INVALID_ENTRY,
                    subject=entry,
                )
            )
        else:
            valid.append(network)
    report_misconfigurations(config, problems, logger=logger, stacklevel=5)
    configure_nat64_prefixes(config, valid)
