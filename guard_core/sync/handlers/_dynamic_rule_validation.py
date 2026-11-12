import ipaddress
import re
from collections.abc import Mapping

from guard_core._security_config_field_validators import (
    canonicalize_cloud_provider_selector,
)
from guard_core.sync.protocols.agent_protocol import DynamicRulesProtocol

_COUNTRY_CODE = re.compile(r"[A-Za-z]{2}")


class MalformedDynamicRules(ValueError):
    def __init__(self, problems: list[str]) -> None:
        super().__init__("; ".join(problems))
        self.problems = problems


def _below_one(value: int | None) -> bool:
    return value is not None and value < 1


def _rate_limit_problems(rules: DynamicRulesProtocol) -> list[str]:
    problems = [
        f"{name}: {value} (must be at least 1)"
        for name, value in (
            ("global_rate_limit", rules.global_rate_limit),
            ("global_rate_window", rules.global_rate_window),
        )
        if _below_one(value)
    ]
    problems.extend(
        f"endpoint_rate_limits[{endpoint}]: {tuple(limit)} "
        "(requests and window must be at least 1)"
        for endpoint, limit in rules.endpoint_rate_limits.items()
        if any(_below_one(part) for part in limit)
    )
    return problems


def _ban_duration_problems(rules: DynamicRulesProtocol) -> list[str]:
    return [
        f"{name}: {value} (must be at least 1)"
        for name, value in (
            ("ip_ban_duration", rules.ip_ban_duration),
            ("auto_ban_duration", rules.auto_ban_duration),
        )
        if _below_one(value)
    ]


def endpoint_rate_limit_key_problems(
    endpoint_rate_limits: Mapping[str, tuple[int, int]],
) -> list[str]:
    from guard_core.sync.core.validation.path_matching import (
        _has_routing_anomaly_in_any_decoding,
        is_router_template,
    )

    problems = []
    for endpoint, limit in endpoint_rate_limits.items():
        if _has_routing_anomaly_in_any_decoding(endpoint):
            problems.append(
                f"endpoint_rate_limits[{endpoint}]: {tuple(limit)} "
                "(a dot segment, an empty segment, a backslash or an encoded dot "
                "or separator, in any decoding round)"
            )
        if is_router_template(endpoint):
            problems.append(
                f"endpoint_rate_limits[{endpoint}]: {tuple(limit)} "
                "(a router template, a regex route or a glob, which matches only that "
                "literal text and so limits nothing; write a concrete path)"
            )
    return problems


def _endpoint_key_problems(rules: DynamicRulesProtocol) -> list[str]:
    return endpoint_rate_limit_key_problems(rules.endpoint_rate_limits)


def _country_problems(name: str, codes: list[str]) -> list[str]:
    return [
        f"{name}: {code!r} (not a two-letter country code)"
        for code in codes
        if not _COUNTRY_CODE.fullmatch(str(code))
    ]


def _provider_problems(providers: set[str]) -> list[str]:
    return [
        f"blocked_cloud_providers: {provider!r} (unknown cloud provider)"
        for provider in sorted(providers, key=str)
        if canonicalize_cloud_provider_selector(provider) is None
    ]


def _ip_problems(name: str, entries: list[str]) -> list[str]:
    problems = []
    for entry in entries:
        try:
            ipaddress.ip_network(entry, strict=False)
        except ValueError:
            problems.append(f"{name}: {entry!r} (not an IP address or CIDR range)")
    return problems


def find_malformed_values(rules: DynamicRulesProtocol) -> list[str]:
    return [
        *_ip_problems("ip_blacklist", rules.ip_blacklist),
        *_ip_problems("ip_whitelist", rules.ip_whitelist),
        *_ip_problems("emergency_whitelist", rules.emergency_whitelist),
        *_rate_limit_problems(rules),
        *_ban_duration_problems(rules),
        *_endpoint_key_problems(rules),
        *_country_problems("blocked_countries", rules.blocked_countries),
        *_country_problems("whitelist_countries", rules.whitelist_countries),
        *_provider_problems(rules.blocked_cloud_providers),
    ]
