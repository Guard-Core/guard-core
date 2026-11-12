import ipaddress
import re
from collections.abc import Mapping

from guard_core._misconfiguration_kinds import (
    K_DYNAMIC_AUTO_BAN_DURATION_BELOW_ONE,
    K_DYNAMIC_BLOCKED_CLOUD_PROVIDERS_UNKNOWN,
    K_DYNAMIC_BLOCKED_COUNTRIES_INVALID_CODE,
    K_DYNAMIC_EMERGENCY_WHITELIST_INVALID_ENTRY,
    K_DYNAMIC_GLOBAL_RATE_LIMIT_BELOW_ONE,
    K_DYNAMIC_GLOBAL_RATE_WINDOW_BELOW_ONE,
    K_DYNAMIC_IP_BAN_DURATION_BELOW_ONE,
    K_DYNAMIC_IP_BLACKLIST_INVALID_ENTRY,
    K_DYNAMIC_IP_WHITELIST_INVALID_ENTRY,
    K_DYNAMIC_WHITELIST_COUNTRIES_INVALID_CODE,
    K_ENDPOINT_KEY_ROUTER_TEMPLATE,
    K_ENDPOINT_KEY_ROUTING_ANOMALY,
    K_ENDPOINT_LIMIT_BELOW_ONE,
    Problem,
)
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
    problems: list[str] = [
        Problem(f"{name}: {value} (must be at least 1)", kind=kind)
        for name, value, kind in (
            (
                "global_rate_limit",
                rules.global_rate_limit,
                K_DYNAMIC_GLOBAL_RATE_LIMIT_BELOW_ONE,
            ),
            (
                "global_rate_window",
                rules.global_rate_window,
                K_DYNAMIC_GLOBAL_RATE_WINDOW_BELOW_ONE,
            ),
        )
        if _below_one(value)
    ]
    problems.extend(
        Problem(
            f"endpoint_rate_limits[{endpoint}]: {tuple(limit)} "
            "(requests and window must be at least 1)",
            kind=K_ENDPOINT_LIMIT_BELOW_ONE,
            subject=endpoint,
        )
        for endpoint, limit in rules.endpoint_rate_limits.items()
        if any(_below_one(part) for part in limit)
    )
    return problems


def _ban_duration_problems(rules: DynamicRulesProtocol) -> list[str]:
    return [
        Problem(f"{name}: {value} (must be at least 1)", kind=kind)
        for name, value, kind in (
            (
                "ip_ban_duration",
                rules.ip_ban_duration,
                K_DYNAMIC_IP_BAN_DURATION_BELOW_ONE,
            ),
            (
                "auto_ban_duration",
                rules.auto_ban_duration,
                K_DYNAMIC_AUTO_BAN_DURATION_BELOW_ONE,
            ),
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

    problems: list[str] = []
    for endpoint, limit in endpoint_rate_limits.items():
        if _has_routing_anomaly_in_any_decoding(endpoint):
            problems.append(
                Problem(
                    f"endpoint_rate_limits[{endpoint}]: {tuple(limit)} "
                    "(a dot segment, an empty segment, a backslash or an encoded dot "
                    "or separator, in any decoding round)",
                    kind=K_ENDPOINT_KEY_ROUTING_ANOMALY,
                    subject=endpoint,
                )
            )
        if is_router_template(endpoint):
            problems.append(
                Problem(
                    f"endpoint_rate_limits[{endpoint}]: {tuple(limit)} "
                    "(a router template, a regex route or a glob, which matches only "
                    "that literal text and so limits nothing; write a concrete path)",
                    kind=K_ENDPOINT_KEY_ROUTER_TEMPLATE,
                    subject=endpoint,
                )
            )
    return problems


def _endpoint_key_problems(rules: DynamicRulesProtocol) -> list[str]:
    return endpoint_rate_limit_key_problems(rules.endpoint_rate_limits)


def _country_problems(name: str, codes: list[str], kind: str) -> list[str]:
    return [
        Problem(
            f"{name}: {code!r} (not a two-letter country code)",
            kind=kind,
            subject=str(code),
        )
        for code in codes
        if not _COUNTRY_CODE.fullmatch(str(code))
    ]


def _provider_problems(providers: set[str]) -> list[str]:
    return [
        Problem(
            f"blocked_cloud_providers: {provider!r} (unknown cloud provider)",
            kind=K_DYNAMIC_BLOCKED_CLOUD_PROVIDERS_UNKNOWN,
            subject=str(provider),
        )
        for provider in sorted(providers, key=str)
        if canonicalize_cloud_provider_selector(provider) is None
    ]


def _ip_problems(name: str, entries: list[str], kind: str) -> list[str]:
    problems: list[str] = []
    for entry in entries:
        try:
            ipaddress.ip_network(entry, strict=False)
        except ValueError:
            problems.append(
                Problem(
                    f"{name}: {entry!r} (not an IP address or CIDR range)",
                    kind=kind,
                    subject=str(entry),
                )
            )
    return problems


def find_malformed_values(rules: DynamicRulesProtocol) -> list[str]:
    return [
        *_ip_problems(
            "ip_blacklist", rules.ip_blacklist, K_DYNAMIC_IP_BLACKLIST_INVALID_ENTRY
        ),
        *_ip_problems(
            "ip_whitelist", rules.ip_whitelist, K_DYNAMIC_IP_WHITELIST_INVALID_ENTRY
        ),
        *_ip_problems(
            "emergency_whitelist",
            rules.emergency_whitelist,
            K_DYNAMIC_EMERGENCY_WHITELIST_INVALID_ENTRY,
        ),
        *_rate_limit_problems(rules),
        *_ban_duration_problems(rules),
        *_endpoint_key_problems(rules),
        *_country_problems(
            "blocked_countries",
            rules.blocked_countries,
            K_DYNAMIC_BLOCKED_COUNTRIES_INVALID_CODE,
        ),
        *_country_problems(
            "whitelist_countries",
            rules.whitelist_countries,
            K_DYNAMIC_WHITELIST_COUNTRIES_INVALID_CODE,
        ),
        *_provider_problems(rules.blocked_cloud_providers),
    ]
