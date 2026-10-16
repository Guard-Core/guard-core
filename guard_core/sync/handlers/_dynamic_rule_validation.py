import re
from typing import Any

from guard_core._security_config_field_validators import (
    canonicalize_cloud_provider_selector,
)

_COUNTRY_CODE = re.compile(r"[A-Za-z]{2}")


class MalformedDynamicRules(ValueError):
    def __init__(self, problems: list[str]) -> None:
        super().__init__("; ".join(problems))
        self.problems = problems


def _below_one(value: Any) -> bool:
    return value is not None and value < 1


def _rate_limit_problems(rules: Any) -> list[str]:
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


def find_malformed_values(rules: Any) -> list[str]:
    return [
        *_rate_limit_problems(rules),
        *_country_problems("blocked_countries", rules.blocked_countries),
        *_country_problems("whitelist_countries", rules.whitelist_countries),
        *_provider_problems(rules.blocked_cloud_providers),
    ]
