import logging
from collections.abc import Callable

from guard_core._misconfiguration_kinds import (
    K_ALLOW_COUNTRIES_EMPTY_LIST,
    K_BLOCK_CLOUDS_EMPTY_LIST,
    K_BLOCK_CLOUDS_UNKNOWN_PROVIDER,
    K_BLOCK_COUNTRIES_EMPTY_LIST,
    K_BYPASS_UNKNOWN_CHECK,
    K_REQUIRE_IP_EMPTY_WHITELIST,
    K_REQUIRE_IP_INVALID_ENTRY,
    Problem,
    kinds_log_extra,
)
from guard_core._security_config_field_validators import (
    canonicalize_cloud_provider_selector,
)
from guard_core.models import VALID_BYPASS_CHECKS, VALID_CLOUD_PROVIDERS
from guard_core.sync.decorators.base import (
    BaseSecurityMixin,
    GuardedParams,
    GuardedReturn,
)


def _canonical_and_unknown_providers(
    providers: list[str],
) -> tuple[set[str], list[str]]:
    resolved = [(p, canonicalize_cloud_provider_selector(p)) for p in providers]
    return (
        {canonical for _, canonical in resolved if canonical},
        sorted(p for p, canonical in resolved if canonical is None),
    )


class AccessControlMixin(BaseSecurityMixin):
    def require_ip(
        self,
        whitelist: list[str] | None = None,
        blacklist: list[str] | None = None,
    ) -> Callable[
        [Callable[GuardedParams, GuardedReturn]], Callable[GuardedParams, GuardedReturn]
    ]:
        def decorator(
            func: Callable[GuardedParams, GuardedReturn],
        ) -> Callable[GuardedParams, GuardedReturn]:
            from guard_core.sync.decorators._route_arguments import invalid_ip_entries

            problems: list[Problem] = []
            if whitelist is not None and not whitelist:
                problems.append(
                    Problem(
                        "@require_ip received an empty whitelist: an empty list "
                        "restricts nothing, so every address is allowed on this "
                        "route.",
                        kind=K_REQUIRE_IP_EMPTY_WHITELIST,
                    )
                )
            for name, entries in (("whitelist", whitelist), ("blacklist", blacklist)):
                problems.extend(
                    Problem(
                        f"@require_ip {name} entry {entry!r} is not a valid IP "
                        "address or CIDR network, so requests to this route can "
                        "be denied by mistake.",
                        kind=K_REQUIRE_IP_INVALID_ENTRY,
                        subject=str(entry),
                    )
                    for entry in invalid_ip_entries(entries)
                )
            self._report_misconfigurations(problems)
            route_config = self._ensure_route_config(func)
            if whitelist:
                route_config.ip_whitelist = whitelist
            if blacklist:
                route_config.ip_blacklist = blacklist
            return self._apply_route_config(func)

        return decorator

    def block_countries(
        self, countries: list[str]
    ) -> Callable[
        [Callable[GuardedParams, GuardedReturn]], Callable[GuardedParams, GuardedReturn]
    ]:
        def decorator(
            func: Callable[GuardedParams, GuardedReturn],
        ) -> Callable[GuardedParams, GuardedReturn]:
            if not countries:
                self._report_misconfiguration(
                    Problem(
                        "@block_countries received an empty country list: an empty "
                        "list blocks nothing on this route.",
                        kind=K_BLOCK_COUNTRIES_EMPTY_LIST,
                    )
                )
            if countries:
                self._require_geo_source("@block_countries")
            route_config = self._ensure_route_config(func)
            route_config.blocked_countries = [c.upper() for c in countries]
            return self._apply_route_config(func)

        return decorator

    def allow_countries(
        self, countries: list[str]
    ) -> Callable[
        [Callable[GuardedParams, GuardedReturn]], Callable[GuardedParams, GuardedReturn]
    ]:
        def decorator(
            func: Callable[GuardedParams, GuardedReturn],
        ) -> Callable[GuardedParams, GuardedReturn]:
            if not countries:
                self._report_misconfiguration(
                    Problem(
                        "@allow_countries received an empty country list: an empty "
                        "list restricts nothing, so every country is allowed on "
                        "this route.",
                        kind=K_ALLOW_COUNTRIES_EMPTY_LIST,
                    )
                )
            if countries:
                self._require_geo_source("@allow_countries")
            route_config = self._ensure_route_config(func)
            route_config.whitelist_countries = [c.upper() for c in countries]
            return self._apply_route_config(func)

        return decorator

    def _checked_cloud_providers(self, providers: list[str] | None) -> set[str] | None:
        if providers is None:
            return None
        canonical, unknown = _canonical_and_unknown_providers(providers)
        if not providers:
            self._report_misconfiguration(
                Problem(
                    "@block_clouds received an empty provider list: an empty "
                    "list blocks nothing on this route (call @block_clouds() to "
                    "block every provider).",
                    kind=K_BLOCK_CLOUDS_EMPTY_LIST,
                )
            )
        if unknown:
            self._report_misconfiguration(
                Problem(
                    f"@block_clouds: ignored unknown cloud providers {unknown}. "
                    f"Valid providers: {sorted(VALID_CLOUD_PROVIDERS)} (matched "
                    "case-insensitively).",
                    kind=K_BLOCK_CLOUDS_UNKNOWN_PROVIDER,
                    subject=", ".join(str(provider) for provider in unknown),
                )
            )
        return canonical

    def block_clouds(
        self, providers: list[str] | None = None
    ) -> Callable[
        [Callable[GuardedParams, GuardedReturn]], Callable[GuardedParams, GuardedReturn]
    ]:
        def decorator(
            func: Callable[GuardedParams, GuardedReturn],
        ) -> Callable[GuardedParams, GuardedReturn]:
            canonical = self._checked_cloud_providers(providers)
            route_config = self._ensure_route_config(func)
            route_config.block_cloud_providers = (
                set(VALID_CLOUD_PROVIDERS) if canonical is None else canonical
            )
            return self._apply_route_config(func)

        return decorator

    def bypass(
        self, checks: list[str]
    ) -> Callable[
        [Callable[GuardedParams, GuardedReturn]], Callable[GuardedParams, GuardedReturn]
    ]:
        def decorator(
            func: Callable[GuardedParams, GuardedReturn],
        ) -> Callable[GuardedParams, GuardedReturn]:
            route_config = self._ensure_route_config(func)
            valid = {c for c in checks if c in VALID_BYPASS_CHECKS}
            route_config.bypassed_checks.update(valid)
            invalid = set(checks) - valid
            if invalid:
                logging.getLogger("guard_core.sync.decorators").warning(
                    "@bypass: ignored unknown checks %s",
                    sorted(invalid, key=str),
                    extra=kinds_log_extra(
                        K_BYPASS_UNKNOWN_CHECK,
                        ", ".join(sorted(map(str, invalid))),
                    ),
                )
            return self._apply_route_config(func)

        return decorator
