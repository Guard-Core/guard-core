import logging
from collections.abc import Callable

from guard_core._security_config_field_validators import (
    canonicalize_cloud_provider_selector,
)
from guard_core.models import VALID_BYPASS_CHECKS, VALID_CLOUD_PROVIDERS
from guard_core.sync.decorators.base import (
    BaseSecurityMixin,
    GuardedParams,
    GuardedReturn,
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

            if whitelist is not None and not whitelist:
                self._report_misconfiguration(
                    "@require_ip received an empty whitelist: an empty list "
                    "restricts nothing, so every address is allowed on this route."
                )
            for name, entries in (("whitelist", whitelist), ("blacklist", blacklist)):
                for entry in invalid_ip_entries(entries):
                    self._report_misconfiguration(
                        f"@require_ip {name} entry {entry!r} is not a valid IP "
                        "address or CIDR network, so requests to this route can "
                        "be denied by mistake."
                    )
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
                    "@block_countries received an empty country list: an empty "
                    "list blocks nothing on this route."
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
                    "@allow_countries received an empty country list: an empty "
                    "list restricts nothing, so every country is allowed on this "
                    "route."
                )
            if countries:
                self._require_geo_source("@allow_countries")
            route_config = self._ensure_route_config(func)
            route_config.whitelist_countries = [c.upper() for c in countries]
            return self._apply_route_config(func)

        return decorator

    def _checked_cloud_providers(self, providers: list[str] | None) -> set[str] | None:
        canonical = (
            None
            if providers is None
            else {
                c for p in providers if (c := canonicalize_cloud_provider_selector(p))
            }
        )
        unknown = (
            []
            if providers is None
            else sorted(
                p for p in providers if canonicalize_cloud_provider_selector(p) is None
            )
        )
        if providers is not None and not providers:
            self._report_misconfiguration(
                "@block_clouds received an empty provider list: an empty "
                "list blocks nothing on this route (call @block_clouds() to "
                "block every provider)."
            )
        if unknown:
            self._report_misconfiguration(
                f"@block_clouds: ignored unknown cloud providers {unknown}. "
                f"Valid providers: {sorted(VALID_CLOUD_PROVIDERS)} (matched "
                "case-insensitively)."
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
                )
            return self._apply_route_config(func)

        return decorator
