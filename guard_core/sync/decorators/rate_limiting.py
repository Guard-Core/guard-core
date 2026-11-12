from collections.abc import Callable

from guard_core._misconfiguration_kinds import (
    K_DECORATOR_RATE_LIMIT_BELOW_ONE,
    K_GEO_RATE_LIMIT_BELOW_ONE,
    Problem,
)
from guard_core.sync.decorators.base import (
    BaseSecurityMixin,
    GuardedParams,
    GuardedReturn,
)


class RateLimitingMixin(BaseSecurityMixin):
    def rate_limit(
        self, requests: int, window: int = 60
    ) -> Callable[
        [Callable[GuardedParams, GuardedReturn]], Callable[GuardedParams, GuardedReturn]
    ]:
        def decorator(
            func: Callable[GuardedParams, GuardedReturn],
        ) -> Callable[GuardedParams, GuardedReturn]:
            if requests < 1 or window < 1:
                self._report_misconfiguration(
                    Problem(
                        f"@rate_limit(requests={requests}, window={window}): the "
                        "limit and the window must both be at least 1.",
                        kind=K_DECORATOR_RATE_LIMIT_BELOW_ONE,
                    )
                )
            route_config = self._ensure_route_config(func)
            route_config.rate_limit = requests
            route_config.rate_limit_window = window
            return self._apply_route_config(func)

        return decorator

    def geo_rate_limit(
        self, limits: dict[str, tuple[int, int]]
    ) -> Callable[
        [Callable[GuardedParams, GuardedReturn]], Callable[GuardedParams, GuardedReturn]
    ]:
        def decorator(
            func: Callable[GuardedParams, GuardedReturn],
        ) -> Callable[GuardedParams, GuardedReturn]:
            self._report_misconfigurations(
                [
                    Problem(
                        f"@geo_rate_limit entry {country!r} is ({limit}, "
                        f"{window}): the limit and the window must both be at "
                        "least 1.",
                        kind=K_GEO_RATE_LIMIT_BELOW_ONE,
                        subject=str(country),
                    )
                    for country, (limit, window) in limits.items()
                    if limit < 1 or window < 1
                ]
            )
            if limits:
                self._require_geo_source("@geo_rate_limit")
            route_config = self._ensure_route_config(func)
            route_config.geo_rate_limits = {
                country.upper(): entry for country, entry in limits.items()
            }
            return self._apply_route_config(func)

        return decorator
