import logging
import weakref
from typing import TYPE_CHECKING

from guard_core._geo_handler_for_tree import (
    build_geo_ip_handler_from_token,
    routes_need_geo_ip_handler,
)
from guard_core._redis_enablement import redis_is_configured
from guard_core.sync.core.initialization._ban_threshold_report import (
    _BanThresholdContext,
    remember_ban_threshold_context,
    report_unreachable_ban_thresholds,
)
from guard_core.sync.core.initialization._country_decorator_report import (
    report_country_decorators_without_geoip,
)
from guard_core.sync.core.initialization._route_limit_report import (
    report_route_limits_with_global_switch_off,
)

if TYPE_CHECKING:
    from guard_core.models import SyncSecurityConfig
    from guard_core.sync.decorators.base import BaseSecurityDecorator, RouteConfig
    from guard_core.sync.protocols.geo_ip_protocol import SyncGeoIPHandler
    from guard_core.sync.protocols.redis_protocol import SyncRedisHandlerProtocol


class RouteMisconfigurationReportsMixin:
    config: "SyncSecurityConfig"
    redis_handler: "SyncRedisHandlerProtocol | None" = None
    geo_ip_handler: "SyncGeoIPHandler | SyncGeoIPHandler | None" = None
    guard_decorator: "BaseSecurityDecorator | None" = None
    logger: logging.Logger
    _adapter: str | None = None
    _geo_handler_is_ours: bool = False
    _route_misconfigurations_reported: tuple[int, int | None, int] | None = None

    def _report_unreachable_ban_thresholds(
        self, candidate: "BaseSecurityDecorator | None" = None
    ) -> None:
        # The context is parked on this app's config, which this initializer owns, so
        # it reads the app through a weak reference and holds no cycle.
        app = weakref.ref(self)

        def route_configs() -> tuple["RouteConfig", ...]:
            live = app()
            decorator = None if live is None else live.guard_decorator
            return tuple(getattr(decorator, "_route_configs", {}).values())

        def redis_shared() -> bool:
            live = app()
            return live is not None and bool(
                redis_is_configured(live.config) and live.redis_handler
            )

        remember_ban_threshold_context(route_configs, redis_shared, self.config)

        def candidate_routes() -> tuple["RouteConfig", ...]:
            return tuple(getattr(candidate, "_route_configs", {}).values())

        reported_routes = route_configs if candidate is None else candidate_routes
        report_unreachable_ban_thresholds(
            self.config,
            _BanThresholdContext(reported_routes, redis_shared),
            self.logger,
            stacklevel=6,
        )

    def _route_rules_need_geo_ip_handler(
        self, decorator: "BaseSecurityDecorator | None"
    ) -> bool:
        if self.geo_ip_handler is not None or not self.config.ipinfo_token:
            return False
        route_configs = getattr(decorator, "_route_configs", {})
        return routes_need_geo_ip_handler(route_configs.values())

    def _require_what_the_geo_handler_for_route_rules_needs(
        self, decorator: "BaseSecurityDecorator | None"
    ) -> None:
        if not self._route_rules_need_geo_ip_handler(decorator):
            return
        from guard_core._config_capabilities import require_geo_extra
        from guard_core.sync.handlers._downloader import require_downloader_installed

        require_downloader_installed(
            "geo", "The built-in GeoIP database download", self._adapter
        )
        require_geo_extra()

    def _build_geo_ip_handler_for_route_rules(
        self, decorator: "BaseSecurityDecorator | None"
    ) -> None:
        if not self._route_rules_need_geo_ip_handler(decorator):
            return
        from guard_core.sync.handlers._downloader import TREE_DOWNLOADER

        self._require_what_the_geo_handler_for_route_rules_needs(decorator)
        self.geo_ip_handler = build_geo_ip_handler_from_token(
            self.config, tree_awaits=TREE_DOWNLOADER == "aiohttp"
        )
        self._geo_handler_is_ours = True

    def _report_country_decorators_without_geoip(
        self, decorator: "BaseSecurityDecorator | None"
    ) -> None:
        report_country_decorators_without_geoip(
            self.config, decorator, self.geo_ip_handler, self.logger
        )

    def _report_route_limits_with_global_switch_off(
        self, decorator: "BaseSecurityDecorator | None"
    ) -> None:
        report_route_limits_with_global_switch_off(self.config, decorator, self.logger)

    def report_route_misconfigurations(
        self, candidate: "BaseSecurityDecorator | None" = None
    ) -> None:
        """Report the route misconfigurations of the bound decorator, or of a
        ``candidate`` not bound yet (then the geo handler is left to the caller,
        who builds it once the candidate is bound)."""
        decorator = self.guard_decorator if candidate is None else candidate
        reported = (
            id(decorator),
            getattr(decorator, "route_config_revision", None),
            id(self.redis_handler),
        )
        if self._route_misconfigurations_reported == reported:
            return
        if candidate is None:
            self._build_geo_ip_handler_for_route_rules(decorator)
        self._report_unreachable_ban_thresholds(candidate)
        self._report_country_decorators_without_geoip(decorator)
        self._report_route_limits_with_global_switch_off(decorator)
        self._route_misconfigurations_reported = reported
