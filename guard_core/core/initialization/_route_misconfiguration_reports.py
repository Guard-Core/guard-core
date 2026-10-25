import logging
from typing import TYPE_CHECKING, Any

from guard_core._geo_handler_for_tree import (
    build_geo_ip_handler_from_token,
    routes_need_geo_ip_handler,
)
from guard_core._redis_enablement import redis_is_configured
from guard_core.core.initialization._ban_threshold_report import (
    _BanThresholdContext,
    remember_ban_threshold_context,
    report_unreachable_ban_thresholds,
)
from guard_core.core.initialization._country_decorator_report import (
    report_country_decorators_without_geoip,
)
from guard_core.core.initialization._route_limit_report import (
    report_route_limits_with_global_switch_off,
)

if TYPE_CHECKING:
    from guard_core.models import SecurityConfig


class RouteMisconfigurationReportsMixin:
    config: "SecurityConfig"
    redis_handler: Any = None
    geo_ip_handler: Any = None
    guard_decorator: Any = None
    logger: logging.Logger
    _adapter: str | None = None
    _geo_handler_is_ours: bool = False
    _route_misconfigurations_reported: tuple[int, int | None] | None = None

    def _report_unreachable_ban_thresholds(self) -> None:
        context = _BanThresholdContext(
            lambda: tuple(getattr(self.guard_decorator, "_route_configs", {}).values()),
            lambda: bool(redis_is_configured(self.config) and self.redis_handler),
        )
        remember_ban_threshold_context(context.route_configs, context.redis_shared)
        report_unreachable_ban_thresholds(
            self.config, context, self.logger, stacklevel=6
        )

    def _build_geo_ip_handler_for_route_rules(self) -> None:
        if self.geo_ip_handler is not None or not self.config.ipinfo_token:
            return
        route_configs = getattr(self.guard_decorator, "_route_configs", {})
        if not routes_need_geo_ip_handler(route_configs.values()):
            return
        from guard_core.handlers._downloader import (
            TREE_DOWNLOADER,
            require_downloader_installed,
        )

        require_downloader_installed(
            "geo", "The built-in GeoIP database download", self._adapter
        )
        self.geo_ip_handler = build_geo_ip_handler_from_token(
            self.config, tree_awaits=TREE_DOWNLOADER == "aiohttp"
        )
        self._geo_handler_is_ours = True

    def _report_country_decorators_without_geoip(self) -> None:
        report_country_decorators_without_geoip(
            self.config, self.guard_decorator, self.geo_ip_handler, self.logger
        )

    def _report_route_limits_with_global_switch_off(self) -> None:
        report_route_limits_with_global_switch_off(
            self.config, self.guard_decorator, self.logger
        )

    def report_route_misconfigurations(self) -> None:
        decorator = self.guard_decorator
        reported = (id(decorator), getattr(decorator, "route_config_revision", None))
        if self._route_misconfigurations_reported == reported:
            return
        self._build_geo_ip_handler_for_route_rules()
        self._report_unreachable_ban_thresholds()
        self._report_country_decorators_without_geoip()
        self._report_route_limits_with_global_switch_off()
        self._route_misconfigurations_reported = reported
