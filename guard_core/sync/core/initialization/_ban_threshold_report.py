import logging
import math
from collections.abc import Callable, Collection
from typing import TYPE_CHECKING

from guard_core._misconfiguration import report_misconfiguration
from guard_core._parked_records import BAN_THRESHOLD_CONTEXT_RECORD
from guard_core.sync.core.checks.helpers import SUSPICIOUS_COUNT_WINDOW_SECONDS

if TYPE_CHECKING:
    from guard_core.models import SyncSecurityConfig
    from guard_core.sync.decorators.route_config import RouteConfig

_RATE_LIMIT_FEED = "rate_limit"
_CATEGORIES_FED_BEFORE_RATE_LIMITING = frozenset(
    {"ip_list", "country", "cloud", "user_agent", "ip_spoofing"}
)
_ROUTE_SOURCES_FED_BEFORE_RATE_LIMITING = (
    "ip_whitelist",
    "ip_blacklist",
    "blocked_countries",
    "whitelist_countries",
    "blocked_user_agents",
    "block_cloud_providers",
)
_CONFIG_SOURCES_FED_BEFORE_RATE_LIMITING = (
    "whitelist",
    "blacklist",
    "blocked_countries",
    "whitelist_countries",
    "blocked_user_agents",
    "block_cloud_providers",
    "trusted_proxies",
)


class _BanThresholdContext:
    def __init__(
        self,
        route_configs: Callable[[], Collection["RouteConfig"]],
        redis_shared: Callable[[], bool],
    ) -> None:
        self.route_configs = route_configs
        self.redis_shared = redis_shared


def remember_ban_threshold_context(
    route_configs: Callable[[], Collection["RouteConfig"]],
    redis_shared: Callable[[], bool],
    config: "SyncSecurityConfig",
) -> None:
    context = _BanThresholdContext(route_configs, redis_shared)
    object.__setattr__(config, BAN_THRESHOLD_CONTEXT_RECORD, context)


def _redis_outage_lets_requests_past_the_limit(
    config: "SyncSecurityConfig", context: _BanThresholdContext
) -> bool:
    if not context.redis_shared():
        return False
    return config.redis_fail_open or not config.fail_secure


def _strike_bound(config: "SyncSecurityConfig") -> int:
    window = config.rate_limit_window
    return math.ceil(config.rate_limit * (SUSPICIOUS_COUNT_WINDOW_SECONDS / window + 1))


def _bound_is_unknown(
    config: "SyncSecurityConfig", context: _BanThresholdContext
) -> bool:
    if not config.enable_rate_limiting or config.passive_mode:
        return True
    if config.rate_limit < 1 or config.rate_limit_window < 1 or config.exempt_ips:
        return True
    if _redis_outage_lets_requests_past_the_limit(config, context):
        return True
    return any(
        "rate_limit" in route.bypassed_checks or "all" in route.bypassed_checks
        for route in context.route_configs()
    )


def _fed_before_rate_limiting(
    config: "SyncSecurityConfig", context: _BanThresholdContext
) -> bool:
    if not config.ban_on_hostile_signals:
        return False
    if any(getattr(config, name) for name in _CONFIG_SOURCES_FED_BEFORE_RATE_LIMITING):
        return True
    return any(
        getattr(route, name)
        for route in context.route_configs()
        for name in _ROUTE_SOURCES_FED_BEFORE_RATE_LIMITING
    )


def _excluded_paths_reach_detection(config: "SyncSecurityConfig") -> bool:
    from guard_core.sync.core.checks.implementations.rate_limit import RateLimitCheck
    from guard_core.sync.core.checks.implementations.suspicious_activity import (
        SuspiciousActivityCheck,
    )

    return bool(
        (config.exclude_paths or config.exclude_all_paths)
        and SuspiciousActivityCheck.enforced_on_excluded_paths
        and not RateLimitCheck.enforced_on_excluded_paths
    )


def unreachable_ban_threshold_problems(
    config: "SyncSecurityConfig", context: _BanThresholdContext
) -> list[str]:
    if _bound_is_unknown(config, context) or _excluded_paths_reach_detection(config):
        return []
    bound = _strike_bound(config)
    fed_early = _fed_before_rate_limiting(config, context)
    thresholds = {} if fed_early else {"auto_ban_threshold": config.auto_ban_threshold}
    thresholds.update(
        {
            f"threat_ban_config['{category}']": entry.threshold
            for category, entry in config.threat_ban_config.items()
            if category != _RATE_LIMIT_FEED
            and not (fed_early and category in _CATEGORIES_FED_BEFORE_RATE_LIMITING)
        }
    )
    return [
        f"{field} is {value}, above the {bound:,} strikes one client can produce "
        f"in {SUSPICIOUS_COUNT_WINDOW_SECONDS} s with rate_limit="
        f"{config.rate_limit} per {config.rate_limit_window} s (rate_limit x "
        f"({SUSPICIOUS_COUNT_WINDOW_SECONDS} / rate_limit_window + 1)), so this "
        f"ban threshold can never fire. Lower it to at most {bound:,} or raise "
        f"rate_limit."
        for field, value in thresholds.items()
        if value > bound
    ]


def report_unreachable_ban_thresholds(
    config: "SyncSecurityConfig",
    context: _BanThresholdContext,
    logger: logging.Logger,
    stacklevel: int,
) -> None:
    for problem in unreachable_ban_threshold_problems(config, context):
        report_misconfiguration(config, problem, logger=logger, stacklevel=stacklevel)


def log_unreachable_ban_thresholds_after_rule_change(
    config: "SyncSecurityConfig", logger: logging.Logger
) -> None:
    context = getattr(config, BAN_THRESHOLD_CONTEXT_RECORD, None)
    if context is None:
        return
    for problem in unreachable_ban_threshold_problems(config, context):
        logger.warning("Dynamic rule: %s", problem)
