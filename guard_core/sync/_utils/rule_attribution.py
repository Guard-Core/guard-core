import time
from typing import TYPE_CHECKING

from guard_core.sync._utils.detection_scan import _first_blocked_user_agent_pattern
from guard_core.sync.handlers._dynamic_rule_attribution import RuleAttribution, Stamp
from guard_core.sync.handlers.dynamic_rule_handler import (
    _APP_RULE_MANAGERS,
    DynamicRuleManager,
)

if TYPE_CHECKING:
    from guard_core.sync.handlers.ipban_handler import IPBanManager


def _view_of(config: object) -> RuleAttribution | None:
    """The view of the dynamic rule manager serving the app of ``config``."""
    manager = _APP_RULE_MANAGERS.resolve(config)
    return manager._attribution_view if manager is not None else None


def set_attribution_view(
    view: RuleAttribution | None, config: object | None = None
) -> None:
    """Hand over the view of the applied set (or None) of the app of ``config``,
    of the process default manager without one. The dynamic rule manager keeps it
    on itself whenever the set changes, so a request reads it without a lookup
    beyond the app's manager."""
    manager = (
        _APP_RULE_MANAGERS.resolve(config)
        if config is not None
        else DynamicRuleManager._instance
    )
    if manager is not None:
        manager._attribution_view = view


def cached_ban_stamp(
    config: object, client_ip: str, bans: "IPBanManager"
) -> Stamp | None:
    """The stamp kept for a banned address, ``{}`` when no rule set is applied,
    ``None`` when it has to be worked out (``ban_attribution``)."""
    view = _view_of(config)
    if view is None:
        return {}
    held = view._ban_stamps.get(client_ip)
    if (
        held is not None
        and held[1] == bans._ban_version_seen
        and time.time() - held[2] < bans._VERSION_RECHECK_SECONDS
    ):
        return held[0]
    return None


def ban_attribution(config: object, client_ip: str, bans: "IPBanManager") -> Stamp:
    view = _view_of(config)
    return view.for_ban(client_ip, bans) if view else {}


def country_attribution(
    config: object, country_rule: str | None, country: str | None
) -> Stamp:
    view = _view_of(config)
    return view.for_country(country_rule, country) if view else {}


def cloud_provider_attribution(
    config: object, provider: str | None, region: str | None
) -> Stamp:
    view = _view_of(config)
    return view.for_cloud_provider(provider, region) if view and provider else {}


def user_agent_attribution(
    config: object, user_agent: str, patterns: list[str]
) -> Stamp:
    view = _view_of(config)
    if view is None:
        return {}
    pattern = _first_blocked_user_agent_pattern(user_agent, patterns)
    return view.for_user_agent_pattern(pattern)


def rate_limit_attribution(config: object, kind: str, bucket: str) -> Stamp:
    view = _view_of(config)
    return view.for_rate_limit_tier(kind, bucket) if view else {}


def emergency_attribution(config: object) -> Stamp:
    view = _view_of(config)
    return view.for_emergency_mode() if view else {}


def pattern_attribution(config: object, source: str | None) -> Stamp:
    view = _view_of(config)
    return view.for_pattern(source) if view else {}
