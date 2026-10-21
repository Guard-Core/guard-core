import time
from typing import Any

from guard_core.sync._utils.detection_scan import _first_blocked_user_agent_pattern
from guard_core.sync.handlers._dynamic_rule_attribution import RuleAttribution

_applied: RuleAttribution | None = None


def set_attribution_view(view: RuleAttribution | None) -> None:
    """The dynamic rule manager hands over the view of the applied set (or None)
    whenever it changes, so a request reads it without a lookup."""
    global _applied
    _applied = view


def _applied_attribution() -> RuleAttribution | None:
    return _applied


def cached_ban_stamp(client_ip: str, bans: Any) -> dict[str, Any] | None:
    """The stamp kept for a banned address, ``{}`` when no rule set is applied,
    ``None`` when it has to be worked out (``ban_attribution``)."""
    view = _applied
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


def ban_attribution(client_ip: str, bans: Any) -> dict[str, Any]:
    view = _applied
    return view.for_ban(client_ip, bans) if view else {}


def country_attribution(
    country_rule: str | None, country: str | None
) -> dict[str, Any]:
    view = _applied
    return view.for_country(country_rule, country) if view else {}


def cloud_provider_attribution(
    provider: str | None, region: str | None
) -> dict[str, Any]:
    view = _applied
    return view.for_cloud_provider(provider, region) if view and provider else {}


def user_agent_attribution(user_agent: str, patterns: list[str]) -> dict[str, Any]:
    view = _applied
    if view is None:
        return {}
    pattern = _first_blocked_user_agent_pattern(user_agent, patterns)
    return view.for_user_agent_pattern(pattern)


def rate_limit_attribution(kind: str, bucket: str) -> dict[str, Any]:
    view = _applied
    return view.for_rate_limit_tier(kind, bucket) if view else {}


def emergency_attribution() -> dict[str, Any]:
    view = _applied
    return view.for_emergency_mode() if view else {}


def pattern_attribution(source: str | None) -> dict[str, Any]:
    view = _applied
    return view.for_pattern(source) if view else {}
