import time
from typing import TYPE_CHECKING

from guard_core._utils.detection_scan import _first_blocked_user_agent_pattern
from guard_core.handlers._dynamic_rule_attribution import RuleAttribution, Stamp

if TYPE_CHECKING:
    from guard_core.handlers.ipban_handler import IPBanManager

_applied: RuleAttribution | None = None


def set_attribution_view(view: RuleAttribution | None) -> None:
    """The dynamic rule manager hands over the view of the applied set (or None)
    whenever it changes, so a request reads it without a lookup."""
    global _applied
    _applied = view


def cached_ban_stamp(client_ip: str, bans: "IPBanManager") -> Stamp | None:
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


async def ban_attribution(client_ip: str, bans: "IPBanManager") -> Stamp:
    view = _applied
    return await view.for_ban(client_ip, bans) if view else {}


def country_attribution(country_rule: str | None, country: str | None) -> Stamp:
    view = _applied
    return view.for_country(country_rule, country) if view else {}


def cloud_provider_attribution(provider: str | None, region: str | None) -> Stamp:
    view = _applied
    return view.for_cloud_provider(provider, region) if view and provider else {}


async def user_agent_attribution(user_agent: str, patterns: list[str]) -> Stamp:
    view = _applied
    if view is None:
        return {}
    pattern = await _first_blocked_user_agent_pattern(user_agent, patterns)
    return view.for_user_agent_pattern(pattern)


def rate_limit_attribution(kind: str, bucket: str) -> Stamp:
    view = _applied
    return view.for_rate_limit_tier(kind, bucket) if view else {}


def emergency_attribution() -> Stamp:
    view = _applied
    return view.for_emergency_mode() if view else {}


def pattern_attribution(source: str | None) -> Stamp:
    view = _applied
    return view.for_pattern(source) if view else {}
