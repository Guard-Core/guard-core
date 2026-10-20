from typing import Any

from guard_core.sync._utils.detection_scan import _first_blocked_user_agent_pattern
from guard_core.sync.handlers._dynamic_rule_attribution import RuleAttribution


def _applied_attribution() -> RuleAttribution | None:
    from guard_core.sync.handlers.dynamic_rule_handler import DynamicRuleManager

    manager = getattr(DynamicRuleManager, "_instance", None)
    if manager is None:
        return None
    view: RuleAttribution | None = manager.rule_attribution()
    return view


def ban_attribution(client_ip: str) -> dict[str, Any]:
    view = _applied_attribution()
    return view.for_ban(client_ip) if view else {}


def country_attribution(
    country_rule: str | None, country: str | None
) -> dict[str, Any]:
    view = _applied_attribution()
    return view.for_country(country_rule, country) if view else {}


def cloud_provider_attribution(provider: str | None) -> dict[str, Any]:
    view = _applied_attribution()
    return view.for_cloud_provider(provider) if view and provider else {}


def user_agent_attribution(user_agent: str, patterns: list[str]) -> dict[str, Any]:
    view = _applied_attribution()
    if view is None:
        return {}
    pattern = _first_blocked_user_agent_pattern(user_agent, patterns)
    return view.for_user_agent_pattern(pattern)


def rate_limit_attribution(kind: str, bucket: str) -> dict[str, Any]:
    view = _applied_attribution()
    return view.for_rate_limit_tier(kind, bucket) if view else {}


def emergency_attribution() -> dict[str, Any]:
    view = _applied_attribution()
    return view.for_emergency_mode() if view else {}


def pattern_attribution(source: str | None) -> dict[str, Any]:
    view = _applied_attribution()
    return view.for_pattern(source) if view else {}
