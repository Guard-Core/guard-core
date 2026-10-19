from collections.abc import Collection, Mapping
from typing import TYPE_CHECKING, Any

from guard_core.core.checks._strike_counts import (
    _RATE_LIMIT_FEED_CATEGORY,
)
from guard_core.models import SecurityConfig, ThreatBanConfig

if TYPE_CHECKING:
    pass


def _flat_threshold_total(
    ip_counts: Mapping[str, int], threat_categories: Collection[str]
) -> int:
    rate_limit_feed = _RATE_LIMIT_FEED_CATEGORY in threat_categories
    request_total = getattr(ip_counts, "request_total", None)
    if request_total is not None and not rate_limit_feed:
        return int(request_total)
    return sum(
        count
        for category, count in ip_counts.items()
        if (category == "rate_limit") == rate_limit_feed
    )


def _flat_total_or_shared(
    shared_total: int | None,
    ip_counts: Mapping[str, int],
    threat_categories: Collection[str],
) -> int:
    if shared_total is not None:
        return shared_total
    return _flat_threshold_total(ip_counts, threat_categories)


async def _resolve_and_apply_threshold_ban(
    ip_counts: Mapping[str, int],
    config: SecurityConfig,
    ip_ban_manager: Any,
    client_ip: str,
    threat_categories: Collection[str],
    reason: str,
    default_entries: Mapping[str, ThreatBanConfig] | None = None,
    flat_total: int | None = None,
) -> tuple[int, str, str | None] | None:
    """Pure threshold resolution against ``ip_counts`` plus the ``ban_ip`` call.

    A ban fires when a matched category's ``threat_ban_config`` entry (or its
    ``default_entries`` entry) has crossed its own threshold; the duration is the
    longest among the crossed entries and a tie goes to the earlier category in
    ``threat_categories``. The flat ``auto_ban_threshold``/``auto_ban_duration`` rule
    counts requests (one strike per request) on the same side of the ``rate_limit``
    line: a rate-limit feed counts only ``rate_limit`` violations and every other
    feed everything except them. It joins the longest only when its total exceeds
    the chosen entry's own count, and the entry wins a duration tie. With no entry
    crossed the flat rule alone decides. Returns
    ``(applied duration, ban_reason, category)`` when a ban was applied
    (``category`` is ``None`` for the flat rule), or ``None`` when banning is
    disabled, nothing crossed, or the ban was refused
    (self-DoS guard). Callers own their own logging: the middleware path logs via
    ``log_activity``, the request-free ``check_rate_limit_by_ip`` primitive logs via
    the module logger.
    """
    if not config.enable_ip_banning:
        return None
    chosen = _longest_crossed_entry(
        ip_counts, config, threat_categories, default_entries
    )
    total = _flat_total_or_shared(flat_total, ip_counts, threat_categories)
    choice = _threshold_ban_choice(chosen, total, ip_counts, config, reason)
    if choice is None:
        return None
    duration, ban_reason, category = choice
    applied = await ip_ban_manager._ban_ip_escalating(
        client_ip, duration, ban_reason, grouped="/" in client_ip
    )
    return None if applied is None else (applied, ban_reason, category)


def _threshold_ban_choice(
    chosen: tuple[str, ThreatBanConfig] | None,
    total: int,
    ip_counts: Mapping[str, int],
    config: SecurityConfig,
    reason: str,
) -> tuple[int, str, str | None] | None:
    flat_crossed = total >= config.auto_ban_threshold
    if chosen is None:
        return (config.auto_ban_duration, reason, None) if flat_crossed else None
    category, entry = chosen
    flat_joins = flat_crossed and total > ip_counts.get(category, 0)
    if flat_joins and entry.duration < config.auto_ban_duration:
        return config.auto_ban_duration, reason, None
    return entry.duration, f"{reason}:{category}", category


def _entry_for(
    config: SecurityConfig,
    category: str,
    default_entries: Mapping[str, ThreatBanConfig] | None,
) -> ThreatBanConfig | None:
    entry = config.threat_ban_config.get(category)
    if entry is None and default_entries:
        return default_entries.get(category)
    return entry


def _longest_crossed_entry(
    ip_counts: Mapping[str, int],
    config: SecurityConfig,
    threat_categories: Collection[str],
    default_entries: Mapping[str, ThreatBanConfig] | None,
) -> tuple[str, ThreatBanConfig] | None:
    chosen: tuple[str, ThreatBanConfig] | None = None
    for category in threat_categories:
        entry = _entry_for(config, category, default_entries)
        if entry is None or ip_counts.get(category, 0) < entry.threshold:
            continue
        if chosen is None or entry.duration > chosen[1].duration:
            chosen = (category, entry)
    return chosen


def _strike_total(ip_counts: Mapping[str, int]) -> int:
    request_total = getattr(ip_counts, "request_total", None)
    return sum(ip_counts.values()) if request_total is None else int(request_total)
