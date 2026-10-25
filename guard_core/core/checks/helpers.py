import logging
import time as time  # the strike-window tests patch the clock through this module
import weakref
from collections.abc import Callable, Collection, Mapping
from ipaddress import ip_address
from typing import TYPE_CHECKING, Any, cast
from urllib.parse import urlparse

from guard_core._tracking_caps import (
    _MAX_TRACKED_SUSPICIOUS_IPS as _MAX_TRACKED_SUSPICIOUS_IPS,
)
from guard_core._utils.access_control import load_geo_database_for_route_rules
from guard_core.core.checks._shared_strikes import (
    SharedStrikes,
    StrikeReport,
    forget_shared_detection_strikes,
    record_shared_detection_strikes,
    strike_categories,
)
from guard_core.core.checks._strike_counts import (
    _RATE_LIMIT_FEED_CATEGORY as _RATE_LIMIT_FEED_CATEGORY,
)
from guard_core.core.checks._strike_counts import (
    _forget_suspicious_counts as _forget_suspicious_counts,
)
from guard_core.core.checks._strike_counts import (
    _ip_strike_counts as _ip_strike_counts,
)
from guard_core.core.checks._strike_counts import (
    _strike_identity as _strike_identity,
)
from guard_core.core.checks._strike_counts import (
    _suspicious_counts_lock as _suspicious_counts_lock,
)
from guard_core.core.checks._strike_counts import (
    _WindowedCategoryCounts as _WindowedCategoryCounts,
)
from guard_core.core.checks._strike_forget import register_strike_middleware
from guard_core.core.checks._threshold_ban import (
    _flat_threshold_total as _flat_threshold_total,
)
from guard_core.core.checks._threshold_ban import (
    _flat_total_or_shared as _flat_total_or_shared,
)
from guard_core.core.checks._threshold_ban import (
    _longest_crossed_entry as _longest_crossed_entry,
)
from guard_core.core.checks._threshold_ban import (
    _resolve_and_apply_threshold_ban as _resolve_and_apply_threshold_ban,
)
from guard_core.core.checks._threshold_ban import (
    _strike_total as _strike_total,
)
from guard_core.core.events.event_types import (
    EVENT_IP_BAN_FAILED,
    EVENT_PENETRATION_ATTEMPT,
)
from guard_core.decorators.base import BaseSecurityDecorator, RouteConfig
from guard_core.detection_result import DetectionResult
from guard_core.models import SecurityConfig, ThreatBanConfig
from guard_core.protocols.request_protocol import GuardRequest
from guard_core.utils import (
    UNKNOWN_CLIENT_IDENTITY,
    _ip_in_list,
    _user_agent_matches_blocked_pattern,
    detect_penetration_attempt,
    log_activity,
)

if TYPE_CHECKING:
    from guard_core.core.checks.base import SecurityCheck
    from guard_core.protocols.middleware_protocol import GuardMiddlewareProtocol

SUSPICIOUS_COUNT_WINDOW_SECONDS = 3600
_DETECTION_RESULT_STATE_ATTR = "_guard_detection_result_cache"
_MAX_RETAINED_EVENTS_PER_CATEGORY = 10_000
_strike_cap_cache: dict[int, tuple[weakref.ref[SecurityConfig], int, int]] = {}


def _strike_cap_forgetter(key: int) -> Callable[[Any], None]:
    def forget(_ref: Any) -> None:
        _strike_cap_cache.pop(key, None)

    return forget


def _retained_strike_cap(config: SecurityConfig) -> int:
    key = id(config)
    revision = config.revision
    cached = _strike_cap_cache.get(key)
    if cached is not None and cached[0]() is config and cached[1] == revision:
        return cached[2]
    cap = max(
        _MAX_RETAINED_EVENTS_PER_CATEGORY,
        config.auto_ban_threshold,
        *(entry.threshold for entry in config.threat_ban_config.values()),
    )
    _strike_cap_cache[key] = (
        weakref.ref(config, _strike_cap_forgetter(key)),
        revision,
        cap,
    )
    return cap


def _increment_suspicious_counts(
    middleware: "GuardMiddlewareProtocol",
    client_ip: str,
    categories: str | Collection[str],
) -> None:
    resolved_categories = strike_categories(categories)
    strike_key = _strike_identity(middleware.config, client_ip)
    now = time.monotonic()
    retain = _retained_strike_cap(middleware.config)
    register_strike_middleware(middleware)
    with _suspicious_counts_lock:
        counts = middleware.suspicious_request_counts
        existing = counts.pop(strike_key, None)
        if existing is None:
            if len(counts) >= middleware.config.ban_counters_max_tracked_ips:
                oldest_ip = next(iter(counts))
                del counts[oldest_ip]
            ip_counts = _WindowedCategoryCounts()
        elif isinstance(existing, _WindowedCategoryCounts):
            ip_counts = existing
        else:
            ip_counts = _WindowedCategoryCounts.adopting(existing, now, retain)
        ip_counts.expire_before(now - SUSPICIOUS_COUNT_WINDOW_SECONDS)
        for category in resolved_categories:
            ip_counts.record(category, now, retain)
        if any(
            category != _RATE_LIMIT_FEED_CATEGORY for category in resolved_categories
        ):
            ip_counts.record_request(now, retain)
        counts[strike_key] = ip_counts


def get_guard_decorator(middleware: Any, request: GuardRequest) -> Any:
    resolver = getattr(middleware, "route_resolver", None)
    context = getattr(resolver, "context", None)
    guard_decorator = getattr(context, "guard_decorator", None)
    if not isinstance(guard_decorator, BaseSecurityDecorator):
        guard_decorator = getattr(request.state, "guard_decorator", None)
    return (
        guard_decorator if isinstance(guard_decorator, BaseSecurityDecorator) else None
    )


def _decorator_action_taken(passive_mode: bool) -> str:
    return "logged_only" if passive_mode else "blocked"


async def emit_access_denied_event(
    middleware: Any,
    request: GuardRequest,
    *,
    event_type: str,
    reason: str,
    decorator_type: str,
    passive_mode: bool,
    **metadata: Any,
) -> None:
    guard_decorator = get_guard_decorator(middleware, request)
    if guard_decorator is not None:
        await guard_decorator.send_access_denied_event(
            request,
            reason=reason,
            decorator_type=decorator_type,
            action_taken=_decorator_action_taken(passive_mode),
            **metadata,
        )
        return
    await middleware.event_bus.send_middleware_event(
        event_type=event_type,
        request=request,
        action_taken="request_blocked" if not passive_mode else "logged_only",
        reason=reason,
        decorator_type=decorator_type,
        **metadata,
    )


async def emit_authentication_failed_event(
    middleware: Any,
    request: GuardRequest,
    *,
    event_type: str,
    reason: str,
    auth_type: str,
    violation_type: str,
    passive_mode: bool,
    **metadata: Any,
) -> None:
    guard_decorator = get_guard_decorator(middleware, request)
    if guard_decorator is not None:
        await guard_decorator.send_authentication_failed_event(
            request,
            reason=reason,
            auth_type=auth_type,
            action_taken=_decorator_action_taken(passive_mode),
            violation_type=violation_type,
            **metadata,
        )
        return
    await middleware.event_bus.send_middleware_event(
        event_type=event_type,
        request=request,
        action_taken="request_blocked" if not passive_mode else "logged_only",
        reason=reason,
        decorator_type="authentication",
        violation_type=violation_type,
        auth_type=auth_type,
        **metadata,
    )


async def emit_rate_limit_event(
    middleware: Any,
    request: GuardRequest,
    *,
    event_type: str,
    limit: int,
    window: int,
    reason: str,
    passive_mode: bool,
) -> None:
    guard_decorator = get_guard_decorator(middleware, request)
    if guard_decorator is not None:
        await guard_decorator.send_rate_limit_event(
            request, limit, window, action_taken=_decorator_action_taken(passive_mode)
        )
        return
    await middleware.event_bus.send_middleware_event(
        event_type=event_type,
        request=request,
        action_taken="request_blocked" if not passive_mode else "logged_only",
        reason=reason,
        decorator_type="rate_limiting",
        violation_type="rate_limit",
        rate_limit=limit,
        window=window,
    )


async def emit_decorator_event(
    middleware: Any,
    request: GuardRequest,
    *,
    event_type: str,
    action_taken: str,
    reason: str,
    decorator_type: str,
    **metadata: Any,
) -> None:
    guard_decorator = get_guard_decorator(middleware, request)
    if guard_decorator is not None:
        await guard_decorator.send_decorator_event(
            event_type=event_type,
            request=request,
            action_taken=action_taken,
            reason=reason,
            decorator_type=decorator_type,
            **metadata,
        )
        return
    await middleware.event_bus.send_middleware_event(
        event_type=event_type,
        request=request,
        action_taken=action_taken,
        reason=reason,
        decorator_type=decorator_type,
        **metadata,
    )


def route_config_applies(
    route_configs: Collection[RouteConfig] | None,
    predicate: Callable[[RouteConfig], bool],
) -> bool:
    if route_configs is None:
        return True
    for route_config in route_configs:
        if predicate(route_config):
            return True
    return False


def is_ip_in_blacklist(client_ip: str, ip_addr: object, blacklist: list[str]) -> bool:
    return _ip_in_list(ip_addr, client_ip, blacklist)


def is_ip_in_whitelist(
    client_ip: str, ip_addr: object, whitelist: list[str]
) -> bool | None:
    if not whitelist:
        return None
    return _ip_in_list(ip_addr, client_ip, whitelist)


def check_country_access(
    client_ip: str, route_config: RouteConfig, geo_ip_handler: Any
) -> bool | None:
    if not geo_ip_handler:
        return None

    country = None

    if route_config.blocked_countries:
        country = geo_ip_handler.get_country(client_ip)
        if country and country in route_config.blocked_countries:
            return False

    if route_config.whitelist_countries:
        if country is None:
            country = geo_ip_handler.get_country(client_ip)

        if country:
            return country in route_config.whitelist_countries
        return False

    return None


def _check_ip_blacklist(
    client_ip: str, ip_addr: object, route_config: RouteConfig
) -> bool:
    if not route_config.ip_blacklist:
        return False
    return is_ip_in_blacklist(client_ip, ip_addr, route_config.ip_blacklist)


def _check_ip_whitelist(
    client_ip: str, ip_addr: object, route_config: RouteConfig
) -> bool | None:
    return is_ip_in_whitelist(client_ip, ip_addr, route_config.ip_whitelist or [])


def _route_whitelist_configured(route_config: RouteConfig) -> bool:
    return bool(route_config.ip_whitelist or route_config.whitelist_countries)


async def check_route_ip_access(
    client_ip: str, route_config: RouteConfig, middleware: Any
) -> bool | None:
    if client_ip == UNKNOWN_CLIENT_IDENTITY:
        return False if _route_whitelist_configured(route_config) else None

    try:
        ip_addr = ip_address(client_ip)

        await load_geo_database_for_route_rules(route_config, middleware)
        ip_result = _check_ip_whitelist(client_ip, ip_addr, route_config)
        if ip_result is None and _check_ip_blacklist(client_ip, ip_addr, route_config):
            ip_result = False

        country_result = check_country_access(
            client_ip, route_config, middleware.geo_ip_handler
        )

        if ip_result is False or country_result is False:
            return False
        if ip_result is True or country_result is True:
            return True
        return None
    except ValueError:
        return False


async def check_user_agent_allowed(
    user_agent: str, route_config: RouteConfig | None, config: Any
) -> bool:
    from guard_core.utils import is_user_agent_allowed as global_user_agent_check

    if route_config and route_config.blocked_user_agents:
        if await _user_agent_matches_blocked_pattern(
            user_agent, route_config.blocked_user_agents
        ):
            return False

    return await global_user_agent_check(user_agent, config)


_SCHEME_FAILURES = {
    "bearer": "Missing or invalid Bearer token",
    "basic": "Missing or invalid Basic authentication",
}


def extract_credential(auth_header: str, auth_type: str) -> tuple[str | None, str]:
    failure = _SCHEME_FAILURES.get(auth_type, f"Missing {auth_type} authentication")
    if auth_type not in _SCHEME_FAILURES:
        return (auth_header, "") if auth_header else (None, failure)
    prefix = f"{auth_type} "
    if auth_header[: len(prefix)].lower() != prefix:
        return None, failure
    credential = auth_header[len(prefix) :].strip()
    return (credential, "") if credential else (None, failure)


def _normalize_allowed_referrer_domain(entry: str) -> str:
    if "://" in entry:
        return urlparse(entry).netloc.lower()
    normalized = entry.lower()
    slash_index = normalized.find("/")
    return normalized[:slash_index] if slash_index != -1 else normalized


def _referrer_matches_allowed_entry(
    host: str, netloc: str, normalized_allowed: str
) -> bool:
    subject = netloc if ":" in normalized_allowed else host
    return subject == normalized_allowed or subject.endswith(f".{normalized_allowed}")


def is_referrer_domain_allowed(referrer: str, allowed_domains: list[str]) -> bool:
    try:
        parts = urlparse(referrer)
        host = parts.hostname
        if host is None or "\\" in parts.netloc or (parts.port or 0) < 0:
            return False
        netloc = parts.netloc.lower()
        return any(
            _referrer_matches_allowed_entry(
                host, netloc, _normalize_allowed_referrer_domain(allowed)
            )
            for allowed in allowed_domains
        )
    except Exception:
        return False


def _get_effective_penetration_setting(
    config: SecurityConfig, route_config: RouteConfig | None
) -> tuple[bool, bool | None]:
    route_specific_detection = None
    penetration_enabled = config.enable_penetration_detection

    if (
        route_config
        and hasattr(route_config, "enable_suspicious_detection")
        and getattr(route_config, "_inherits_suspicious_detection", False) is not True
    ):
        route_specific_detection = route_config.enable_suspicious_detection
        penetration_enabled = route_specific_detection

    return penetration_enabled, route_specific_detection


def _get_detection_disabled_reason(
    config: SecurityConfig, route_specific_detection: bool | None
) -> str:
    if route_specific_detection is False and config.enable_penetration_detection:
        return "disabled_by_decorator"
    return "not_enabled"


async def detect_penetration_patterns(
    request: GuardRequest,
    route_config: RouteConfig | None,
    config: SecurityConfig,
    should_bypass_check_fn: Any,
) -> DetectionResult:
    penetration_enabled, route_specific_detection = _get_effective_penetration_setting(
        config, route_config
    )

    if penetration_enabled and not should_bypass_check_fn("penetration", route_config):
        return await detect_penetration_attempt(request, config, route_config)

    reason = _get_detection_disabled_reason(config, route_specific_detection)
    return DetectionResult(is_threat=False, trigger_info=reason)


async def get_cached_detection_result(
    request: GuardRequest,
    route_config: RouteConfig | None,
    config: SecurityConfig,
    should_bypass_check_fn: Any,
) -> DetectionResult:
    cached = getattr(request.state, _DETECTION_RESULT_STATE_ATTR, None)
    if cached is not None and cached[0] is request and cached[1] is route_config:
        return cast(DetectionResult, cached[2])

    result = await detect_penetration_patterns(
        request, route_config, config, should_bypass_check_fn
    )
    setattr(
        request.state, _DETECTION_RESULT_STATE_ATTR, (request, route_config, result)
    )
    return result


async def _try_threshold_ban(
    request: GuardRequest,
    config: SecurityConfig,
    ip_ban_manager: Any,
    middleware: "GuardMiddlewareProtocol",
    client_ip: str,
    trigger_info: str,
    logger: logging.Logger,
    check_name: str,
    muted_check_logs: frozenset[str],
    threat_categories: Collection[str],
    reason: str = "penetration_attempt",
    default_entries: Mapping[str, ThreatBanConfig] | None = None,
    ip_counts: Mapping[str, int] | None = None,
    strikes: StrikeReport | None = None,
) -> bool:
    shared: SharedStrikes | None = None
    strike_key = _strike_identity(config, client_ip)
    if ip_counts is None:
        shared = await record_shared_detection_strikes(
            middleware,
            strike_key,
            threat_categories,
            SUSPICIOUS_COUNT_WINDOW_SECONDS,
            _retained_strike_cap(config),
        )
        ip_counts = (
            shared.counts
            if shared is not None
            else middleware.suspicious_request_counts.get(strike_key, {})
        )
    result = await _resolve_and_apply_threshold_ban(
        ip_ban_manager=ip_ban_manager,
        ip_counts=ip_counts,
        config=config,
        client_ip=strike_key,
        threat_categories=threat_categories,
        reason=reason,
        default_entries=default_entries,
        flat_total=shared.total if shared is not None else None,
    )
    if strikes is not None:
        strikes.record(
            shared,
            result is not None,
            _strike_total(ip_counts),
            None if result is None else result[0],
        )
    if result is None:
        return False
    _forget_suspicious_counts(middleware, client_ip)
    if shared is not None:
        await forget_shared_detection_strikes(middleware, strike_key)
    duration, _, category = result
    log_reason = (
        f"IP banned due to {category} threshold: {client_ip} - {trigger_info}"
        if category is not None
        else f"IP banned due to suspicious activity: {client_ip} - {trigger_info}"
    ) + f" (ban duration {duration}s)"
    await log_activity(
        request,
        logger,
        log_type="suspicious",
        reason=log_reason,
        level=config.log_suspicious_level,
        check_name=check_name,
        muted_check_logs=muted_check_logs,
        on_block=config.on_block,
        sensitive_headers=config.log_sensitive_headers,
        sensitive_params=config.log_sensitive_params,
        sensitive_body_fields=config.log_sensitive_body_fields,
    )
    return True


async def _emit_ban_escalation_failed(
    middleware: "GuardMiddlewareProtocol",
    request: GuardRequest,
    client_ip: str,
    error: Exception,
) -> None:
    await middleware.event_bus.send_middleware_event(
        event_type=EVENT_IP_BAN_FAILED,
        request=request,
        action_taken="ban_not_applied",
        reason=f"Escalation ban failed for {client_ip}: {error}",
        ip_address=client_ip,
    )


def _log_exception_safely(logger: logging.Logger, message: str, *args: Any) -> None:
    try:
        logger.exception(message, *args)
    except Exception:
        logging.getLogger(__name__).exception(message, *args)


async def count_hostile_signal_and_maybe_ban(
    check: "SecurityCheck",
    request: GuardRequest,
    category: str,
    trigger_info: str,
    default_threshold: int | None = None,
) -> bool:
    """Count one hostile failure under ``category`` and ban at the threshold.

    The category threshold is the ``threat_ban_config`` entry when present,
    else ``default_threshold`` (``auto_ban_threshold`` when ``None``) with
    ``auto_ban_duration``. Nothing is counted in passive mode, with banning
    disabled, for an unknown client or for a whitelisted client. A failure while
    counting or banning is logged and reported as an ``ip_ban_failed`` event,
    never raised, so the denial itself still goes out. Returns ``True`` when the
    client was banned.
    """
    config = check.config
    client_ip = getattr(request.state, "client_ip", None)
    if (
        config.passive_mode
        or not config.enable_ip_banning
        or not client_ip
        or getattr(request.state, "is_whitelisted", False)
    ):
        return False
    try:
        _increment_suspicious_counts(check.middleware, client_ip, category)
        return await _try_threshold_ban(
            request,
            config,
            check.ip_ban_manager,
            check.middleware,
            client_ip,
            trigger_info,
            check.logger,
            check.check_name,
            config.muted_check_logs,
            (category,),
            reason=f"{category}_triggered",
            default_entries={
                category: ThreatBanConfig(
                    threshold=default_threshold or config.auto_ban_threshold,
                    duration=config.auto_ban_duration,
                )
            },
        )
    except Exception as exc:
        _log_exception_safely(
            check.logger, "counting hostile signal %s failed", category
        )
        try:
            await _emit_ban_escalation_failed(check.middleware, request, client_ip, exc)
        except Exception:
            _log_exception_safely(
                check.logger, "reporting ban failure for %s failed", category
            )
        return False


async def escalate_identity_violation(
    middleware: "GuardMiddlewareProtocol",
    config: SecurityConfig,
    ip_ban_manager: Any,
    request: GuardRequest,
    client_ip: str,
    logger: logging.Logger,
    check_name: str,
    muted_check_logs: frozenset[str],
    violation_category: str,
    trigger_info: str,
) -> None:
    if not client_ip:
        return

    if getattr(request.state, "is_whitelisted", False):
        return

    try:
        route_config = getattr(request.state, "route_config", None)
        result = await get_cached_detection_result(
            request,
            route_config,
            config,
            middleware.route_resolver.should_bypass_check,
        )
        if not result.is_threat or result.trigger_info == "disabled_by_decorator":
            return

        threat_categories = list(result.threat_categories) or ["uncategorized"]
        _increment_suspicious_counts(middleware, client_ip, threat_categories)

        strikes = StrikeReport()
        banned = await _try_threshold_ban(
            request,
            config,
            ip_ban_manager,
            middleware,
            client_ip,
            trigger_info,
            logger,
            check_name,
            muted_check_logs,
            threat_categories,
            strikes=strikes,
        )

        await middleware.event_bus.send_middleware_event(
            event_type=EVENT_PENETRATION_ATTEMPT,
            request=request,
            action_taken="banned" if banned else "tracked",
            reason=f"Identity violation escalated: {trigger_info}",
            request_count=strikes.count_or(
                lambda: sum(_ip_strike_counts(middleware, client_ip).values())
            ),
            trigger_info=trigger_info,
            violation_category=violation_category,
        )
    except Exception as exc:
        _log_exception_safely(
            logger, "escalate_identity_violation failed for %s", client_ip
        )
        try:
            await _emit_ban_escalation_failed(middleware, request, client_ip, exc)
        except Exception:
            _log_exception_safely(
                logger,
                "Failed to report ban escalation failure for %s",
                client_ip,
            )


async def report_hostile_signal(
    check: "SecurityCheck",
    request: GuardRequest,
    category: str | None,
    trigger_info: str,
    legacy_violation: str | None = None,
) -> None:
    """Feed a denial into the ban policy that ``ban_on_hostile_signals`` selects.

    With the flag on, a denial that has a ``category`` counts toward an automatic
    ban. With the flag off, the denial keeps the 4.4.0 behavior: a denial that
    names a ``legacy_violation`` escalates only when the request also matches a
    penetration-detection pattern, and every other denial counts nothing.
    """
    if check.config.ban_on_hostile_signals:
        if category is not None:
            await count_hostile_signal_and_maybe_ban(
                check, request, category, trigger_info
            )
        return
    client_ip = getattr(request.state, "client_ip", None)
    if legacy_violation is None or check.config.passive_mode or not client_ip:
        return
    await escalate_identity_violation(
        check.middleware,
        check.config,
        check.ip_ban_manager,
        request,
        client_ip,
        check.logger,
        check.check_name,
        check.config.muted_check_logs,
        legacy_violation,
        trigger_info,
    )
