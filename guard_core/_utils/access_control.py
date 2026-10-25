import logging
from collections.abc import Sequence
from dataclasses import dataclass, replace
from ipaddress import ip_address
from typing import Any

from guard_core._utils.detection_scan import _user_agent_matches_blocked_pattern
from guard_core._utils.ip_extraction import (
    MALFORMED_FORWARDED_FOR_PREFIX,
    UNKNOWN_CLIENT_IDENTITY,
    _canonicalize_ip,
)
from guard_core._utils.logging_utils import _log_at_level
from guard_core._utils.whitelist_match import is_listed
from guard_core.protocols.geo_ip_protocol import GeoIPHandler
from guard_core.protocols.request_protocol import GuardRequest

logger = logging.getLogger("guard_core")


async def is_user_agent_allowed(user_agent: str, config: Any) -> bool:
    blocked = await _user_agent_matches_blocked_pattern(
        user_agent, config.blocked_user_agents
    )
    return not blocked


def _extract_ip_from_request(request: str | GuardRequest) -> str:
    if isinstance(request, str):
        return request
    return (
        _canonicalize_ip(request.client_host)
        if request.client_host
        else UNKNOWN_CLIENT_IDENTITY
    )


def _has_country_rules(config: Any) -> bool:
    return bool(config.blocked_countries or config.whitelist_countries)


def _is_loopback(ip: str) -> bool:
    try:
        return ip_address(ip).is_loopback
    except ValueError:
        return False


def _log_country_check_result(
    ip: str, country: str | None, result_type: str, config: Any
) -> None:
    if result_type == "no_rules":
        logger.debug(
            f"No countries blocked or whitelisted {ip} - "
            "No countries blocked or whitelisted"
        )
    elif result_type == "no_geolocation":
        logger.debug(f"IP not geolocated {ip} - IP geolocation failed")
    elif result_type == "loopback_exempt":
        logger.debug(f"Loopback IP exempt from country allowlist check {ip}")
    elif result_type == "blocked":
        level = config.log_suspicious_level
        if level is None:
            return
        _log_at_level(
            logger,
            level,
            f"IP from blocked country {ip} - {country} - IP from blocked country",
        )
    elif result_type in ("whitelisted", "not_affected"):
        level = config.log_country_check_level
        if level is None:
            return
        if result_type == "whitelisted":
            _log_at_level(
                logger,
                level,
                f"IP from whitelisted country {ip} - {country} - "
                "IP from whitelisted country",
            )
        else:
            _log_at_level(
                logger,
                level,
                f"IP not from blocked or whitelisted country {ip} - {country} - "
                "IP not from blocked or whitelisted country",
            )


def _evaluate_country_access(country: str, config: Any) -> tuple[bool, str]:
    if config.whitelist_countries:
        if country in config.whitelist_countries:
            return False, "whitelisted"
        return True, "blocked"

    if config.blocked_countries and country in config.blocked_countries:
        return True, "blocked"

    return False, "not_affected"


async def _load_geo_database(geo_ip_handler: GeoIPHandler) -> None:
    ensure_database_loaded = getattr(geo_ip_handler, "ensure_database_loaded", None)
    if ensure_database_loaded is None:
        await geo_ip_handler.initialize()
        return
    await ensure_database_loaded()


async def load_geo_database_for_route_rules(middleware: Any) -> None:
    geo_ip_handler: GeoIPHandler | None = middleware.geo_ip_handler
    if geo_ip_handler is not None and not geo_ip_handler.is_initialized:
        await _load_geo_database(geo_ip_handler)


async def _resolve_country_verdict(
    ip: str, config: Any, geo_ip_handler: GeoIPHandler
) -> tuple[bool, str | None]:
    if not _has_country_rules(config):
        _log_country_check_result(ip, None, "no_rules", config)
        return False, None

    if _is_loopback(ip):
        _log_country_check_result(ip, None, "loopback_exempt", config)
        return False, None

    if not geo_ip_handler.is_initialized:
        await _load_geo_database(geo_ip_handler)

    country = geo_ip_handler.get_country(ip)

    if not country:
        _log_country_check_result(ip, None, "no_geolocation", config)
        return bool(config.whitelist_countries), None

    is_blocked, result_type = _evaluate_country_access(country, config)
    _log_country_check_result(ip, country, result_type, config)

    return is_blocked, country


async def check_ip_country(
    request: str | GuardRequest,
    config: Any,
    geo_ip_handler: GeoIPHandler,
) -> bool:
    ip = _extract_ip_from_request(request)
    is_blocked, _country = await _resolve_country_verdict(ip, config, geo_ip_handler)
    return is_blocked


def _ip_in_list(ip_addr: Any, ip: str, entries: Sequence[str] | None) -> bool:
    if not entries:
        return False
    return is_listed(ip_addr, _canonicalize_ip(ip), entries, "list")


async def _check_blacklist(ip_addr: Any, ip: str, config: Any) -> bool:
    return not _ip_in_list(ip_addr, ip, config.blacklist)


async def _check_whitelist(ip_addr: Any, ip: str, config: Any) -> bool:
    if config.whitelist:
        return _ip_in_list(ip_addr, ip, config.whitelist)
    return True


async def _check_blocked_countries(
    ip: str, config: Any, geo_ip_handler: GeoIPHandler | None
) -> bool:
    if (config.blocked_countries or config.whitelist_countries) and geo_ip_handler:
        country_blocked = await check_ip_country(ip, config, geo_ip_handler)
        if country_blocked:
            return False
    return True


ALLOW_LIST_MISSES_ARE_HOSTILE = False


def allow_list_miss_category(category: str) -> str | None:
    """Return ``category`` when an allow-list miss counts toward a ban, else ``None``.

    Block-list hits always count. Whether a client that merely is not on an
    allow-list (IP whitelist, country whitelist) is a hostile signal is a pending
    maintainer decision, so this one switch keeps those misses uncounted.
    """
    return category if ALLOW_LIST_MISSES_ARE_HOSTILE else None


@dataclass(frozen=True)
class IpAccessResult:
    allowed: bool
    reason: str
    cloud_provider: str | None = None
    network: str | None = None
    denial_category: str | None = None
    country: str | None = None
    country_rule: str | None = None
    status_code: int = 403
    geo_failure: str | None = None


_GENERIC_LIST_BLOCK_REASON = "IP {ip} not in global allowlist/blocklist"


class _GeoLookupError(Exception):
    def __init__(self, kind: str) -> None:
        super().__init__(kind)
        self.kind = kind


def _result_for_geo_failure(kind: str, config: Any) -> IpAccessResult | None:
    if config.fail_secure:
        return IpAccessResult(False, f"GeoIP lookup failed ({kind})", geo_failure=kind)
    return None


async def _check_blocked_countries_detail(
    ip: str, config: Any, geo_ip_handler: GeoIPHandler | None
) -> IpAccessResult | None:
    if (
        not (config.blocked_countries or config.whitelist_countries)
        or not geo_ip_handler
    ):
        return None

    try:
        is_blocked, country = await _resolve_country_verdict(ip, config, geo_ip_handler)
    except Exception as error:
        raise _GeoLookupError(type(error).__name__) from error
    if not is_blocked:
        return None

    reason = (
        f"IP from blocked country: {country}"
        if country
        else _GENERIC_LIST_BLOCK_REASON.format(ip=ip)
    )
    return IpAccessResult(
        False,
        reason,
        denial_category=allow_list_miss_category("country")
        if config.whitelist_countries
        else "country",
        country=country,
        country_rule="country_whitelist"
        if config.whitelist_countries
        else "country_blacklist",
    )


async def _check_cloud_providers_detail(ip: str, config: Any) -> IpAccessResult | None:
    from guard_core.handlers.cloud_handler import cloud_handler_for

    if not config.block_cloud_providers:
        return None
    cloud_handler = cloud_handler_for(config)
    if not cloud_handler.is_cloud_ip(ip, config.block_cloud_providers):
        return None

    details = cloud_handler.get_cloud_provider_details(ip, config.block_cloud_providers)
    if details is None:
        return IpAccessResult(
            False, _GENERIC_LIST_BLOCK_REASON.format(ip=ip), denial_category="cloud"
        )

    provider, network = details
    return IpAccessResult(
        False,
        f"IP belongs to blocked cloud provider: {provider}",
        cloud_provider=provider,
        network=network,
        denial_category="cloud",
    )


def _check_unknown_identity_access(
    ip: str, config: Any, skip_ip_lists: bool, skip_countries: bool
) -> IpAccessResult | None:
    if ip != UNKNOWN_CLIENT_IDENTITY:
        return None
    whitelist_blocks = not skip_ip_lists and config.whitelist
    country_whitelist_blocks = not skip_countries and config.whitelist_countries
    if whitelist_blocks or country_whitelist_blocks:
        return IpAccessResult(
            False,
            _GENERIC_LIST_BLOCK_REASON.format(ip=ip),
            denial_category=allow_list_miss_category(
                "ip_list" if whitelist_blocks else "country"
            ),
        )
    return IpAccessResult(True, "")


def _unparsable_identity_result(
    ip: str, config: Any, skip_ip_lists: bool, skip_countries: bool
) -> IpAccessResult:
    if ip.startswith(MALFORMED_FORWARDED_FOR_PREFIX):
        return _malformed_forwarded_for_result(
            ip, config, skip_ip_lists, skip_countries
        )
    return IpAccessResult(False, _GENERIC_LIST_BLOCK_REASON.format(ip=ip))


def _malformed_forwarded_for_result(
    ip: str, config: Any, skip_ip_lists: bool, skip_countries: bool
) -> IpAccessResult:
    if config.fail_secure:
        return IpAccessResult(
            False,
            f"Malformed X-Forwarded-For entry from trusted proxy ({ip})",
            status_code=400,
        )
    allowed_by_lists = (skip_ip_lists or not config.whitelist) and (
        skip_countries or not config.whitelist_countries
    )
    if allowed_by_lists:
        return IpAccessResult(True, "")
    return IpAccessResult(False, _GENERIC_LIST_BLOCK_REASON.format(ip=ip))


async def _check_ip_lists_detail(
    ip_addr: Any, ip: str, config: Any, skip_whitelist: bool = False
) -> IpAccessResult | None:
    reason = _GENERIC_LIST_BLOCK_REASON.format(ip=ip)
    if config.blacklist and not await _check_blacklist(ip_addr, ip, config):
        return IpAccessResult(False, reason, denial_category="ip_list")
    if (
        config.whitelist
        and not skip_whitelist
        and not await _check_whitelist(ip_addr, ip, config)
    ):
        return IpAccessResult(
            False, reason, denial_category=allow_list_miss_category("ip_list")
        )
    return None


async def _check_country_and_cloud_detail(
    ip_addr: Any,
    ip: str,
    config: Any,
    geo_ip_handler: GeoIPHandler | None,
    skip_countries: bool,
    skip_clouds: bool,
) -> IpAccessResult | None:
    geo_failure: str | None = None
    if not skip_countries:
        try:
            country_result = await _check_blocked_countries_detail(
                ip, config, geo_ip_handler
            )
        except _GeoLookupError as failure:
            geo_failure = failure.kind
            country_result = _result_for_geo_failure(failure.kind, config)
        if country_result is not None:
            return country_result
    if not (skip_clouds or _ip_in_list(ip_addr, ip, config.exempt_ips)):
        cloud_result = await _check_cloud_providers_detail(ip, config)
        if cloud_result is not None:
            return replace(cloud_result, geo_failure=geo_failure)
    return IpAccessResult(True, "", geo_failure=geo_failure) if geo_failure else None


async def check_ip_access(
    ip: str,
    config: Any,
    geo_ip_handler: GeoIPHandler | None = None,
    *,
    skip_ip_lists: bool = False,
    skip_countries: bool = False,
    skip_clouds: bool = False,
    skip_whitelist: bool = False,
) -> IpAccessResult:
    unknown_result = _check_unknown_identity_access(
        ip, config, skip_ip_lists or skip_whitelist, skip_countries
    )
    if unknown_result is not None:
        return unknown_result

    try:
        ip_addr = ip_address(ip)

        if not skip_ip_lists:
            list_result = await _check_ip_lists_detail(
                ip_addr, ip, config, skip_whitelist
            )
            if list_result is not None:
                return list_result
            if not skip_whitelist and _ip_in_list(ip_addr, ip, config.whitelist):
                skip_countries = True
                skip_clouds = True

        result = await _check_country_and_cloud_detail(
            ip_addr, ip, config, geo_ip_handler, skip_countries, skip_clouds
        )
        if result is not None:
            return result
        return IpAccessResult(True, "")
    except ValueError:
        return _unparsable_identity_result(
            ip, config, skip_ip_lists or skip_whitelist, skip_countries
        )


async def is_ip_allowed(
    ip: str,
    config: Any,
    geo_ip_handler: GeoIPHandler | None = None,
    *,
    skip_ip_lists: bool = False,
    skip_countries: bool = False,
    skip_clouds: bool = False,
    skip_whitelist: bool = False,
) -> bool:
    result = await check_ip_access(
        ip,
        config,
        geo_ip_handler,
        skip_ip_lists=skip_ip_lists,
        skip_countries=skip_countries,
        skip_clouds=skip_clouds,
        skip_whitelist=skip_whitelist,
    )
    return result.allowed
