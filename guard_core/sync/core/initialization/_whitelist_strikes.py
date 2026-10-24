import hashlib
import ipaddress
import logging
from collections.abc import Iterable
from typing import Any

from guard_core.models import SyncSecurityConfig
from guard_core.sync.handlers.redis_handler import is_connected_redis_manager

_NAMESPACE = "whitelist"
_APPLIED_KEY = "strikes_applied"
_LOCK_KEY = "strikes_lock"
_LOCK_SECONDS = 60
_logger = logging.getLogger("guard_core.sync.core.initialization.whitelist_strikes")


def whitelist_fingerprint(entries: Iterable[str]) -> str:
    canonical = sorted(
        {str(ipaddress.ip_network(entry, strict=False)) for entry in entries}
    )
    return hashlib.sha256("\n".join(canonical).encode()).hexdigest()[:32]


def _claim_changed_whitelist(redis_handler: Any, fingerprint: str) -> bool:
    if redis_handler.get_key(_NAMESPACE, _APPLIED_KEY) == fingerprint:
        return False
    return bool(
        redis_handler.set_key_if_absent(_NAMESPACE, _LOCK_KEY, "1", _LOCK_SECONDS)
    )


def _reset_covered_identities(entries: list[str], ip_ban_manager: Any) -> None:
    for entry in entries:
        if "/" not in entry:
            ip_ban_manager.forget_strikes_of_ip(entry, strict=True)
    ip_ban_manager.forget_strikes_inside(
        [entry for entry in entries if "/" in entry], strict=True
    )


def reset_strikes_for_changed_whitelist(
    config: SyncSecurityConfig, redis_handler: Any, ip_ban_manager: Any
) -> None:
    """Start every identity the startup whitelist covers with no strikes.

    One key per prefix holds the fingerprint of the last applied whitelist. Only
    a start whose whitelist differs takes a 60 s lock, resets the strikes (exact
    entries one by one, ranges with one scan) and stores its fingerprint after the
    scan succeeded, so a crashed scan is retried by the next start.
    """
    entries = list(config.whitelist or [])
    try:
        fingerprint = whitelist_fingerprint(entries)
        if not _claim_changed_whitelist(redis_handler, fingerprint):
            return
        try:
            _reset_covered_identities(entries, ip_ban_manager)
            ip_ban_manager.rewrite_carved_bans_without_whitelist()
            redis_handler.set_key(_NAMESPACE, _APPLIED_KEY, fingerprint)
        finally:
            redis_handler.delete(_NAMESPACE, _LOCK_KEY)
    except Exception as error:
        _logger.warning(
            "The strikes of the startup whitelist could not be reset, the next "
            "start tries again: %s",
            error,
        )


def reset_startup_whitelist_strikes(
    config: SyncSecurityConfig, redis_handler: Any, ip_ban_manager: Any
) -> None:
    if is_connected_redis_manager(redis_handler):
        reset_strikes_for_changed_whitelist(config, redis_handler, ip_ban_manager)
