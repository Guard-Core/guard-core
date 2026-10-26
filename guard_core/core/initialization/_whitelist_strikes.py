import hashlib
import ipaddress
import logging
from collections.abc import Iterable
from typing import Protocol

from guard_core.handlers.redis_handler import is_connected_redis_manager
from guard_core.models import SecurityConfig
from guard_core.protocols.redis_protocol import RedisHandlerProtocol

_NAMESPACE = "whitelist"
_APPLIED_KEY = "strikes_applied"
_LOCK_KEY = "strikes_lock"
_LOCK_SECONDS = 60
_logger = logging.getLogger("guard_core.core.initialization.whitelist_strikes")


class StrikeResetBanManager(Protocol):
    async def forget_strikes_of_ip(self, ip: str, strict: bool = False) -> None: ...

    async def forget_strikes_inside(
        self, entries: Iterable[str], strict: bool = False
    ) -> None: ...

    async def rewrite_carved_bans_without_whitelist(self) -> int: ...


def whitelist_fingerprint(entries: Iterable[str]) -> str:
    canonical = sorted(
        {str(ipaddress.ip_network(entry, strict=False)) for entry in entries}
    )
    return hashlib.sha256("\n".join(canonical).encode()).hexdigest()[:32]


async def _claim_changed_whitelist(
    redis_handler: RedisHandlerProtocol, fingerprint: str
) -> bool:
    if await redis_handler.get_key(_NAMESPACE, _APPLIED_KEY) == fingerprint:
        return False
    return bool(
        await redis_handler.set_key_if_absent(_NAMESPACE, _LOCK_KEY, "1", _LOCK_SECONDS)
    )


async def _reset_covered_identities(
    entries: list[str], ip_ban_manager: StrikeResetBanManager
) -> None:
    for entry in entries:
        if "/" not in entry:
            await ip_ban_manager.forget_strikes_of_ip(entry, strict=True)
    await ip_ban_manager.forget_strikes_inside(
        [entry for entry in entries if "/" in entry], strict=True
    )


async def reset_strikes_for_changed_whitelist(
    config: SecurityConfig,
    redis_handler: RedisHandlerProtocol,
    ip_ban_manager: StrikeResetBanManager,
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
        if not await _claim_changed_whitelist(redis_handler, fingerprint):
            return
        try:
            await _reset_covered_identities(entries, ip_ban_manager)
            await ip_ban_manager.rewrite_carved_bans_without_whitelist()
            await redis_handler.set_key(_NAMESPACE, _APPLIED_KEY, fingerprint)
        finally:
            await redis_handler.delete(_NAMESPACE, _LOCK_KEY)
    except Exception as error:
        _logger.warning(
            "The strikes of the startup whitelist could not be reset, the next "
            "start tries again: %s",
            error,
        )


async def reset_startup_whitelist_strikes(
    config: SecurityConfig,
    redis_handler: RedisHandlerProtocol,
    ip_ban_manager: StrikeResetBanManager,
) -> None:
    if is_connected_redis_manager(redis_handler):
        await reset_strikes_for_changed_whitelist(config, redis_handler, ip_ban_manager)
