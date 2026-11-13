import ipaddress
from typing import TYPE_CHECKING

from guard_core._utils.ip_extraction import _client_identity
from guard_core._utils.nat64 import nat64_table_of
from guard_core._utils.whitelist_match import most_specific_whitelist_entry
from guard_core.handlers._dynamic_rule_persistence import BAN_FLOORS_NAMESPACE
from guard_core.handlers._ipban_lookup import IpBanLookupMixin
from guard_core.handlers._ipban_migration import _MISSING_KEY, _expiry_ms
from guard_core.protocols.redis_protocol import RedisHandlerProtocol

if TYPE_CHECKING:
    from redis.asyncio import Redis

_SIX_TO_FOUR_GROUP_LENGTH = 48
_SIX_TO_FOUR = ipaddress.ip_network("2002::/16")
_SCAN_COUNT = 2000


async def _plan_floor_move(
    conn: "Redis", stem: str, key: str, target: str
) -> tuple[str, str, str | None, int]:
    """The floor keys of a carved ban and of its base identity, and the floor to
    write at the base (None when the carve has none or the base keeps a later),
    with the floor's absolute expiry in milliseconds."""
    floor_stem = (
        f"{stem.removesuffix('banned_identities:')}{BAN_FLOORS_NAMESPACE}:"
        "banned_identities:"
    )
    floor_key, floor_target = f"{floor_stem}{key[len(stem) :]}", f"{floor_stem}{target}"
    async with conn.pipeline() as pipe:
        await pipe.get(floor_key)
        await pipe.pttl(floor_key)
        await pipe.pttl(floor_target)
        await pipe.time()
        floor, floor_pttl, target_pttl, now = await pipe.execute()
    floor_expiry_ms = _expiry_ms(now, floor_pttl)
    moves = floor is not None and (
        target_pttl == _MISSING_KEY
        or (target_pttl >= 0 and floor_expiry_ms > _expiry_ms(now, target_pttl))
    )
    return floor_key, floor_target, floor if moves else None, floor_expiry_ms


async def _read_live_ban(conn: "Redis", key: str) -> tuple[str, int] | None:
    """A ban's value and absolute expiry in milliseconds, None when the key is gone
    or has no remaining time."""
    async with conn.pipeline() as pipe:
        await pipe.get(key)
        await pipe.pttl(key)
        await pipe.time()
        value, pttl, now = await pipe.execute()
    if value is None or pttl <= 0:
        return None
    return value, _expiry_ms(now, pttl)


class IpBanCarveMixin(IpBanLookupMixin):
    """Moves an active ban back to its base identity when its carve is gone.

    A whitelisted host or range inside a grouped identity is banned under its own
    carved identity (a /128 or a /72). When the whitelist entry is removed, that
    identity is no longer produced by any request, so the ban would stay in the
    store and no longer deny anyone: it is rewritten to the identity the same
    address resolves to without the entry, keeping its remaining time.
    """

    def _carved_address_of(self, key: str) -> ipaddress.IPv6Address | None:
        try:
            network = ipaddress.ip_network(key, strict=False)
        except ValueError:
            return None
        group_length = (
            _SIX_TO_FOUR_GROUP_LENGTH
            if network.network_address in _SIX_TO_FOUR
            else self._prefix_length(self.config)
        )
        if network.version != 6 or network.prefixlen <= group_length:
            return None
        return network.network_address

    def _whitelist_still_produces_carve(
        self, address: ipaddress.IPv6Address, key: str
    ) -> bool:
        nat64 = nat64_table_of(self.config)
        entry = most_specific_whitelist_entry(
            address, getattr(self.config, "whitelist", None) or (), nat64
        )
        return (
            entry is not None
            and _client_identity(
                str(address), self._prefix_length(self.config), entry, nat64
            )
            == key
        )

    def _base_identity_if_carve_is_gone(self, key: str) -> str | None:
        address = self._carved_address_of(key)
        if address is None or self._whitelist_still_produces_carve(address, key):
            return None
        return _client_identity(
            str(address),
            self._prefix_length(self.config),
            None,
            nat64_table_of(self.config),
        )

    async def rewrite_carved_bans_without_whitelist(self) -> int:
        moved = self._rewrite_memory_carves()
        if self.redis_handler:
            moved += await self._rewrite_redis_carves(self.redis_handler)
        if moved:
            await self._bump_ban_version()
        return moved

    def _rewrite_memory_carves(self) -> int:
        moved = 0
        for key in [key for key in self.banned_ips if "/" in key]:
            target = self._base_identity_if_carve_is_gone(key)
            if target is None:
                continue
            expiry = self.banned_ips[key]
            del self.banned_ips[key]
            self.banned_ips[target] = max(self.banned_ips.get(target, 0.0), expiry)
            moved += 1
        return moved

    async def _rewrite_redis_carves(self, redis: RedisHandlerProtocol) -> int:
        stem = f"{redis.config.redis_prefix}banned_identities:"
        moved = 0
        async with redis.get_connection() as conn:
            keys = [
                key async for key in conn.scan_iter(match=f"{stem}*", count=_SCAN_COUNT)
            ]
            for key in keys:
                target = self._base_identity_if_carve_is_gone(key[len(stem) :])
                if target is None:
                    continue
                live = await _read_live_ban(conn, key)
                if live is None:
                    continue
                value, expires_at_ms = live
                await self._move_identity_key(
                    redis, conn, stem, key, target, value, expires_at_ms
                )
                moved += 1
        return moved

    async def _move_identity_key(
        self,
        redis: RedisHandlerProtocol,
        conn: "Redis",
        stem: str,
        key: str,
        target: str,
        value: str,
        expires_at_ms: int,
    ) -> None:
        target_key = f"{stem}{target}"
        async with conn.pipeline() as pipe:
            await pipe.pttl(target_key)
            await pipe.time()
            existing, now = await pipe.execute()
        floor_key, floor_target, floor, floor_expires_at_ms = await _plan_floor_move(
            conn, stem, key, target
        )
        async with conn.pipeline(transaction=True) as pipe:
            if existing == _MISSING_KEY or (
                existing >= 0 and _expiry_ms(now, existing) < expires_at_ms
            ):
                await pipe.set(target_key, value)
                await pipe.pexpireat(target_key, expires_at_ms)
            if floor is not None:
                await pipe.set(floor_target, floor)
                await pipe.pexpireat(floor_target, floor_expires_at_ms)
            await pipe.delete(key, floor_key)
            await pipe.incr(self._version_redis_key(redis))
            await pipe.execute()
        self._purge_banned_ip(key[len(stem) :])
