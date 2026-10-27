import ipaddress
from typing import TYPE_CHECKING

from guard_core.sync._utils.ip_extraction import _client_identity
from guard_core.sync._utils.nat64 import nat64_table_of
from guard_core.sync._utils.whitelist_match import most_specific_whitelist_entry
from guard_core.sync.handlers._dynamic_rule_persistence import BAN_FLOORS_NAMESPACE
from guard_core.sync.handlers._ipban_lookup import IpBanLookupMixin
from guard_core.sync.protocols.redis_protocol import SyncRedisHandlerProtocol

if TYPE_CHECKING:
    from redis import Redis

_SIX_TO_FOUR_GROUP_LENGTH = 48
_SIX_TO_FOUR = ipaddress.ip_network("2002::/16")
_SCAN_COUNT = 2000


def _plan_floor_move(
    conn: "Redis", stem: str, key: str, target: str
) -> tuple[str, str, str | None, int]:
    """The floor keys of a carved ban and of its base identity, and the floor to
    write at the base (None when the carve has none or the base keeps a later)."""
    floor_stem = (
        f"{stem.removesuffix('banned_identities:')}{BAN_FLOORS_NAMESPACE}:"
        "banned_identities:"
    )
    floor_key, floor_target = f"{floor_stem}{key[len(stem) :]}", f"{floor_stem}{target}"
    floor, floor_pttl = conn.get(floor_key), conn.pttl(floor_key)
    moves = floor is not None and floor_pttl > conn.pttl(floor_target)
    return floor_key, floor_target, floor if moves else None, floor_pttl


class IpBanCarveMixin(IpBanLookupMixin):
    """Moves an active ban back to its base identity when its carve is gone.

    A whitelisted host or range inside a grouped identity is banned under its own
    carved identity (a /128 or a /72). When the whitelist entry is removed, that
    identity is no longer produced by any request, so the ban would stay in the
    store and no longer deny anyone: it is rewritten to the identity the same
    address resolves to without the entry, keeping its remaining time.
    """

    def _base_identity_if_carve_is_gone(self, key: str) -> str | None:
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
        address = network.network_address
        nat64 = nat64_table_of(self.config)
        entry = most_specific_whitelist_entry(
            address, getattr(self.config, "whitelist", None) or (), nat64
        )
        text = str(address)
        prefix_length = self._prefix_length(self.config)
        if (
            entry is not None
            and _client_identity(text, prefix_length, entry, nat64) == key
        ):
            return None
        return _client_identity(text, prefix_length, None, nat64)

    def rewrite_carved_bans_without_whitelist(self) -> int:
        moved = self._rewrite_memory_carves()
        if self.redis_handler:
            moved += self._rewrite_redis_carves(self.redis_handler)
        if moved:
            self._bump_ban_version()
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

    def _rewrite_redis_carves(self, redis: SyncRedisHandlerProtocol) -> int:
        stem = f"{redis.config.redis_prefix}banned_identities:"
        moved = 0
        with redis.get_connection() as conn:
            keys = [key for key in conn.scan_iter(match=f"{stem}*", count=_SCAN_COUNT)]
            for key in keys:
                target = self._base_identity_if_carve_is_gone(key[len(stem) :])
                if target is None:
                    continue
                value, pttl = conn.get(key), conn.pttl(key)
                if value is None or pttl <= 0:
                    continue
                self._move_identity_key(redis, conn, stem, key, target, value, pttl)
                moved += 1
        return moved

    def _move_identity_key(
        self,
        redis: SyncRedisHandlerProtocol,
        conn: "Redis",
        stem: str,
        key: str,
        target: str,
        value: str,
        pttl: int,
    ) -> None:
        target_key = f"{stem}{target}"
        existing = conn.pttl(target_key)
        floor_key, floor_target, floor, floor_pttl = _plan_floor_move(
            conn, stem, key, target
        )
        with conn.pipeline(transaction=True) as pipe:
            if existing < pttl:
                pipe.set(target_key, value, px=pttl)
            if floor is not None:
                pipe.set(floor_target, floor, px=floor_pttl)
            pipe.delete(key, floor_key)
            pipe.incr(self._version_redis_key(redis))
            pipe.execute()
        self._purge_banned_ip(key[len(stem) :])
