import ipaddress
from typing import Any

from guard_core.sync._utils.ip_extraction import _client_identity
from guard_core.sync._utils.whitelist_match import most_specific_whitelist_entry
from guard_core.sync.handlers._ipban_lookup import IpBanLookupMixin

_SIX_TO_FOUR_GROUP_LENGTH = 48
_SIX_TO_FOUR = ipaddress.ip_network("2002::/16")
_SCAN_COUNT = 2000


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
        entry = most_specific_whitelist_entry(
            address, getattr(self.config, "whitelist", None) or ()
        )
        text = str(address)
        if (
            entry is not None
            and _client_identity(text, self._prefix_length(self.config), entry) == key
        ):
            return None
        return _client_identity(text, self._prefix_length(self.config))

    def rewrite_carved_bans_without_whitelist(self) -> int:
        moved = self._rewrite_memory_carves()
        if self.redis_handler:
            moved += self._rewrite_redis_carves()
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

    def _rewrite_redis_carves(self) -> int:
        redis: Any = self.redis_handler
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
                self._move_identity_key(conn, stem, key, target, value, pttl)
                moved += 1
        return moved

    def _move_identity_key(
        self, conn: Any, stem: str, key: str, target: str, value: str, pttl: int
    ) -> None:
        target_key = f"{stem}{target}"
        existing = conn.pttl(target_key)
        if existing < pttl:
            conn.set(target_key, value, px=pttl)
        conn.delete(key)
        self._purge_banned_ip(key[len(stem) :])
