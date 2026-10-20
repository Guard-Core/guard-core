import ipaddress
import logging
import time
from collections.abc import Iterable, MutableMapping
from typing import Any

from guard_core.sync.handlers._ipban_cache import _BanStore, _Network
from guard_core.sync.handlers._ipban_events import IpBanEventMixin
from guard_core.sync.handlers._ipban_rule_exempt import rule_ban_target
from guard_core.sync.handlers._ipban_version import IpBanVersionMixin

REVOKE_GONE = 0
REVOKE_DELETED = 1
REVOKE_REWRITTEN = 2
REVOKE_KEPT = 3
_LIFTED = (REVOKE_DELETED, REVOKE_REWRITTEN)
_REVOKE_REASON = "dynamic_rule_revoked"
_RULE_NAMESPACES = ("banned_ips", "banned_networks")


class IpBanRuleRevokeMixin(IpBanVersionMixin, IpBanEventMixin):
    """Lifts the bans a dynamic rule wrote and nothing else.

    A revoke removes a ban only while it still holds the expiry the rule wrote;
    a longer ban written over it stays, a shorter one it hid (its floor) takes
    over. Strikes, recidive history and the grouped identity are never touched:
    a rule ban never wrote them. Without Redis the same compare-and-delete runs
    on the in-memory entry against the expiry this process recorded.
    """

    banned_ips: MutableMapping[str, float]
    banned_networks: list[tuple[_Network, float]]
    redis_handler: Any = None
    logger: logging.Logger
    _rule_owned_expiries: dict[str, float]
    _rule_floor_expiries: dict[str, float]
    _foreign_network_expiries: dict[str, float]
    MAX_LOCAL_BANS: int

    def _live_memory_expiry(self, namespace: str, key: str, now: float) -> float | None:
        if namespace == "banned_networks":
            expiry = self._held_network_expiry(key)
        else:
            expiry = self.banned_ips.get(key)
        return expiry if expiry is not None and expiry > now else None

    def _held_network_expiry(self, key: str) -> float | None:
        held = [until for network, until in self.banned_networks if str(network) == key]
        return max(held, default=None)

    def _note_memory_ban_write(
        self, namespace: str, key: str, new: float, rule_owned: bool
    ) -> None:
        """Mirror, for a ban held in this process only, what the extend-only
        write script records in Redis: the rule's own expiry, and the foreign
        expiry a longer rule ban hides (its floor)."""
        member = f"{namespace}:{key}"
        live = self._live_memory_expiry(namespace, key, time.time())
        if live is None:
            self._rule_floor_expiries.pop(member, None)
        if rule_owned:
            self._note_memory_rule_write(member, live, new)
        elif live is not None and live > new and member in self._rule_owned_expiries:
            self._keep_memory_floor(member, new)

    def _note_memory_rule_write(
        self, member: str, live: float | None, new: float
    ) -> None:
        if live is None or live >= new:
            if live is None:
                self._rule_owned_expiries[member] = new
            return
        if self._rule_owned_expiries.get(member) != live:
            self._keep_memory_floor(member, live)
        self._rule_owned_expiries[member] = new

    def _keep_memory_floor(self, member: str, expiry: float) -> None:
        self._rule_floor_expiries[member] = max(
            expiry, self._rule_floor_expiries.get(member, 0.0)
        )

    def _set_memory_expiry(self, namespace: str, key: str, expiry: float) -> None:
        if namespace == "banned_networks":
            network = ipaddress.ip_network(key, strict=False)
            kept = [entry for entry in self.banned_networks if entry[0] != network]
            self.banned_networks = [*kept, (network, expiry)]
            return
        self.banned_ips[key] = expiry
        if isinstance(self.banned_ips, _BanStore):
            self.banned_ips.mark_memory_only(key)

    def _drop_local_rule_ban(self, namespace: str, key: str) -> None:
        if namespace == "banned_networks":
            network = ipaddress.ip_network(key, strict=False)
            self.banned_networks = [
                entry for entry in self.banned_networks if entry[0] != network
            ]
            self._foreign_network_expiries.pop(key, None)
            return
        self.banned_ips.pop(key, None)

    def _revoke_in_memory(self, namespace: str, key: str) -> int:
        member = f"{namespace}:{key}"
        owned = self._rule_owned_expiries.pop(member, 0.0)
        floor = self._rule_floor_expiries.pop(member, 0.0)
        now = time.time()
        live = self._live_memory_expiry(namespace, key, now)
        if live is None or owned <= now:
            return REVOKE_GONE
        if live != owned:
            return REVOKE_KEPT
        if floor > now:
            self._set_memory_expiry(namespace, key, floor)
            return REVOKE_REWRITTEN
        self._drop_local_rule_ban(namespace, key)
        return REVOKE_DELETED

    def _record_foreign_memory_ban(
        self, namespace: str, key: str, expiry: float, rule_owned: bool
    ) -> None:
        """A ban another source wrote whose Redis write failed lives in this
        process only; remember its expiry so a rule revoke does not lift it."""
        if rule_owned or namespace == "banned_identities":
            return
        if namespace == "banned_ips":
            if isinstance(self.banned_ips, _BanStore):
                self.banned_ips.record_foreign_memory(key, expiry)
            return
        now = time.time()
        held = {str(network) for network, _ in self.banned_networks}
        records = {**self._foreign_network_expiries}
        records[key] = max(expiry, records.get(key, 0.0))
        live = {k: until for k, until in records.items() if until > now and k in held}
        while len(live) > self.MAX_LOCAL_BANS:
            del live[min(live, key=lambda name: live[name])]
        self._foreign_network_expiries = live

    def _foreign_memory_expiry(self, namespace: str, key: str) -> float | None:
        if namespace == "banned_networks":
            expiry = self._foreign_network_expiries.get(key)
        elif isinstance(self.banned_ips, _BanStore):
            expiry = self.banned_ips.foreign_memory_expiry(key)
        else:
            expiry = None
        return expiry if expiry is not None and expiry > time.time() else None

    def _keep_foreign_memory_ban_or_drop(self, namespace: str, key: str) -> None:
        foreign = self._foreign_memory_expiry(namespace, key)
        if foreign is None:
            self._drop_local_rule_ban(namespace, key)
            return
        self._set_memory_expiry(namespace, key, foreign)

    def owned_rule_ban_targets(self) -> list[str]:
        """The addresses and networks a dynamic rule owns, in the form
        ``rule_ban_target`` gives them, from Redis and from this process."""
        members = list(self._rule_owned_expiries)
        if self.redis_handler:
            prefix = self.redis_handler.config.redis_prefix
            members += [
                member[len(prefix) :]
                for member in self.redis_handler.owned_ban_members()
            ]
        parts = [member.partition(":") for member in members]
        return list(
            dict.fromkeys(key for ns, _, key in parts if ns in _RULE_NAMESPACES)
        )

    def revoke_rule_ban(self, ip: str) -> int:
        """Lift the ban a rule wrote on ip (an address or a CIDR): 0 gone, 1
        deleted, 2 rewritten to the shorter ban it hid, 3 a longer ban replaced
        it and was left alone. Settle a batch with ``settle_rule_revocations``."""
        namespace, key = rule_ban_target(ip)
        held = f"{namespace}:{key}" in self._rule_owned_expiries
        in_memory = self._revoke_in_memory(namespace, key) if held else REVOKE_GONE
        if not self.redis_handler:
            return in_memory
        prefix = self.redis_handler.config.redis_prefix
        outcome = self.redis_handler.purge_owned_ban(f"{prefix}{namespace}:{key}")
        if in_memory == REVOKE_GONE:
            self._keep_foreign_memory_ban_or_drop(namespace, key)
        return outcome or in_memory

    def settle_rule_revocations(self, revoked: Iterable[tuple[str, int]]) -> None:
        """One version bump and one event per lifted ban for a batch of
        ``revoke_rule_ban`` outcomes; a batch that lifted nothing does neither."""
        lifted = [(ip, outcome) for ip, outcome in revoked if outcome in _LIFTED]
        if not lifted:
            return
        if self.redis_handler:
            self._bump_ban_version()
            self._forget_shared_state()
        for ip, outcome in lifted if self.agent_handler else ():
            self._send_unban_event(
                ip, _REVOKE_REASON, self._revoke_event_details(ip, outcome)
            )

    def _revoke_event_details(self, ip: str, outcome: int) -> dict[str, Any]:
        if outcome != REVOKE_REWRITTEN:
            return {}
        namespace, key = rule_ban_target(ip)
        if self.redis_handler:
            held = self.redis_handler.get_key(namespace, key)
            expiry = float(held) if held else 0.0
        else:
            expiry = self._live_memory_expiry(namespace, key, time.time()) or 0.0
        return {
            "outcome": "rewritten_to_floor",
            "remaining_seconds": max(0, int(expiry - time.time())),
        }
