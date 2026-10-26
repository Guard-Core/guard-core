import ipaddress
import logging
import threading
import time
from collections import OrderedDict
from collections.abc import Iterable, MutableMapping

from guard_core.sync._utils.sampling import observe_sampled_key
from guard_core.sync.handlers._ipban_cache import _BanStore, _Network
from guard_core.sync.handlers._ipban_events import IpBanEventMixin
from guard_core.sync.handlers._ipban_rule_exempt import rule_ban_target
from guard_core.sync.handlers._ipban_version import IpBanVersionMixin
from guard_core.sync.protocols.redis_protocol import SyncRedisHandlerProtocol

REVOKE_GONE = 0
REVOKE_DELETED = 1
REVOKE_REWRITTEN = 2
REVOKE_KEPT = 3
_LIFTED = (REVOKE_DELETED, REVOKE_REWRITTEN)
_REVOKE_REASON = "dynamic_rule_revoked"
_RULE_NAMESPACES = ("banned_ips", "banned_networks")
_OWNED_EXPIRY_TOLERANCE = 1e-6
_MAX_OWNER_ANSWERS = 10_000
_ATTRIBUTION_FAILURE_WINDOW_SECONDS = 60
_attribution_failure_lock = threading.Lock()
_attribution_failure_samples: OrderedDict[str, float] = OrderedDict()


def _sample_attribution_failure() -> bool:
    return observe_sampled_key(
        _attribution_failure_samples,
        _attribution_failure_lock,
        "redis",
        window=_ATTRIBUTION_FAILURE_WINDOW_SECONDS,
        max_tracked=1,
    )


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
    redis_handler: SyncRedisHandlerProtocol | None = None
    logger: logging.Logger
    _rule_owned_expiries: dict[str, float]
    _rule_owner_answers: dict[str, tuple[bool, str | None, float]]
    _rule_floor_expiries: dict[str, float]
    _foreign_network_expiries: dict[str, float]
    MAX_LOCAL_BANS: int

    def rule_written_expiry(self, member: str) -> float | None:
        """The expiry this process recorded when a dynamic rule wrote the ban
        under ``member`` (``namespace:key``), for a ban held without Redis."""
        return self._rule_owned_expiries.get(member)

    def forget_rule_written_except(self, members: Iterable[str]) -> None:
        keep = set(members)
        self._rule_owned_expiries = {
            member: expiry
            for member, expiry in self._rule_owned_expiries.items()
            if member in keep
        }

    def answer_stamp(self) -> tuple[str | None, float]:
        """The ban version this worker sees and the time, to date an answer kept
        until ``answer_is_current`` says otherwise."""
        return self._ban_version_seen, time.time()

    def answer_is_current(self, version: str | None, at: float) -> bool:
        return (
            version == self._ban_version_seen
            and time.time() - at < self._VERSION_RECHECK_SECONDS
        )

    def rule_owns_live_ban(self, member: str) -> bool:
        """True when the live ban under ``member`` (``namespace:key``) is the one
        a dynamic rule wrote: the rule owns it, its own expiry has not passed and
        the live ban is not longer than that expiry (a longer ban written over it
        is another source's). Redis answers from the shared owned set and the
        stored ban, so every worker gives the same verdict, whatever its local
        cache holds; without Redis the same test runs on this process's record.

        A Redis answer is kept per member until the ban version this worker
        sees changes or ``_VERSION_RECHECK_SECONDS`` pass (an exact-address rule
        write or a longer foreign write does not move the version), so a flood
        from one banned address reads Redis once per interval, in one round
        trip."""
        namespace, _, key = member.partition(":")
        now = time.time()
        if not self.redis_handler:
            return self._owns_live_ban(
                self.rule_written_expiry(member),
                self._live_memory_expiry(namespace, key, now),
                now,
            )
        held = self._rule_owner_answers.get(member)
        if (
            held is not None
            and held[1] == self._ban_version_seen
            and now - held[2] < self._VERSION_RECHECK_SECONDS
        ):
            return held[0]
        try:
            owned, live = self.redis_handler.owned_ban_state(namespace, key)
            verdict = self._owns_live_ban(owned, live, now)
        except Exception as error:
            verdict = False
            if _sample_attribution_failure():
                self.logger.warning("Ban attribution skipped, Redis failed: %s", error)
        if len(self._rule_owner_answers) >= _MAX_OWNER_ANSWERS:
            self._rule_owner_answers.clear()
        self._rule_owner_answers[member] = (verdict, self._ban_version_seen, now)
        return verdict

    @staticmethod
    def _owns_live_ban(owned: float | None, live: float | None, now: float) -> bool:
        return (
            owned is not None
            and live is not None
            and owned > now
            and live <= owned + _OWNED_EXPIRY_TOLERANCE
        )

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
        agent_handler = self.agent_handler
        if not agent_handler:
            return
        for ip, outcome in lifted:
            self._send_unban_event(
                agent_handler,
                ip,
                _REVOKE_REASON,
                self._revoke_event_details(ip, outcome),
            )

    def _revoke_event_details(self, ip: str, outcome: int) -> dict[str, object]:
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
