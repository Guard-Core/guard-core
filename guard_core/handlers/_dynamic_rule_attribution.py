import ipaddress
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from guard_core._dynamic_rules import DynamicRules
from guard_core._security_config_field_validators import (
    canonicalize_cloud_provider_selector,
)
from guard_core._utils.access_control import _ip_in_list
from guard_core.handlers._cloud_provider_registry import _parse_cloud_selectors
from guard_core.handlers._ipban_rule_exempt import rule_ban_member

MATCHED_RULE_TYPE_DYNAMIC = "dynamic"
_MAX_BAN_STAMPS = 10_000

_Selectors = tuple[frozenset[str], Mapping[str, frozenset[str]]]


def _selectors(selectors: Iterable[Any]) -> _Selectors:
    canonical = {
        name
        for name in map(canonicalize_cloud_provider_selector, selectors)
        if name is not None
    }
    blocked, carveouts = _parse_cloud_selectors(canonical)
    return frozenset(blocked), {
        provider: frozenset(regions) for provider, regions in carveouts.items()
    }


def _selectors_block(selectors: _Selectors, provider: str, region: str | None) -> bool:
    blocked, carveouts = selectors
    if provider not in blocked:
        return False
    return not (region is not None and region in carveouts.get(provider, ()))


def _limit_pair(value: Any) -> tuple[Any, ...]:
    return tuple(value)


def _listed_ban_members(listed: Sequence[str]) -> frozenset[str]:
    members: set[str] = set()
    for entry in listed:
        try:
            members.add(rule_ban_member(entry))
        except ValueError:
            continue
    return frozenset(members)


@dataclass(frozen=True)
class RuleAttribution:
    """What the applied dynamic rule set owns, derived once per set.

    Every method answers for one kind of deciding entry and returns the event
    metadata to attach: empty when the rule did not decide, the type and id
    when it did, plus the overlap flag when the static configuration or a
    built-in entry would have decided the same way.
    """

    rule_id: str
    config: Any
    listed_ban_members: frozenset[str]
    blocked_countries: frozenset[str]
    static_blocked_countries: frozenset[str]
    whitelist_countries_in_force: bool
    static_whitelist_countries: frozenset[str]
    cloud_selectors: _Selectors
    static_cloud_selectors: _Selectors
    user_agents: frozenset[str]
    static_user_agents: frozenset[str]
    patterns: frozenset[str]
    owned_patterns: frozenset[str]
    global_rate: tuple[int, int | None] | None
    static_global_rate: tuple[Any, Any]
    endpoint_limits: Mapping[str, tuple[Any, ...]]
    static_endpoint_limits: Mapping[str, tuple[Any, ...]]
    emergency: bool
    static_emergency: bool
    _ban_stamps: dict[str, tuple[dict[str, Any], str | None, float]] = field(
        default_factory=dict, repr=False, compare=False
    )

    @property
    def owned_ban_members(self) -> frozenset[str]:
        """The ban entries the rule lists; Redis (or this process) says which of
        them it owns at the moment a ban answers."""
        return self.listed_ban_members

    @property
    def ban_networks(self) -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]:
        """The addresses and networks the rule owns bans on."""
        return tuple(
            ipaddress.ip_network(member.partition(":")[2], strict=False)
            for member in sorted(self.listed_ban_members)
        )

    @property
    def cloud_providers(self) -> frozenset[str]:
        """The provider names the rule blocks, carve-outs aside."""
        return self.cloud_selectors[0]

    @property
    def static_cloud_providers(self) -> frozenset[str]:
        """The provider names the static configuration blocks, carve-outs aside."""
        return self.static_cloud_selectors[0]

    def _stamp(self, overlaps_static: bool) -> dict[str, Any]:
        stamp: dict[str, Any] = {
            "matched_rule_type": MATCHED_RULE_TYPE_DYNAMIC,
            "matched_rule_id": self.rule_id,
        }
        if overlaps_static:
            stamp["matched_rule_overlaps_static"] = True
        return stamp

    async def for_ban(self, client_ip: str, bans: Any) -> dict[str, Any]:
        """The stamp of a ban hit, kept per address while the ban version this
        worker sees is unchanged and the ban lookup's own recheck interval has
        not passed, so a repeat hit from one banned address is one dict read.
        The version and the time are read before the stamp is worked out, so a
        stamp is never kept under a version newer than the one it was computed
        under."""
        held = self._ban_stamps.get(client_ip)
        if held is not None and bans.answer_is_current(held[1], held[2]):
            return held[0]
        version, at = bans.answer_stamp()
        stamp = await self._ban_stamp(client_ip, bans)
        if len(self._ban_stamps) >= _MAX_BAN_STAMPS:
            self._ban_stamps.clear()
        self._ban_stamps[client_ip] = (stamp, version, at)
        return stamp

    async def _ban_stamp(self, client_ip: str, bans: Any) -> dict[str, Any]:
        entry = bans.deciding_ban_entry(client_ip)
        if entry is None or entry[0] not in self.listed_ban_members:
            return {}
        if not await bans.rule_owns_live_ban(entry[0]):
            return {}
        try:
            address = ipaddress.ip_address(client_ip)
        except ValueError:
            return self._stamp(False)
        return self._stamp(_ip_in_list(address, client_ip, self.config.blacklist))

    def for_country(
        self, country_rule: str | None, country: str | None
    ) -> dict[str, Any]:
        if country_rule == "country_blacklist":
            if country not in self.blocked_countries:
                return {}
            return self._stamp(country in self.static_blocked_countries)
        if country_rule == "country_whitelist" and self.whitelist_countries_in_force:
            return self._stamp(
                bool(self.static_whitelist_countries)
                and country not in self.static_whitelist_countries
            )
        return {}

    def for_cloud_provider(self, provider: str, region: str | None) -> dict[str, Any]:
        if not _selectors_block(self.cloud_selectors, provider, region):
            return {}
        return self._stamp(
            _selectors_block(self.static_cloud_selectors, provider, region)
        )

    def for_user_agent_pattern(self, pattern: str | None) -> dict[str, Any]:
        if pattern is None or pattern not in self.user_agents:
            return {}
        return self._stamp(pattern in self.static_user_agents)

    def for_rate_limit_tier(self, kind: str, bucket: str) -> dict[str, Any]:
        if kind == "global" and self.global_rate is not None:
            limit, window = self.global_rate
            static_limit, static_window = self.static_global_rate
            return self._stamp(
                static_limit == limit and window in (None, static_window)
            )
        if kind == "endpoint" and bucket in self.endpoint_limits:
            return self._stamp(
                self.static_endpoint_limits.get(bucket) == self.endpoint_limits[bucket]
            )
        return {}

    def for_emergency_mode(self) -> dict[str, Any]:
        if not self.emergency:
            return {}
        return self._stamp(self.static_emergency)

    def for_pattern(self, source: str | None) -> dict[str, Any]:
        if source is None or source not in self.patterns:
            return {}
        return self._stamp(source not in self.owned_patterns)


def build_rule_attribution(
    rules: DynamicRules,
    config: Any,
    owned_bans: Sequence[str],
    owned_patterns: Sequence[str],
    base: Mapping[str, Any],
) -> RuleAttribution:
    static_endpoint_limits = base.get("endpoint_rate_limits") or {}
    return RuleAttribution(
        rule_id=str(rules.rule_id),
        config=config,
        listed_ban_members=_listed_ban_members(rules.ip_blacklist),
        blocked_countries=frozenset(code.upper() for code in rules.blocked_countries),
        static_blocked_countries=frozenset(base.get("blocked_countries") or ()),
        whitelist_countries_in_force=bool(rules.whitelist_countries),
        static_whitelist_countries=frozenset(base.get("whitelist_countries") or ()),
        cloud_selectors=_selectors(rules.blocked_cloud_providers),
        static_cloud_selectors=_selectors(base.get("block_cloud_providers") or ()),
        user_agents=frozenset(rules.blocked_user_agents),
        static_user_agents=frozenset(base.get("blocked_user_agents") or ()),
        patterns=frozenset(rules.suspicious_patterns),
        owned_patterns=frozenset(owned_patterns),
        global_rate=(
            (rules.global_rate_limit, rules.global_rate_window)
            if rules.global_rate_limit
            else None
        ),
        static_global_rate=(base.get("rate_limit"), base.get("rate_limit_window")),
        endpoint_limits={
            key: _limit_pair(value) for key, value in rules.endpoint_rate_limits.items()
        },
        static_endpoint_limits={
            key: _limit_pair(value) for key, value in static_endpoint_limits.items()
        },
        emergency=bool(rules.emergency_mode),
        static_emergency=bool(base.get("emergency_mode")),
    )
