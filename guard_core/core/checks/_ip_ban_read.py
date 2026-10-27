from abc import abstractmethod
from ipaddress import ip_address
from typing import NamedTuple

from guard_core._utils.ip_extraction import UNKNOWN_CLIENT_IDENTITY, _parsed_ip_or_none
from guard_core._utils.nat64 import DEFAULT_NAT64_TABLE, Nat64Table, nat64_table_of
from guard_core.core.checks._ban_flow import NO_BAN_FLOW, BanFlow
from guard_core.core.checks._pending_ban import PendingBan
from guard_core.core.checks._shared_strikes import FusedStrike, _shared_strikes_redis
from guard_core.core.checks._strike_counts import _strike_identity
from guard_core.core.checks.base import SecurityCheck
from guard_core.core.checks.helpers import (
    SUSPICIOUS_COUNT_WINDOW_SECONDS,
    _retained_strike_cap,
    check_route_ip_access,
)
from guard_core.decorators.base import RouteConfig
from guard_core.exceptions import GuardRedisError
from guard_core.handlers._ipban_lookup import PendingKeysRead
from guard_core.handlers.ipban_handler import IPBanManager
from guard_core.protocols.request_protocol import GuardRequest
from guard_core.protocols.response_protocol import GuardResponse
from guard_core.utils import _ip_in_list, allow_list_miss_category, check_ip_access


def _route_blacklist_matches(
    route_config: RouteConfig, client_ip: str, nat64: Nat64Table = DEFAULT_NAT64_TABLE
) -> bool:
    try:
        return _ip_in_list(
            ip_address(client_ip), client_ip, route_config.ip_blacklist or [], nat64
        )
    except ValueError:
        return False


def _route_denial_category(
    route_config: RouteConfig,
    decorator_type: str,
    client_ip: str,
    nat64: Nat64Table = DEFAULT_NAT64_TABLE,
) -> str | None:
    if decorator_type == "block_countries":
        return "country"
    if decorator_type == "allow_countries":
        return allow_list_miss_category("country")
    if route_config.ip_whitelist:
        return allow_list_miss_category("ip_list")
    return (
        "ip_list" if _route_blacklist_matches(route_config, client_ip, nat64) else None
    )


def _route_overrides_ip_lists(route_config: RouteConfig | None) -> bool:
    return bool(route_config and route_config.ip_whitelist)


class _ListVerdict(NamedTuple):
    category: str | None
    decidable: bool


class IpBanReadMixin(SecurityCheck):
    """The ban read of the IP check: when it is issued, what rides in its round
    trip, and the resolution of a read a later check needed first."""

    @abstractmethod
    async def banned_response(
        self, request: GuardRequest, client_ip: str
    ) -> GuardResponse | None: ...

    def _strike_gates_open(
        self, state: object, whitelisted_counts_nothing: bool
    ) -> bool:
        """The conditions under which ``count_hostile_signal_and_maybe_ban``
        records a strike, and the strike goes to the Redis the ban manager reads."""
        config = self.config
        if (
            config.passive_mode
            or not config.ban_on_hostile_signals
            or not config.enable_ip_banning
            or (whitelisted_counts_nothing and getattr(state, "is_whitelisted", False))
        ):
            return False
        redis_handler = _shared_strikes_redis(self.middleware)
        return (
            redis_handler is not None
            and redis_handler is self.ip_ban_manager.redis_handler
        )

    def _country_rules_apply(self, route_config: RouteConfig | None) -> bool:
        config = self.config
        return bool(
            config.blocked_countries
            or config.whitelist_countries
            or (
                route_config
                and (route_config.blocked_countries or route_config.whitelist_countries)
            )
        )

    def _lists_cannot_decide(
        self, client_ip: str, route_config: RouteConfig | None
    ) -> bool:
        return (
            client_ip == UNKNOWN_CLIENT_IDENTITY
            or _parsed_ip_or_none(client_ip) is None
            or self._country_rules_apply(route_config)
        )

    async def _static_denial_verdict(
        self, state: object, client_ip: str, route_config: RouteConfig | None
    ) -> _ListVerdict:
        """What the IP lists decide for this client, in the order the check
        applies them (the route's lists, then the global ones), without a country
        lookup: the category of a denial, none for an allow, and whether the lists
        alone decide (no country rule, a parsable address)."""
        if self._lists_cannot_decide(client_ip, route_config):
            return _ListVerdict(None, False)
        if route_config is None and not (
            self.config.blacklist or self.config.whitelist
        ):
            return _ListVerdict(None, True)
        route_denial = await self._route_list_denial(state, client_ip, route_config)
        if route_denial is not None:
            return route_denial
        result = await check_ip_access(
            client_ip,
            self.config,
            None,
            skip_whitelist=_route_overrides_ip_lists(route_config),
            skip_countries=True,
            skip_clouds=True,
        )
        if result.allowed:
            return _ListVerdict(None, True)
        flow = getattr(state, "guard_ban_flow", None)
        if not isinstance(flow, BanFlow):
            raise AttributeError(NO_BAN_FLOW)
        flow.denied_access = (result, False, False)
        return _ListVerdict(result.denial_category, True)

    async def _route_list_denial(
        self, state: object, client_ip: str, route_config: RouteConfig | None
    ) -> _ListVerdict | None:
        if not route_config or (
            await check_route_ip_access(
                client_ip, route_config, self.middleware, nat64_table_of(self.config)
            )
            is not False
        ):
            return None
        if getattr(state, "is_whitelisted", False):
            return _ListVerdict(None, False)
        category = _route_denial_category(
            route_config, "access_control", client_ip, nat64_table_of(self.config)
        )
        return _ListVerdict(category, True)

    def _fused_strike_for(
        self, state: object, client_ip: str, category: str
    ) -> FusedStrike:
        strike = FusedStrike(
            _strike_identity(self.config, client_ip),
            category,
            SUSPICIOUS_COUNT_WINDOW_SECONDS,
            _retained_strike_cap(self.config),
        )
        flow = getattr(state, "guard_ban_flow", None)
        if not isinstance(flow, BanFlow):
            raise AttributeError(NO_BAN_FLOW)
        flow.fused = strike
        return strike

    def warn_ban_lookup_skipped(self, client_ip: str) -> None:
        self.logger.warning(
            "Redis unavailable: ban lookup skipped for %s, the IP lists "
            "still apply (redis_fail_open=True)",
            client_ip,
        )

    def _ban_lookup_lost(self, client_ip: str) -> bool:
        if not self.config.redis_fail_open:
            raise
        self.warn_ban_lookup_skipped(client_ip)
        return False

    @staticmethod
    def _route_config_of(
        state: object, given: RouteConfig | None
    ) -> RouteConfig | None:
        if given is not None:
            return given
        found: RouteConfig | None = getattr(state, "route_config", None)
        return found

    def strike_for(
        self, request: GuardRequest, client_ip: str, category: str | None
    ) -> FusedStrike | None:
        state = request.state
        if category is None or not self._strike_gates_open(state, True):
            return None
        return self._fused_strike_for(state, client_ip, category)

    async def resolve_ban_read(
        self, request: GuardRequest, pending: PendingBan, category: str | None
    ) -> GuardResponse | None:
        """Read the ban a check left pending, recording the strike of ``category``
        (when it is certain) in the same round trip. The banned client gets the
        banned response; the resolving check's own side effects never run."""
        state = request.state
        strike = (
            self._fused_strike_for(state, pending.client_ip, category)
            if category is not None and self._strike_gates_open(state, True)
            else None
        )

        async def fused_strike() -> FusedStrike | None:
            return strike

        try:
            banned = await self.ip_ban_manager.finish_ban_check(
                pending.read, fused_strike
            )
        except GuardRedisError:
            banned = self._ban_lookup_lost(pending.client_ip)
        if banned:
            return await self.banned_response(request, pending.client_ip)
        return None

    async def _plan_ban_read(
        self, state: object, client_ip: str, route_config: RouteConfig | None
    ) -> tuple[FusedStrike | None, bool]:
        """What to do with a ban read only Redis can decide: the strike that rides
        in it when the IP lists deny the client, and whether to leave it pending
        (the lists allow, no country rule applies, not passive mode)."""
        config = self.config
        if config.passive_mode or getattr(state, "guard_exclusion_scoped", False):
            return None, False
        if self.middleware.route_resolver.should_bypass_check("ip", route_config):
            return None, True
        verdict = await self._static_denial_verdict(state, client_ip, route_config)
        if verdict.category is None:
            return None, verdict.decidable
        if not self._strike_gates_open(state, False):
            return None, False
        return self._fused_strike_for(state, client_ip, verdict.category), False

    async def _check_banned_ip(
        self, request: GuardRequest, client_ip: str, route_config: RouteConfig | None
    ) -> GuardResponse | None:
        if self.middleware.route_resolver.should_bypass_check("ip_ban", route_config):
            return None
        plan: list[tuple[FusedStrike | None, bool]] = []
        state = request.state
        flow = BanFlow()
        state.guard_ban_flow = flow

        async def defer(read: PendingKeysRead) -> bool:
            plan.append(await self._plan_ban_read(state, client_ip, route_config))
            if plan[0][1]:
                flow.pending = PendingBan(self, client_ip, read)
            return plan[0][1]

        async def strike() -> FusedStrike | None:
            return plan[0][0] if plan else None

        try:
            banned = await self.ip_ban_manager.is_ip_banned(client_ip, strike, defer)
        except GuardRedisError:
            banned = self._ban_lookup_lost(client_ip)
        flow.read_done = True
        if not banned:
            return None
        return await self.banned_response(request, client_ip)

    async def _banned_at_spoofing(self, request: GuardRequest, client_ip: str) -> bool:
        """The second ban read of the spoofing signal: the request's own result
        when this request already read the ban (a ban made earlier in the request
        is held locally), a lookup otherwise."""
        manager = self.ip_ban_manager
        flow = getattr(request.state, "guard_ban_flow", None)
        if (
            isinstance(flow, BanFlow)
            and flow.read_done
            and isinstance(manager, IPBanManager)
        ):
            return await manager.begin_ban_check(client_ip) is True
        return bool(await manager.is_ip_banned(client_ip))
