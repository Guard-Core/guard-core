import time
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from redis.asyncio.connection import Connection

from guard_core.core.checks._ban_flow import BanFlow
from guard_core.core.checks.base import SecurityCheck
from guard_core.core.checks.implementations.authentication import AuthenticationCheck
from guard_core.core.checks.implementations.cors_preflight import CorsPreflightCheck
from guard_core.core.checks.implementations.ip_security import IpSecurityCheck
from guard_core.core.checks.implementations.rate_limit import RateLimitCheck
from guard_core.core.checks.implementations.referrer import ReferrerCheck
from guard_core.core.checks.implementations.required_headers import (
    RequiredHeadersCheck,
)
from guard_core.core.checks.implementations.user_agent import UserAgentCheck
from guard_core.core.checks.pipeline import SecurityCheckPipeline
from guard_core.decorators.base import RouteConfig
from guard_core.exceptions import GuardRedisError
from guard_core.handlers.ipban_handler import IPBanManager
from guard_core.handlers.ratelimit_handler import RateLimitManager
from guard_core.handlers.redis_handler import RedisManager
from guard_core.models import SecurityConfig
from tests.conftest import REDIS_URL

CLIENT = "198.51.100.31"
TWIN = "198.51.100.32"
BAD_AGENT = "badbot/1.0"


class _Probe(SecurityCheck):
    """A check that is not defer-safe: it records whether a ban read was pending."""

    def __init__(self, middleware: Any, seen: list[bool]) -> None:
        super().__init__(middleware)
        self.seen = seen

    @property
    def check_name(self) -> str:
        return "probe"

    async def check(self, request: Any) -> None:
        flow = getattr(request.state, "guard_ban_flow", None)
        self.seen.append(isinstance(flow, BanFlow) and flow.pending is not None)


class _Rig:
    def __init__(self, **overrides: Any) -> None:
        fields: dict[str, Any] = dict(
            enable_redis=True,
            redis_url=REDIS_URL,
            redis_prefix=f"test:wp56d:{uuid.uuid4().hex}:",
            blocked_user_agents=["badbot"],
            auto_ban_threshold=10**6,
            enable_penetration_detection=False,
            enable_rate_limiting=True,
            rate_limit=3,
            rate_limit_window=60,
            ban_on_hostile_signals=True,
        )
        fields.update(overrides)
        self.config = SecurityConfig(**fields)
        self.redis = RedisManager(self.config)
        self.events: list[tuple[Any, Any]] = []
        self.round_trips = 0
        self.counting = True
        self.commands: list[str] = []
        self.bypassed: set[str] = set()

    async def start(self, extra_checks: bool = False) -> None:
        await self.redis.initialize()
        self.manager = IPBanManager()
        self.manager.redis_handler = None
        await self.manager.reset()
        self.manager.config = self.config
        await self.manager.initialize_redis(self.redis)
        self.limiter = RateLimitManager(self.config)
        await self.limiter.initialize_redis(self.redis)
        middleware = MagicMock()
        middleware.config = self.config
        middleware.logger = __import__("logging").getLogger("wp56d")
        middleware.suspicious_request_counts = {}
        middleware.rate_limit_handler = self.limiter
        middleware.geo_ip_handler = None
        middleware.route_resolver.should_bypass_check = lambda name, *_: (
            name in self.bypassed
        )
        middleware.event_bus.agent_handler = None

        async def create_error_response(status_code: int, default_message: str) -> Any:
            return SimpleNamespace(status_code=status_code, headers={})

        middleware.create_error_response = create_error_response

        async def record(**kwargs: Any) -> None:
            self.events.append((kwargs["event_type"], kwargs.get("filter_type")))

        middleware.event_bus.send_middleware_event = record
        self.middleware = middleware
        self.seen: list[bool] = []
        checks: list[SecurityCheck] = [
            IpSecurityCheck(middleware),
            UserAgentCheck(middleware),
            CorsPreflightCheck(middleware),
            RateLimitCheck(middleware),
            RequiredHeadersCheck(middleware),
            AuthenticationCheck(middleware),
            ReferrerCheck(middleware),
        ]
        for check in checks:
            check.ip_ban_manager = self.manager
        if extra_checks:
            checks.insert(1, _Probe(middleware, self.seen))
        self.pipeline = SecurityCheckPipeline(checks)

    async def request(
        self,
        ip: str,
        agent: str = "curl/8",
        method: str = "GET",
        forwarded: str | None = None,
        route: dict[str, Any] | None = None,
        extra_headers: dict[str, str] | None = None,
        exclusion_scoped: bool = False,
        whitelisted: bool = False,
    ) -> int | None:
        request = MagicMock()
        request.state.client_ip = ip
        request.state.route_config = _route(route) if route else None
        request.state.is_whitelisted = whitelisted
        request.state.whitelist_entry = None
        request.state.is_exempt = False
        request.state.guard_exclusion_scoped = exclusion_scoped
        request.state.untrusted_forwarded_for = forwarded
        headers = {"User-Agent": agent, **(extra_headers or {})}
        if method == "OPTIONS":
            headers["Access-Control-Request-Method"] = "GET"
        request.headers = SimpleNamespace(
            get=lambda name, default="": {k.lower(): v for k, v in headers.items()}.get(
                name.lower(), default
            ),
            keys=lambda: list(headers),
            __contains__=lambda name: name in headers,
        )
        request.method = method
        request.url_path = "/x"
        try:
            response = await self.pipeline.execute(request)
        except GuardRedisError:
            return -1
        return None if response is None else int(response.status_code)

    async def state(self) -> dict[str, Any]:
        self.counting = False
        try:
            prefix = self.config.redis_prefix
            found: dict[str, Any] = {}
            async with self.redis.get_connection() as conn:
                for key in sorted(await conn.keys(f"{prefix}*")):
                    name = key[len(prefix) :]
                    kind = await conn.type(key)
                    if kind == "zset":
                        found[name] = ("zset", await conn.zcard(key))
                    elif name.startswith("banned_ips:"):
                        found[name] = ("ban", True)
                    elif kind == "set":
                        found[name] = ("set", len(await conn.smembers(key)))
                    else:
                        found[name] = (kind, await conn.get(key))
            for ignored in ("whitelist:strikes_applied", "config:ipv6_prefix_length"):
                found.pop(ignored, None)
            return found
        finally:
            self.counting = True

    async def ban_in_redis_only(self, ip: str) -> None:
        await self.redis.set_key("banned_ips", ip, str(time.time() + 300), 300)
        self.manager.banned_ips.clear()

    async def stop(self) -> None:
        patch.stopall()
        self.manager.redis_handler = self.redis
        await self.manager.reset()
        self.manager.redis_handler = None
        await self.redis.delete_pattern("*")
        await self.redis.close()


async def _never_planned(*_args: Any, **_kwargs: Any) -> tuple[None, bool]:
    return None, False


def _route(fields: dict[str, Any]) -> RouteConfig:
    route_config = RouteConfig()
    for name, value in fields.items():
        setattr(route_config, name, value)
    return route_config


def _command_of(packed: Any) -> str:
    chunk = packed[0] if isinstance(packed, list) else packed
    return str(chunk.split(b"\r\n")[2].decode())


_HANDSHAKE = frozenset({"HELLO", "CLIENT", "SELECT", "AUTH"})


_ACTIVE: list[_Rig] = []


@pytest.fixture(autouse=True)
def count_redis_round_trips(monkeypatch: pytest.MonkeyPatch) -> None:
    real = Connection.send_packed_command

    async def counted(
        connection: Connection, command: Any, *rest: Any, **kw: Any
    ) -> Any:
        name = _command_of(command)
        if name not in _HANDSHAKE:
            for rig in _ACTIVE:
                rig.round_trips += rig.counting
                rig.commands.append(name)
        return await real(connection, command, *rest, **kw)

    monkeypatch.setattr(Connection, "send_packed_command", counted)


@asynccontextmanager
async def _rig(extra_checks: bool = False, **overrides: Any) -> AsyncIterator[_Rig]:
    rig = _Rig(**overrides)
    await rig.start(extra_checks)
    for module in (
        "implementations.ip_security",
        "implementations.user_agent",
        "implementations.required_headers",
        "implementations.referrer",
        "implementations.authentication",
        "helpers",
    ):
        patch(f"guard_core.core.checks.{module}.log_activity", new=AsyncMock()).start()
    patch("guard_core.handlers.ratelimit_handler.log_activity", new=AsyncMock()).start()
    _ACTIVE.append(rig)
    try:
        yield rig
    finally:
        _ACTIVE.remove(rig)
        await rig.stop()


def _normalized(state: dict[str, Any], ip: str) -> dict[str, Any]:
    return {
        name.replace(ip, "IP"): value for name, value in state.items() if ip in name
    }


async def _observe(
    rig: _Rig, ip: str, requests: list[dict[str, Any]]
) -> dict[str, Any]:
    first = len(rig.events)
    codes = [await rig.request(ip, **request) for request in requests]
    return {
        "codes": codes,
        "events": rig.events[first:],
        "redis": _normalized(await rig.state(), ip),
    }


async def _deferred_and_not(
    monkeypatch: pytest.MonkeyPatch,
    requests: list[dict[str, Any]],
    prepare_banned: bool = False,
    **overrides: Any,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """The same requests from two addresses, the second with the deferral
    switched off (the lookup read at IpSecurity as at 30602dc2)."""
    async with _rig(**overrides) as rig:
        if prepare_banned:
            await rig.ban_in_redis_only(CLIENT)
        deferred = await _observe(rig, CLIENT, requests)
        monkeypatch.setattr(IpSecurityCheck, "_plan_ban_read", _never_planned, False)
        if prepare_banned:
            await rig.ban_in_redis_only(TWIN)
        immediate = await _observe(rig, TWIN, requests)
    return deferred, immediate


_SCENARIOS: dict[str, list[dict[str, Any]]] = {
    "blocked_user_agent": [{"agent": BAD_AGENT}] * 4,
    "clean_rate_limited": [{}] * 6,
    "preflight": [{"method": "OPTIONS"}] * 3,
    "mixed": [{}, {"agent": BAD_AGENT}, {"method": "OPTIONS"}, {}, {}, {}],
    "spoofing": [{"forwarded": "10.0.0.1"}] * 4,
    "spoofing_and_blocked_agent": [{"forwarded": "10.0.0.1", "agent": BAD_AGENT}] * 3,
}


@pytest.mark.parametrize("scenario", sorted(_SCENARIOS))
@pytest.mark.parametrize("banned", [False, True])
async def test_deferring_the_ban_read_changes_no_observable(
    monkeypatch: pytest.MonkeyPatch, scenario: str, banned: bool
) -> None:
    deferred, immediate = await _deferred_and_not(
        monkeypatch,
        _SCENARIOS[scenario],
        prepare_banned=banned,
        trusted_proxies=["10.0.0.1"],
    )

    assert deferred == immediate


@pytest.mark.parametrize("scenario", sorted(_SCENARIOS))
async def test_a_redis_only_ban_gets_the_banned_response_and_touches_nothing(
    scenario: str,
) -> None:
    async with _rig() as rig:
        await rig.ban_in_redis_only(CLIENT)

        codes = [await rig.request(CLIENT, **r) for r in _SCENARIOS[scenario]]

        assert set(codes) == {403}
        assert set(rig.events) == {("ip_blocked", "banned")}
        assert [key for key in await rig.state() if key != f"banned_ips:{CLIENT}"] == []


async def test_a_clean_rate_limited_request_makes_one_round_trip() -> None:
    async with _rig() as rig:
        await rig.request(CLIENT)
        rig.round_trips = 0
        rig.commands.clear()

        assert await rig.request(CLIENT) is None
        assert rig.round_trips == 1, rig.commands


async def test_a_user_agent_blocked_request_makes_one_round_trip() -> None:
    async with _rig() as rig:
        await rig.request(CLIENT, agent=BAD_AGENT)
        rig.round_trips = 0
        rig.commands.clear()

        assert await rig.request(CLIENT, agent=BAD_AGENT) == 403
        assert rig.round_trips == 1, rig.commands


async def test_a_banned_client_is_never_rate_limited_or_counted() -> None:
    async with _rig(rate_limit=1) as rig:
        await rig.ban_in_redis_only(CLIENT)

        codes = [await rig.request(CLIENT) for _ in range(5)]

        assert codes == [403] * 5
        assert not [key for key in await rig.state() if "rate_limit" in key]


async def test_no_check_outside_the_allow_list_runs_with_a_pending_read() -> None:
    async with _rig(extra_checks=True) as rig:
        await rig.request(CLIENT)
        await rig.request(CLIENT, agent=BAD_AGENT)

        assert rig.seen == [False, False]


@pytest.mark.parametrize("fail_open", [True, False])
@pytest.mark.parametrize("scenario", ["blocked_user_agent", "clean_rate_limited"])
async def test_a_redis_that_drops_the_fused_script_fails_as_before(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    fail_open: bool,
    scenario: str,
) -> None:
    real = Connection.send_packed_command

    async def dropping(
        connection: Connection, command: Any, *rest: Any, **kw: Any
    ) -> Any:
        if _command_of(command) in ("EVALSHA", "MGET"):
            raise ConnectionError("dropped")
        return await real(connection, command, *rest, **kw)

    results = []
    for deferred in (True, False):
        async with _rig(redis_fail_open=fail_open) as rig:
            if not deferred:
                monkeypatch.setattr(
                    IpSecurityCheck,
                    "_plan_ban_read",
                    _never_planned,
                    False,
                )
            monkeypatch.setattr(Connection, "send_packed_command", dropping)
            caplog.clear()
            observed = await _observe(rig, CLIENT, _SCENARIOS[scenario][:3])
            observed.pop("redis")
            observed["logs"] = [
                record.levelname
                for record in caplog.records
                if record.name.startswith("guard_core")
            ]
            results.append(observed)
            monkeypatch.undo()
            monkeypatch.setattr(Connection, "send_packed_command", real)

    assert results[0]["codes"] == results[1]["codes"]
    assert results[0]["events"] == results[1]["events"]


async def test_a_spoofing_request_reads_the_ban_once_and_strikes_in_that_read() -> None:
    async with _rig(trusted_proxies=["10.0.0.1"], enable_rate_limiting=False) as rig:
        await rig.request(CLIENT, forwarded="10.0.0.1")
        rig.round_trips = 0
        rig.commands.clear()

        assert await rig.request(CLIENT, forwarded="10.0.0.1") is None
        assert rig.round_trips == 1, rig.commands
        state = await rig.state()
        assert state[f"detection:strikes:{CLIENT}|ip_spoofing"] == ("zset", 2)


async def test_a_ban_made_earlier_in_the_request_stops_the_spoofing_strike() -> None:
    async with _rig(
        trusted_proxies=["10.0.0.1"],
        blocked_user_agents=[],
        blacklist=[CLIENT],
        auto_ban_threshold=1,
    ) as rig:
        assert await rig.request(CLIENT, forwarded="10.0.0.1") == 403

        state = await rig.state()
        assert f"banned_ips:{CLIENT}" in state
        assert not [key for key in state if key.endswith("ip_spoofing")]


@pytest.mark.parametrize("banned", [False, True])
@pytest.mark.parametrize(
    "overrides",
    [
        {"passive_mode": True},
        {"whitelist": [CLIENT, TWIN], "whitelist_access_only": False},
        {"exempt_ips": [CLIENT, TWIN]},
        {"enable_rate_limiting": False},
        {"enable_ip_banning": False},
        {"ban_on_hostile_signals": False},
    ],
    ids=["passive", "whitelisted", "exempt", "no_rate_limit", "no_banning", "flag_off"],
)
async def test_the_same_requests_give_the_same_result_under_each_mode(
    monkeypatch: pytest.MonkeyPatch, overrides: dict[str, Any], banned: bool
) -> None:
    deferred, immediate = await _deferred_and_not(
        monkeypatch,
        _SCENARIOS["mixed"] + _SCENARIOS["blocked_user_agent"],
        prepare_banned=banned,
        **overrides,
    )

    assert deferred == immediate


_GROUP_B: dict[str, dict[str, Any]] = {
    "required_header": {"route": {"required_headers": {"X-Req": "required"}}},
    "referrer": {"route": {"require_referrer": ["https://ok.example"]}},
    "authorization_header": {"route": {"authorization_header_required": "bearer"}},
    "bearer_without_credential": {"route": {"auth_required": "bearer"}},
}


@pytest.mark.parametrize("banned", [False, True])
@pytest.mark.parametrize("name", sorted(_GROUP_B))
async def test_group_b_denials_are_the_same_deferred_or_immediate(
    monkeypatch: pytest.MonkeyPatch, name: str, banned: bool
) -> None:
    """Ten requests: the first three are denied by the check, the rest cross the
    rate limit (3 per window), so both the 429 and the denial are covered, and a
    request that satisfies the check passes."""
    denied = [dict(_GROUP_B[name])] * 6
    passing = {
        "required_header": {"extra_headers": {"X-Req": "1"}},
        "referrer": {"extra_headers": {"Referer": "https://ok.example/x"}},
        "authorization_header": {"extra_headers": {"authorization": "Bearer t"}},
        "bearer_without_credential": {"extra_headers": {"authorization": "Bearer t"}},
    }[name]
    allowed = [{**_GROUP_B[name], **passing}]
    deferred, immediate = await _deferred_and_not(
        monkeypatch, denied + allowed, prepare_banned=banned
    )

    assert deferred == immediate


@pytest.mark.parametrize("name", sorted(_GROUP_B))
async def test_a_group_b_denial_makes_one_redis_command(name: str) -> None:
    async with _rig() as rig:
        await rig.request(CLIENT, **_GROUP_B[name])
        rig.round_trips = 0
        rig.commands.clear()

        code = await rig.request(CLIENT, **_GROUP_B[name])
        assert code is not None and code in (400, 401, 403)
        assert rig.round_trips == 1, rig.commands


async def test_a_banned_client_gets_the_banned_response_before_any_group_b_denial() -> (
    None
):
    async with _rig(rate_limit=1) as rig:
        await rig.ban_in_redis_only(CLIENT)

        codes = [await rig.request(CLIENT, **_GROUP_B["referrer"]) for _ in range(3)]

        assert codes == [403] * 3
        assert set(rig.events) == {("ip_blocked", "banned")}
        state = await rig.state()
        assert not [key for key in state if "rate_limit" in key or "detection" in key]


async def test_a_rate_limited_client_missing_a_header_gets_the_429() -> None:
    async with _rig(rate_limit=1) as rig:
        await rig.request(CLIENT, **_GROUP_B["required_header"])

        assert await rig.request(CLIENT, **_GROUP_B["required_header"]) == 429


@pytest.mark.parametrize("fail_open", [True, False])
@pytest.mark.parametrize("name", ["required_header", "referrer"])
async def test_a_redis_that_drops_the_group_b_script_fails_as_before(
    monkeypatch: pytest.MonkeyPatch,
    fail_open: bool,
    name: str,
) -> None:
    real = Connection.send_packed_command

    async def dropping(
        connection: Connection, command: Any, *rest: Any, **kw: Any
    ) -> Any:
        if _command_of(command) in ("EVALSHA", "MGET"):
            raise ConnectionError("dropped")
        return await real(connection, command, *rest, **kw)

    results = []
    for deferred in (True, False):
        async with _rig(redis_fail_open=fail_open) as rig:
            if not deferred:
                monkeypatch.setattr(
                    IpSecurityCheck,
                    "_plan_ban_read",
                    _never_planned,
                    False,
                )
            monkeypatch.setattr(Connection, "send_packed_command", dropping)
            observed = await _observe(rig, CLIENT, [_GROUP_B[name]] * 3)
            observed.pop("redis")
            results.append(observed)
            monkeypatch.undo()
            monkeypatch.setattr(Connection, "send_packed_command", real)

    assert results[0]["codes"] == results[1]["codes"]
    assert results[0]["events"] == results[1]["events"]


async def test_passive_mode_and_exclusion_scoped_requests_do_not_defer_the_count(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for overrides in ({"passive_mode": True}, {}):
        scoped = overrides == {}
        deferred, immediate = await _deferred_and_not(
            monkeypatch,
            [{**_GROUP_B["referrer"], "exclusion_scoped": scoped}] * 4,
            **overrides,
        )
        monkeypatch.undo()
        assert deferred == immediate


async def test_a_failed_ban_read_is_logged_under_the_ip_check(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    real = Connection.send_packed_command

    async def dropping(
        connection: Connection, command: Any, *rest: Any, **kw: Any
    ) -> Any:
        if _command_of(command) in ("EVALSHA", "MGET"):
            raise ConnectionError("dropped")
        return await real(connection, command, *rest, **kw)

    async with _rig(rate_limit=100, enable_rate_limiting=False) as rig:
        monkeypatch.setattr(Connection, "send_packed_command", dropping)
        caplog.clear()

        assert await rig.request(CLIENT, agent=BAD_AGENT) == 500

        messages = [
            r.getMessage() for r in caplog.records if "security check" in r.getMessage()
        ]
        assert any("ip_security" in message for message in messages), messages
        assert not any("user_agent" in message for message in messages), messages


async def test_unknown_and_country_ruled_clients_read_the_ban_at_the_ip_check() -> None:
    async with _rig() as rig:
        assert await rig.request("unknown") is None
        assert rig.round_trips >= 1
    async with _rig() as rig:
        assert await rig.request(CLIENT, route={"blocked_countries": ["XX"]}) is None
        assert rig.commands.count("MGET") == 1


async def test_a_bypassed_ip_check_still_defers_the_ban_read() -> None:
    async with _rig() as rig:
        rig.bypassed.add("ip")
        assert await rig.request(CLIENT, route={"required_headers": {}}) is None
        assert rig.commands.count("EVALSHA") == 1


async def test_a_whitelisted_route_denial_reads_the_ban_without_a_strike() -> None:
    async with _rig() as rig:
        assert (
            await rig.request(
                CLIENT, route={"ip_blacklist": [CLIENT]}, whitelisted=True
            )
            == 403
        )
        assert not [key for key in await rig.state() if "detection:" in key]


async def test_a_pending_read_resolves_before_a_check_that_cannot_wait() -> None:
    async with _rig(extra_checks=True) as rig:
        await rig.ban_in_redis_only(CLIENT)

        assert await rig.request(CLIENT) == 403
        assert rig.seen == []


async def test_the_spoofing_second_read_without_a_first_one_asks_the_manager() -> None:
    async with _rig(trusted_proxies=["10.0.0.1"]) as rig:
        check = rig.pipeline.checks[0]
        assert isinstance(check, IpSecurityCheck)
        request = MagicMock()
        request.state.guard_ban_flow = BanFlow()
        manager = MagicMock()
        manager.is_ip_banned = AsyncMock(return_value=True)
        check.ip_ban_manager = manager

        assert await check._banned_at_spoofing(request, CLIENT) is True


async def test_a_banned_client_never_reaches_the_verifier() -> None:
    verifier = AsyncMock(return_value=True)
    async with _rig() as rig:
        await rig.ban_in_redis_only(CLIENT)
        route = {"auth_required": "bearer", "auth_verifier": verifier}

        code = await rig.request(
            CLIENT, route=route, extra_headers={"authorization": "Bearer t"}
        )

        assert code == 403
        verifier.assert_not_awaited()


@pytest.mark.parametrize(
    "headers", [{}, {"Referer": "https://bad.example/"}], ids=["missing", "invalid"]
)
async def test_a_banned_client_gets_the_banned_response_at_a_referrer_denial(
    headers: dict[str, str],
) -> None:
    async with _rig() as rig:
        await rig.ban_in_redis_only(CLIENT)

        assert (
            await rig.request(
                CLIENT, route=_GROUP_B["referrer"]["route"], extra_headers=headers
            )
            == 403
        )
        assert set(rig.events) == {("ip_blocked", "banned")}


async def test_a_banned_client_gets_the_banned_response_at_a_cloud_denial(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from guard_core.core.checks.implementations.cloud_provider import (
        CloudProviderCheck,
    )

    middleware = MagicMock()
    middleware.route_resolver.should_bypass_check = lambda *_: False
    middleware.route_resolver.get_cloud_providers_to_check = lambda _route: ["AWS"]
    check = CloudProviderCheck(middleware)
    check.cloud_handler = MagicMock(is_cloud_ip=lambda *_: True)
    banned_response = object()
    monkeypatch.setattr(
        "guard_core.core.checks.implementations.cloud_provider.resolve_pending_ban",
        AsyncMock(return_value=banned_response),
    )
    request = MagicMock()
    request.state.client_ip = CLIENT
    request.state.is_whitelisted = False
    request.state.is_exempt = False
    request.state.route_config = None

    assert await check.check(request) is banned_response


async def test_an_ipv6_client_is_counted_by_its_prefix_in_the_one_script() -> None:
    async with _rig(rate_limit=2) as rig:
        codes = [await rig.request("2001:db8::5") for _ in range(4)]

        assert codes == [None, None, 429, 429]
        state = await rig.state()
        assert any("rate_limit:rate:2001:db8::" in key for key in state)


def test_with_the_flag_off_no_source_is_fed_before_rate_limiting() -> None:
    from guard_core.core.initialization import _ban_threshold_report as report

    config = SecurityConfig(
        enable_redis=False,
        rate_limit=1,
        blacklist=["198.51.100.1"],
        ban_on_hostile_signals=False,
        auto_ban_threshold=10**6,
    )

    problems = report.unreachable_ban_threshold_problems(
        config, report._BanThresholdContext(lambda: [], lambda: False)
    )

    assert any("auto_ban_threshold" in problem for problem in problems)


def test_the_route_config_of_the_spoofing_check_is_the_given_one_or_the_states() -> (
    None
):
    state = MagicMock()
    state.route_config = "from the state"
    given = RouteConfig()

    assert IpSecurityCheck._route_config_of(state, given) is given
    assert IpSecurityCheck._route_config_of(state, None) == "from the state"


async def test_the_rate_limit_skip_reads_the_state_itself_when_it_is_not_given() -> (
    None
):
    async with _rig() as rig:
        check = next(c for c in rig.pipeline.checks if isinstance(c, RateLimitCheck))
        request = MagicMock()
        request.state.is_whitelisted = True
        request.state.is_exempt = False
        request.method = "GET"

        assert check._skips_rate_limiting(request, None) is True
