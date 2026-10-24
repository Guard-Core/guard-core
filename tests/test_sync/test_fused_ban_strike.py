import logging
import time
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from redis.connection import Connection

from guard_core.exceptions import GuardRedisError
from guard_core.models import SyncSecurityConfig
from guard_core.sync.core.checks._pending_ban import resolve_pending_ban
from guard_core.sync.core.checks.implementations.ip_security import IpSecurityCheck
from guard_core.sync.decorators.base import RouteConfig
from guard_core.sync.handlers.ipban_handler import IPBanManager
from guard_core.sync.handlers.redis_handler import RedisManager
from tests.test_sync.conftest import REDIS_URL

BLACKLISTED = "198.51.100.21"
BLACKLISTED_TWIN = "198.51.100.22"
CLEAN = "203.0.113.9"
CLEAN_TWIN = "203.0.113.10"
TWINS = {BLACKLISTED: BLACKLISTED_TWIN, CLEAN: CLEAN_TWIN}
VERSION = ("ban_version", "counter")


class _Rig:
    def __init__(self, threshold: int, **overrides: Any) -> None:
        fields: dict[str, Any] = dict(
            enable_redis=True,
            redis_url=REDIS_URL,
            redis_prefix=f"test:wp56:{uuid.uuid4().hex}:",
            blacklist=[BLACKLISTED, BLACKLISTED_TWIN],
            auto_ban_threshold=threshold,
            auto_ban_duration=300,
            enable_penetration_detection=False,
            enable_rate_limiting=False,
            ban_on_hostile_signals=True,
        )
        fields.update(overrides)
        self.config = SyncSecurityConfig(**fields)
        self.redis = RedisManager(self.config)
        self.round_trips = 0
        self.counting = True
        self.commands: list[str] = []
        self.events: list[tuple[str, str | None]] = []

    def start(self) -> None:
        self.redis.initialize()
        self.manager = IPBanManager()
        self.manager.redis_handler = None
        self.manager.reset()
        self.manager.config = self.config
        self.manager.initialize_redis(self.redis)
        middleware = MagicMock()
        middleware.config = self.config
        middleware.logger = logging.getLogger("wp56")
        middleware.suspicious_request_counts = {}
        middleware.rate_limit_handler.redis_handler = self.redis
        middleware.geo_ip_handler = None
        middleware.route_resolver.should_bypass_check = lambda *_: False
        middleware.create_error_response = MagicMock(
            return_value=MagicMock(status_code=403)
        )

        def record(**kwargs: Any) -> None:
            self.events.append((kwargs["event_type"], kwargs.get("filter_type")))

        middleware.event_bus.send_middleware_event = record
        middleware.event_bus.agent_handler = None
        self.check = IpSecurityCheck(middleware)
        for module in ("implementations.ip_security", "helpers"):
            patch(f"guard_core.sync.core.checks.{module}.log_activity").start()
        self.check.ip_ban_manager = self.manager

    def request(
        self,
        ip: str,
        route_config: RouteConfig | None = None,
        exclusion_scoped: bool = False,
    ) -> int | None:
        request = MagicMock()
        request.state.client_ip = ip
        request.state.is_whitelisted = False
        request.state.is_exempt = False
        request.state.route_config = route_config
        request.state.guard_exclusion_scoped = exclusion_scoped
        request.headers = {}
        response = self.check.check(request)
        if response is None:
            response = resolve_pending_ban(request)
        return None if response is None else int(response.status_code)

    def state(self) -> dict[str, Any]:
        self.counting = False
        try:
            return self._read_state()
        finally:
            self.counting = True

    def _read_state(self) -> dict[str, Any]:
        prefix = self.config.redis_prefix
        found: dict[str, Any] = {}
        with self.redis.get_connection() as conn:
            for key in sorted(conn.keys(f"{prefix}*")):
                name = key[len(prefix) :]
                kind = conn.type(key)
                if kind == "zset":
                    found[name] = ("zset", conn.zcard(key))
                elif kind == "set":
                    found[name] = ("set", sorted(conn.smembers(key)))
                elif name.startswith("banned_ips:"):
                    found[name] = ("ban", float(conn.get(key)) > time.time())
                else:
                    found[name] = (kind, conn.get(key))
        found.pop("whitelist:strikes_applied", None)
        return found

    def stop(self) -> None:
        patch.stopall()
        self.manager.redis_handler = self.redis
        self.manager.reset()
        self.manager.redis_handler = None
        self.redis.delete_pattern("*")
        self.redis.close()


def _command_of(packed: Any) -> str:
    chunk = packed[0] if isinstance(packed, list) else packed
    return str(chunk.split(b"\r\n")[2].decode())


_HANDSHAKE = frozenset({"HELLO", "CLIENT", "SELECT", "AUTH"})


_ACTIVE: list[_Rig] = []


@pytest.fixture(autouse=True)
def count_redis_round_trips(monkeypatch: pytest.MonkeyPatch) -> None:
    real = Connection.send_packed_command

    def counted(connection: Connection, command: Any, *rest: Any, **kw: Any) -> Any:
        name = _command_of(command)
        if name not in _HANDSHAKE:
            for rig in _ACTIVE:
                rig.round_trips += rig.counting
                rig.commands.append(name)
        return real(connection, command, *rest, **kw)

    monkeypatch.setattr(Connection, "send_packed_command", counted)


@contextmanager
def _rig(threshold: int, **overrides: Any) -> Iterator[_Rig]:
    rig = _Rig(threshold, **overrides)
    rig.start()
    _ACTIVE.append(rig)
    try:
        yield rig
    finally:
        _ACTIVE.remove(rig)
        rig.stop()


def _without_ip(value: Any, ip: str) -> Any:
    return (value[0], str(value[1]).replace(ip, "IP"))


def _banned(rig: _Rig, ip: str) -> bool | str:
    try:
        return rig.manager.is_ip_banned(ip)
    except GuardRedisError:
        return "GuardRedisError"


def _outcome(rig: _Rig, ip: str, **request_state: Any) -> Any:
    try:
        return rig.request(ip, **request_state)
    except GuardRedisError:
        return "GuardRedisError"


def _observed(
    rig: _Rig, ip: str, requests: int, **request_state: Any
) -> dict[str, Any]:
    first_event = len(rig.events)
    codes = [_outcome(rig, ip, **request_state) for _ in range(requests)]
    state = rig.state()
    return {
        "codes": codes,
        "banned": _banned(rig, ip),
        "events": rig.events[first_event:],
        "local_counts": dict(
            rig.check.middleware.suspicious_request_counts.get(ip, {})
        ),
        "redis": {
            name.replace(ip, "IP"): _without_ip(value, ip)
            for name, value in state.items()
            if ip in name or ":" not in name or "detection" in name and ip in name
        },
    }


def _route(fields: dict[str, Any]) -> RouteConfig:
    route_config = RouteConfig()
    for name, value in fields.items():
        setattr(route_config, name, value)
    return route_config


def _never_planned(*_args: Any, **_kwargs: Any) -> tuple[None, bool]:
    return None, False


def _fused_and_separate(
    monkeypatch: pytest.MonkeyPatch,
    ip: str,
    threshold: int = 3,
    config: dict[str, Any] | None = None,
    route: dict[str, Any] | None = None,
    **request_state: Any,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """The same requests from two addresses of one list, the second with the
    fused lookup switched off (the two separate calls of 49493c30)."""
    with _rig(threshold, **(config or {})) as rig:
        route_config = _route(route) if route else None
        fused = _observed(rig, ip, 6, route_config=route_config, **request_state)
        monkeypatch.setattr(IpSecurityCheck, "_plan_ban_read", _never_planned, False)
        separate = _observed(
            rig, TWINS[ip], 6, route_config=route_config, **request_state
        )
    return fused, separate


@pytest.mark.parametrize("threshold", [3, 10**6])
@pytest.mark.parametrize("ip", [BLACKLISTED, CLEAN])
def test_the_fused_lookup_leaves_every_observable_as_the_two_calls_did(
    monkeypatch: pytest.MonkeyPatch, threshold: int, ip: str
) -> None:
    fused, separate = _fused_and_separate(monkeypatch, ip, threshold)

    assert fused == separate


@pytest.mark.parametrize(
    "route",
    [
        {"ip_whitelist": ["10.0.0.1"]},
        {"ip_blacklist": [BLACKLISTED, BLACKLISTED_TWIN]},
        {"ip_whitelist": [BLACKLISTED, BLACKLISTED_TWIN]},
    ],
)
def test_a_route_denial_keeps_the_routes_strike_category(
    monkeypatch: pytest.MonkeyPatch, route: dict[str, Any]
) -> None:
    fused, separate = _fused_and_separate(monkeypatch, BLACKLISTED, route=route)

    assert fused == separate


def test_a_route_whitelist_miss_counts_nothing_even_when_globally_blacklisted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fused, _ = _fused_and_separate(
        monkeypatch, BLACKLISTED, route={"ip_whitelist": ["10.0.0.1"]}
    )

    assert not [key for key in fused["redis"] if "detection" in key]


@pytest.mark.parametrize(
    "config", [{"passive_mode": True}, {"enable_ip_banning": False}]
)
def test_a_denial_that_counts_nothing_stays_unfused(
    monkeypatch: pytest.MonkeyPatch, config: dict[str, Any]
) -> None:
    fused, separate = _fused_and_separate(monkeypatch, BLACKLISTED, config=config)

    assert fused == separate
    assert not [key for key in fused["redis"] if "detection" in key]


def test_the_exclusion_scoped_path_stays_unfused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fused, separate = _fused_and_separate(
        monkeypatch, BLACKLISTED, exclusion_scoped=True
    )

    assert fused == separate
    assert not [key for key in fused["redis"] if "detection" in key]


def test_banned_and_blacklisted_gets_the_ban_response_and_no_strike() -> None:
    with _rig(10**6) as rig:
        rig.manager.ban_ip(BLACKLISTED, 300)

        assert rig.request(BLACKLISTED) == 403
        assert rig.events == [("ip_blocked", "banned")]
        assert not [key for key in rig.state() if "detection:" in key]


@pytest.mark.parametrize("fail_open", [True, False])
@pytest.mark.parametrize("ip", [BLACKLISTED, CLEAN])
def test_a_redis_that_drops_the_lookup_fails_as_the_two_calls_did(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    fail_open: bool,
    ip: str,
) -> None:
    real = Connection.send_packed_command

    def dropping(connection: Connection, command: Any, *rest: Any, **kw: Any) -> Any:
        if _command_of(command) in ("EVALSHA", "MGET"):
            raise ConnectionError("dropped")
        return real(connection, command, *rest, **kw)

    results = []
    for fused in (True, False):
        with _rig(3, redis_fail_open=fail_open) as rig:
            if not fused:
                monkeypatch.setattr(
                    IpSecurityCheck,
                    "_plan_ban_read",
                    _never_planned,
                    False,
                )
            monkeypatch.setattr(Connection, "send_packed_command", dropping)
            caplog.clear()
            observed = _observed(rig, ip, 3)
            observed["logs"] = [
                (record.levelname, record.getMessage().replace(ip, "IP"))
                for record in caplog.records
                if record.name.startswith("guard_core")
            ]
            observed.pop("redis")
            results.append(observed)
            monkeypatch.undo()
            monkeypatch.setattr(Connection, "send_packed_command", real)

    assert results[0] == results[1]


def test_a_blocked_request_makes_one_round_trip() -> None:
    with _rig(10**6) as rig:
        rig.request(BLACKLISTED)
        rig.round_trips = 0
        rig.commands.clear()

        assert rig.request(BLACKLISTED) == 403
        assert rig.round_trips == 1, rig.commands


def test_a_clean_request_makes_one_round_trip_and_no_strike() -> None:
    with _rig(10**6) as rig:
        rig.request(CLEAN_TWIN)
        rig.round_trips = 0
        rig.commands.clear()

        assert rig.request(CLEAN) is None
        assert rig.round_trips == 1, rig.commands
        assert not [key for key in rig.state() if "detection:" in key]


def test_a_banned_client_records_no_strike() -> None:
    with _rig(10**6) as rig:
        rig.manager.ban_ip(BLACKLISTED, 300)
        rig.manager.banned_ips.clear()
        rig.round_trips = 0
        rig.commands.clear()

        assert rig.request(BLACKLISTED) == 403
        assert not [key for key in rig.state() if "detection:" in key]
        assert rig.events == [("ip_blocked", "banned")]


def test_a_flushed_script_cache_still_blocks_and_records_the_strike() -> None:
    with _rig(10**6) as rig:
        with rig.redis.get_connection() as conn:
            conn.script_flush()

        assert rig.request(BLACKLISTED) == 403
        state = rig.state()
        assert state[f"detection:strikes:{BLACKLISTED}"] == ("zset", 1)


def test_a_moved_ban_version_records_no_strike_in_the_lookup() -> None:
    with _rig(10**6) as rig:
        now = time.time()
        values, recorded = rig.redis.get_bans_and_record_strike(
            [("banned_ips", BLACKLISTED)],
            VERSION,
            "41",
            now,
            BLACKLISTED,
            ("ip_list",),
            now,
            now - 3600,
            3600,
            1000,
        )

        assert values == [None, None]
        assert recorded is None
        assert not [key for key in rig.state() if "detection:" in key]


def test_the_lookup_returns_what_get_many_returns() -> None:
    with _rig(10**6) as rig:
        rig.redis.set_key("banned_ips", BLACKLISTED, str(time.time() - 5), 60)
        now = time.time()
        pairs = [("banned_ips", BLACKLISTED), ("banned_identities", "x")]
        expected = rig.redis.get_many([*pairs, VERSION])

        values, recorded = rig.redis.get_bans_and_record_strike(
            pairs,
            VERSION,
            None,
            now,
            BLACKLISTED,
            ("ip_list",),
            now,
            now - 3600,
            3600,
            9,
        )

        assert values == expected
        assert recorded == (1, 0, {"ip_list": 1})


def test_a_seen_version_and_no_ban_values_return_the_short_reply() -> None:
    with _rig(10**6) as rig:
        now = time.time()
        values, recorded = rig.redis.get_bans_and_record_strike(
            [("banned_ips", BLACKLISTED)],
            VERSION,
            "0",
            now,
            BLACKLISTED,
            ("ip_list",),
            now,
            now - 3600,
            3600,
            9,
        )

        assert values == [None, "0"]
        assert recorded == (1, 0, {"ip_list": 1})
