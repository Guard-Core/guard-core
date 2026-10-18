import asyncio
import json
import logging
import os
import time
from pathlib import Path
from typing import Any

from guard_core.core.checks.factory import build_default_pipeline
from guard_core.handlers.cloud_handler import CloudManager
from guard_core.handlers.cloud_ip_stores import RedisCloudIpStore
from guard_core.handlers.ipban_handler import IPBanManager, ip_ban_manager
from guard_core.handlers.ratelimit_handler import (
    RateLimitManager,
    RateLimitTier,
    _redis_tier_verdict,
    check_rate_limit_by_ip,
)
from guard_core.handlers.redis_handler import RedisManager
from guard_core.models import SecurityConfig
from guard_core.protocols.response_protocol import GuardResponse

PREFIX = "guard_core_interop:"
RATE_WINDOW = 120
RATE_LIMIT_LOOSE = 10000
BAN_DURATION = 900
NETWORK_DURATION = 900
LEGACY_DURATION = 600
CLOUD_TTL = 3600

PY_BAN_IP = "203.0.113.7"
PY_NET_BAN = "198.51.100.0/24"
PY_NET_PROBE = "198.51.100.55"
LEGACY_MAPPED_IP = "::ffff:203.0.113.9"
LEGACY_CANONICAL_IP = "203.0.113.9"
GO_BAN_IP = "192.0.2.66"
PHP_BAN_IP = "192.0.2.77"
BUCKET_A_IP = "192.0.2.10"
BUCKET_B_IP = "192.0.2.11"
BUCKET_C_IP = "192.0.2.12"
EXEMPT_IP = "192.0.2.30"
EXEMPT_NORMAL_IP = "192.0.2.31"
EXEMPT_BLACK_IP = "192.0.2.32"
EXEMPT_LIMIT = 2
AWS_ENTRIES = {"203.0.113.0/25|us-east-1", "203.0.113.128/25"}
AWS_BLOCKED_PROBE = "203.0.113.200"
AWS_CARVE_PROBE = "203.0.113.5"
GCP_PROBE = "192.0.2.200"
AZURE_PROBE = "198.51.100.200"
AZURE_OTHER_PROBE = "198.51.100.5"

logger = logging.getLogger("interop.py")


class Reporter:
    def __init__(self, participant: str, phase: str) -> None:
        self.participant = participant
        self.phase = phase
        self.passed = 0
        self.failed = 0
        self.checks: list[dict[str, Any]] = []
        self.artifacts: dict[str, str] = {}

    def check(
        self,
        scenario: str,
        direction: str,
        name: str,
        ok: bool,
        detail: str = "",
    ) -> None:
        verdict = "ok" if ok else "FAIL"
        print(f"{verdict} - [{scenario}] {name}" + (f" ({detail})" if detail else ""))
        if ok:
            self.passed += 1
        else:
            self.failed += 1
        self.checks.append(
            {
                "scenario": scenario,
                "direction": direction,
                "name": name,
                "passed": bool(ok),
                "detail": detail,
            }
        )

    def report(self) -> dict[str, Any]:
        return {
            "participant": self.participant,
            "phase": self.phase,
            "passed": self.passed,
            "failed": self.failed,
            "checks": self.checks,
            "artifacts": self.artifacts,
        }


def parse_float(value: str | None) -> float | None:
    if value is None or value == "":
        return None
    try:
        return float(value)
    except ValueError:
        return None


def has_fraction(value: str | None) -> bool:
    if value is None or "." not in value:
        return False
    return value.split(".", 1)[1] != "0"


def make_config(redis_host: str, rate_limit: int) -> SecurityConfig:
    return SecurityConfig(
        redis_url=f"redis://{redis_host}:6379",
        redis_prefix=PREFIX,
        enable_redis=True,
        enable_rate_limiting=True,
        rate_limit=rate_limit,
        rate_limit_window=RATE_WINDOW,
        redis_fail_open=False,
    )


async def phase_py_write(rep: Reporter, redis: RedisManager, redis_host: str) -> None:
    cfg = make_config(redis_host, RATE_LIMIT_LOOSE)
    ban = IPBanManager()
    await ban.initialize_redis(redis)

    banned = await ban.ban_ip(PY_BAN_IP, BAN_DURATION, "interop_py")
    rep.check("exact_ban_write", "py:py", "py bans 203.0.113.7", banned is True)

    py_expiry = await redis.get_key("banned_ips", PY_BAN_IP)
    parsed = parse_float(py_expiry)
    rep.check(
        "float_string_value",
        "py:py",
        "py ban expiry is a parseable float string in the future",
        parsed is not None and parsed > time.time(),
        f"raw={py_expiry!r}",
    )
    rep.check(
        "float_string_noninteger",
        "py:py",
        "py ban expiry carries a non-integer fraction",
        has_fraction(py_expiry),
        f"raw={py_expiry!r}",
    )
    rep.artifacts["py_ban_expiry_raw"] = py_expiry or ""

    self_read = await ban.is_ip_banned(PY_BAN_IP)
    mapped_read = await ban.is_ip_banned("::ffff:203.0.113.7")
    rep.check(
        "exact_ban_read",
        "py:py",
        "py honors its own exact ban",
        self_read is True and mapped_read is True,
    )
    rep.check(
        "canonical_mapped_spelling",
        "py:py",
        "py maps ::ffff:203.0.113.7 onto the canonical ban key",
        mapped_read is True,
    )

    net_banned = await ban.ban_ip(PY_NET_BAN, NETWORK_DURATION, "interop_py")
    net_raw = await redis.get_key("banned_networks", PY_NET_BAN)
    net_parsed = parse_float(net_raw)
    rep.check(
        "network_ban_write",
        "py:py",
        "py bans network 198.51.100.0/24 with a float expiry",
        net_banned is True
        and net_parsed is not None
        and net_parsed > time.time()
        and has_fraction(net_raw),
        f"raw={net_raw!r}",
    )

    legacy_expiry = str(time.time() + LEGACY_DURATION)
    await redis.set_key(
        "banned_ips", LEGACY_MAPPED_IP, legacy_expiry, ttl=LEGACY_DURATION
    )
    legacy_back = await redis.get_key("banned_ips", LEGACY_MAPPED_IP)
    rep.check(
        "legacy_seed",
        "py:py",
        "py seeds the legacy mapped-form ban key",
        legacy_back == legacy_expiry,
        f"raw={legacy_back!r}",
    )
    rep.artifacts["legacy_value_raw"] = legacy_expiry

    hits = [await check_rate_limit_by_ip(BUCKET_A_IP, cfg, redis) for _ in range(3)]
    rep.check(
        "rate_write",
        "py:py",
        "py records 3 hits on bucket A",
        all(hit is True for hit in hits) and len(hits) == 3,
    )

    store = RedisCloudIpStore(redis)
    await store.set("AWS", AWS_ENTRIES, ttl=CLOUD_TTL)
    stored = await store.get("AWS")
    rep.check(
        "cloud_aws_write",
        "py:py",
        "py writes cloud_ip_v2:AWS through the redis store",
        stored == AWS_ENTRIES,
        f"store={sorted(stored) if stored else None}",
    )
    aws_raw = await redis.get_key("cloud_ip_v2", "AWS")
    expected_payload = json.dumps(sorted(AWS_ENTRIES))
    rep.check(
        "cloud_payload_bytes",
        "py:py",
        "py AWS payload equals json.dumps(sorted(entries))",
        aws_raw == expected_payload,
        f"raw={aws_raw!r}",
    )
    rep.artifacts["aws_payload_raw"] = aws_raw or ""


class _StubResponse(GuardResponse):
    """Explicit ``GuardResponse`` implementation over in-memory state."""

    def __init__(self, status_code: int, default_message: str = "") -> None:
        self._status_code = status_code
        self._body = default_message.encode()
        self.headers: dict[str, str] = {}

    @property
    def status_code(self) -> int:
        return self._status_code

    @property
    def body(self) -> bytes | None:
        return self._body

    @body.setter
    def body(self, value: bytes | None) -> None:
        self._body = value if value is not None else b""


class _StubRouteResolver:
    def get_route_config(self, request: Any) -> None:
        return None

    def should_bypass_check(self, *args: Any) -> bool:
        return False

    def get_cloud_providers_to_check(self, route_config: Any) -> None:
        return None


class _StubDecorator:
    """No per-route decorators configured, like a bare deployment."""

    def __init__(self) -> None:
        self._route_configs: dict[str, Any] = {}
        self.route_config_revision = 0


class _StubEventBus:
    async def send_middleware_event(self, **kwargs: Any) -> None:
        return None


class _ExemptMiddleware:
    """Minimal GuardMiddlewareProtocol surface for the real check pipeline.

    Carries the real SecurityConfig (exempt_ips, blacklist, tight rate limit)
    and the real Redis-backed RateLimitManager, so build_default_pipeline
    assembles the engine's actual check list and every drive below runs the
    same code the HTTP pipeline runs.
    """

    def __init__(
        self, config: SecurityConfig, rate_limit_handler: RateLimitManager
    ) -> None:
        self.config = config
        self.logger = logging.getLogger("interop.py.exempt")
        self.rate_limit_handler = rate_limit_handler
        self.suspicious_request_counts: dict[str, dict[str, int]] = {}
        self.last_cloud_ip_refresh = 0
        self.agent_handler = None
        self.geo_ip_handler = None
        self.event_bus = _StubEventBus()
        self.route_resolver = _StubRouteResolver()
        self.guard_decorator = _StubDecorator()

    @property
    def response_factory(self) -> None:
        return None

    @property
    def guard_response_factory(self) -> None:
        return None

    async def create_error_response(
        self, status_code: int, default_message: str
    ) -> _StubResponse:
        return _StubResponse(status_code, default_message)

    async def refresh_cloud_ip_ranges(self) -> None:
        return None


class _PipelineRequest:
    def __init__(self, client_ip: str) -> None:
        self.query_params: dict[str, str] = {}
        self.headers: dict[str, str] = {}
        self.url_path = "/api"
        self.url_full = "http://example.com/api"
        self.url_scheme = "http"
        self.method = "GET"
        self.client_host = client_ip
        self.state = type("State", (), {})()
        self.state.client_ip = client_ip

    async def body(self) -> bytes:
        return b""


def make_exempt_config(redis_host: str, rate_limit: int) -> SecurityConfig:
    return SecurityConfig(
        redis_url=f"redis://{redis_host}:6379",
        redis_prefix=PREFIX,
        enable_redis=True,
        enable_rate_limiting=True,
        rate_limit=rate_limit,
        rate_limit_window=RATE_WINDOW,
        redis_fail_open=False,
        enable_rate_limit_auto_ban=False,
        auto_ban_threshold=1000,
        blacklist=(EXEMPT_BLACK_IP,),
        exempt_ips=(EXEMPT_IP, EXEMPT_BLACK_IP),
    )


async def build_exempt_pipeline(
    redis: RedisManager, redis_host: str, rate_limit: int
) -> Any:
    config = make_exempt_config(redis_host, rate_limit)
    rate_limit_handler = RateLimitManager(config)
    await rate_limit_handler.initialize_redis(redis)
    middleware = _ExemptMiddleware(config, rate_limit_handler)
    return build_default_pipeline(middleware)


async def bucket_count(redis: RedisManager, client_ip: str) -> int:
    async with redis.get_connection() as conn:
        return int(await conn.zcard(f"{PREFIX}rate_limit:rate:{client_ip}"))


async def record_hit_and_count(redis: RedisManager, client_ip: str) -> int:
    tier = RateLimitTier("", RATE_LIMIT_LOOSE, RATE_WINDOW)
    await _redis_tier_verdict(redis, logger, client_ip, [tier], None)
    return await bucket_count(redis, client_ip)


async def phase_py_exempt_write(
    rep: Reporter, redis: RedisManager, redis_host: str, incoming: dict[str, Any]
) -> None:
    del incoming
    await ip_ban_manager.initialize_redis(redis)
    pipeline = await build_exempt_pipeline(redis, redis_host, EXEMPT_LIMIT)

    for _ in range(EXEMPT_LIMIT + 1):
        response = await pipeline.execute(_PipelineRequest(EXEMPT_IP))
    rep.check(
        "exempt_allowed",
        "py:py",
        f"exempt client exceeds the limit "
        f"({EXEMPT_LIMIT + 1} drives) with only normal responses",
        response is None,
        f"last_status={getattr(response, 'status_code', None)}",
    )

    exempt_count = await bucket_count(redis, EXEMPT_IP)
    rep.check(
        "exempt_no_state",
        "py:py",
        "exempt traffic leaves the shared rate bucket empty",
        exempt_count == 0,
        f"zcard={exempt_count}",
    )

    black_request = _PipelineRequest(EXEMPT_BLACK_IP)
    response = await pipeline.execute(black_request)
    rep.check(
        "blacklist_precedence",
        "py:py",
        "blacklisted exempt IP is denied 403 and carries no exempt flag",
        response is not None
        and response.status_code == 403
        and getattr(black_request.state, "is_exempt", None) is False,
        f"status={getattr(response, 'status_code', None)}",
    )
    black_count = await bucket_count(redis, EXEMPT_BLACK_IP)
    rep.check(
        "blacklist_no_state",
        "py:py",
        "the blacklisted exempt IP never reaches the rate limiter",
        black_count == 0,
        f"zcard={black_count}",
    )

    for _ in range(EXEMPT_LIMIT):
        response = await pipeline.execute(_PipelineRequest(EXEMPT_NORMAL_IP))
    rep.check(
        "non_exempt_write",
        "py:py",
        f"non-exempt client passes exactly {EXEMPT_LIMIT} drives under the limit",
        response is None,
        f"last_status={getattr(response, 'status_code', None)}",
    )
    normal_count = await bucket_count(redis, EXEMPT_NORMAL_IP)
    rep.check(
        "non_exempt_write_count",
        "py:py",
        f"non-exempt shared bucket holds exactly {EXEMPT_LIMIT} hits",
        normal_count == EXEMPT_LIMIT,
        f"zcard={normal_count}",
    )
    rep.artifacts["exempt_n_after_py"] = str(normal_count)
    rep.artifacts["exempt_limit"] = str(EXEMPT_LIMIT)


async def phase_py_exempt_verify(
    rep: Reporter, redis: RedisManager, redis_host: str, incoming: dict[str, Any]
) -> None:
    await ip_ban_manager.initialize_redis(redis)

    normal_count = await bucket_count(redis, EXEMPT_NORMAL_IP)
    expected = int(incoming.get("exempt_n_after_php", "-1"))
    rep.check(
        "rate_continuity",
        "py+go+php:py",
        "non-exempt shared bucket holds the php-pinned count",
        normal_count == expected,
        f"zcard={normal_count} expected={expected}",
    )

    pipeline = await build_exempt_pipeline(redis, redis_host, normal_count)
    response = await pipeline.execute(_PipelineRequest(EXEMPT_NORMAL_IP))
    rep.check(
        "rate_blocked_crossing",
        "py+go+php:py",
        f"non-exempt client is blocked 429 at the shared crossing "
        f"(limit {normal_count})",
        response is not None and response.status_code == 429,
        f"status={getattr(response, 'status_code', None)}",
    )
    crossed = await bucket_count(redis, EXEMPT_NORMAL_IP)
    rep.check(
        "rate_blocked_crossing",
        "py+go+php:py",
        "the blocked crossing hit pins the shared count exactly",
        crossed == normal_count + 1,
        f"zcard={crossed}",
    )

    exempt_pipeline = await build_exempt_pipeline(redis, redis_host, EXEMPT_LIMIT)
    exempt_request = _PipelineRequest(EXEMPT_IP)
    response = await exempt_pipeline.execute(exempt_request)
    rep.check(
        "exempt_allowed",
        "py+go+php:py",
        "exempt client still receives a normal response after all writers",
        response is None and getattr(exempt_request.state, "is_exempt", None) is True,
        f"status={getattr(response, 'status_code', None)}",
    )
    exempt_count = await bucket_count(redis, EXEMPT_IP)
    rep.check(
        "exempt_no_state",
        "py+go+php:py",
        "no participant ever wrote the exempt bucket",
        exempt_count == 0,
        f"zcard={exempt_count}",
    )

    black_request = _PipelineRequest(EXEMPT_BLACK_IP)
    response = await exempt_pipeline.execute(black_request)
    rep.check(
        "blacklist_precedence",
        "py+go+php:py",
        "blacklist still beats exemption after all writers",
        response is not None
        and response.status_code == 403
        and getattr(black_request.state, "is_exempt", None) is False,
        f"status={getattr(response, 'status_code', None)}",
    )
    black_count = await bucket_count(redis, EXEMPT_BLACK_IP)
    rep.check(
        "blacklist_no_state",
        "py+go+php:py",
        "the blacklisted exempt bucket stays empty across all participants",
        black_count == 0,
        f"zcard={black_count}",
    )


async def phase_py_verify(
    rep: Reporter, redis: RedisManager, redis_host: str, incoming: dict[str, Any]
) -> None:
    ban = IPBanManager()
    await ban.initialize_redis(redis)

    go_raw = await redis.get_key("banned_ips", GO_BAN_IP)
    go_expiry = parse_float(go_raw)
    rep.check(
        "exact_ban_read",
        "go:py",
        "py honors the go-written ban 192.0.2.66",
        await ban.is_ip_banned(GO_BAN_IP) is True,
    )
    rep.check(
        "float_string_value",
        "go:py",
        "go ban expiry is byte-equal and parses",
        go_raw == incoming.get("go_ban_expiry_raw")
        and go_expiry is not None
        and go_expiry > time.time(),
        f"raw={go_raw!r}",
    )

    php_raw = await redis.get_key("banned_ips", PHP_BAN_IP)
    php_expiry = parse_float(php_raw)
    rep.check(
        "exact_ban_read",
        "php:py",
        "py honors the php-written ban 192.0.2.77",
        await ban.is_ip_banned(PHP_BAN_IP) is True,
    )
    rep.check(
        "float_string_value",
        "php:py",
        "php ban expiry is byte-equal and parses",
        php_raw == incoming.get("php_ban_expiry_raw")
        and php_expiry is not None
        and php_expiry > time.time(),
        f"raw={php_raw!r}",
    )
    rep.check(
        "float_string_noninteger",
        "php:py",
        "php ban expiry carries a non-integer fraction",
        has_fraction(php_raw),
        f"raw={php_raw!r}",
    )

    legacy_banned = await ban.is_ip_banned(LEGACY_CANONICAL_IP)
    legacy_mapped = await ban.is_ip_banned(LEGACY_MAPPED_IP)
    rep.check(
        "legacy_migration_banned",
        "go:py",
        "py honors the post-migration canonical legacy ban",
        legacy_banned is True and legacy_mapped is True,
        f"canonical={legacy_banned} mapped={legacy_mapped}",
    )

    expected = incoming
    count_a = await record_hit_and_count(redis, BUCKET_A_IP)
    rep.check(
        "rate_continuity",
        "py+go+php:py",
        "bucket A shared count reaches 7",
        count_a == expected.get("a_obs"),
        f"observed={count_a} expected={expected.get('a_obs')}",
    )
    blocked = await check_rate_limit_by_ip(
        BUCKET_A_IP, make_config(redis_host, 7), redis
    )
    rep.check(
        "rate_blocked_crossing",
        "py+go+php:py",
        "bucket A is blocked for py at limit 7",
        blocked is False,
    )
    count_b = await record_hit_and_count(redis, BUCKET_B_IP)
    rep.check(
        "rate_continuity",
        "go+php:py",
        "bucket B shared count reaches 4",
        count_b == expected.get("b_obs"),
        f"observed={count_b} expected={expected.get('b_obs')}",
    )
    count_c = await record_hit_and_count(redis, BUCKET_C_IP)
    rep.check(
        "rate_continuity",
        "php:py",
        "bucket C shared count reaches 3",
        count_c == expected.get("c_obs"),
        f"observed={count_c} expected={expected.get('c_obs')}",
    )

    store = RedisCloudIpStore(redis)
    cached = {
        provider: await store.get(provider) for provider in ("AWS", "GCP", "Azure")
    }
    rep.check(
        "cloud_cache_present",
        "go+php:py",
        "all three cloud_ip_v2 caches decode",
        all(value is not None for value in cached.values()),
        f"providers={ {k: (sorted(v) if v else None) for k, v in cached.items()} }",
    )
    if all(value is not None for value in cached.values()):
        manager = CloudManager()
        manager.set_store(store)
        await manager.refresh_async(["AWS", "GCP", "Azure"], ttl=CLOUD_TTL)
        rep.check(
            "cloud_block",
            "py:py",
            "py blocks an AWS IP from its own payload",
            manager.is_cloud_ip(AWS_BLOCKED_PROBE, {"AWS"}) is True,
        )
        rep.check(
            "cloud_carveout",
            "py:py",
            "py honors the AWS us-east-1 carve-out",
            manager.is_cloud_ip(AWS_CARVE_PROBE, {"AWS:!us-east-1"}) is False
            and manager.is_cloud_ip(AWS_CARVE_PROBE, {"AWS"}) is True,
        )
        rep.check(
            "cloud_block",
            "go:py",
            "py blocks a GCP IP from the go-written payload",
            manager.is_cloud_ip(GCP_PROBE, {"GCP"}) is True,
        )
        rep.check(
            "cloud_block",
            "php:py",
            "py blocks an Azure IP from the php-written payload",
            manager.is_cloud_ip(AZURE_PROBE, {"Azure"}) is True
            and manager.is_cloud_ip(AZURE_OTHER_PROBE, {"Azure"}) is True,
        )
        rep.check(
            "cloud_carveout",
            "php:py",
            "py honors the Azure eastus carve-out",
            manager.is_cloud_ip(AZURE_PROBE, {"Azure:!eastus"}) is False,
        )
        for provider, direction, artifact in (
            ("AWS", "py:py", "aws_payload_raw"),
            ("GCP", "go:py", "gcp_payload_raw"),
            ("Azure", "php:py", "azure_payload_raw"),
        ):
            raw_payload = await redis.get_key("cloud_ip_v2", provider)
            reencoded = json.dumps(sorted(cached[provider] or set()))
            rep.check(
                "cloud_payload_bytes",
                direction,
                f"{provider} payload round-trips to Python byte format",
                raw_payload == reencoded == incoming.get(artifact),
                f"raw={raw_payload!r}",
            )

    async with redis.get_connection() as conn:
        bucket_a_key = f"{PREFIX}rate_limit:rate:{BUCKET_A_IP}"
        bucket_pttl = await conn.pttl(bucket_a_key)
        legacy_pttl = await conn.pttl(f"{PREFIX}banned_ips:{LEGACY_CANONICAL_IP}")
        legacy_legacy_pttl = await conn.pttl(f"{PREFIX}banned_ips:{LEGACY_MAPPED_IP}")
    rep.check(
        "ttl_semantics",
        "py:py",
        "bucket A TTL stays within 2x the window",
        0 < bucket_pttl <= RATE_WINDOW * 2 * 1000,
        f"pttl_ms={bucket_pttl}",
    )
    rep.check(
        "legacy_migration_ttl",
        "go:py",
        "migrated canonical ban kept a positive TTL and the legacy key is gone",
        0 < legacy_pttl <= LEGACY_DURATION * 1000 and legacy_legacy_pttl == -2,
        f"canonical_pttl_ms={legacy_pttl} legacy_pttl_ms={legacy_legacy_pttl}",
    )


async def run() -> int:
    phase = os.environ["INTEROP_PHASE"]
    redis_host = os.environ.get("REDIS_HOST", "127.0.0.1")
    incoming = json.loads(os.environ.get("INTEROP_INPUT", "{}"))
    rep = Reporter("python", phase)
    redis = RedisManager(make_config(redis_host, RATE_LIMIT_LOOSE))
    await redis.initialize()
    if phase == "py_write":
        await phase_py_write(rep, redis, redis_host)
    elif phase == "py_verify":
        await phase_py_verify(rep, redis, redis_host, incoming)
    elif phase == "py_exempt_write":
        await phase_py_exempt_write(rep, redis, redis_host, incoming)
    elif phase == "py_exempt_verify":
        await phase_py_exempt_verify(rep, redis, redis_host, incoming)
    else:
        raise SystemExit(f"py_participant does not serve phase {phase!r}")
    write_report(rep)
    return rep.failed


def write_report(rep: Reporter) -> None:
    report_path = os.environ.get("INTEROP_REPORT_FILE")
    if not report_path:
        raise SystemExit("INTEROP_REPORT_FILE is required")
    Path(report_path).write_text(json.dumps(rep.report(), indent=2))
    total = rep.passed + rep.failed
    print(f"\nPassed: {rep.passed}, Failed: {rep.failed}")
    print(f"{rep.passed}/{total}" + (" GREEN" if rep.failed == 0 else " RED"))


def main() -> int:
    logging.basicConfig(
        level=logging.ERROR, format="%(levelname)s %(name)s %(message)s"
    )
    try:
        return asyncio.run(run())
    except Exception as exc:
        logger.error("participant crashed: %r", exc)
        print(f"FAIL - participant crashed: {exc!r}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
