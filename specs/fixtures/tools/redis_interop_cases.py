"""Redis interop cases for the guard-core conformance corpus.

Byte-level pins of the reference engine's on-the-wire Redis surface per
specs/08-redis-schema.md: one operation per key family, driven through the
REAL guard-core handlers pointed at the suite Redis under the dedicated
prefix ``REDIS_PREFIX``. Every expected record is captured by executing the
operation and then scanning the prefix, so the pinned key strings, value
bytes, zset shapes and TTL semantics are observations of the live engine -
never hand-written.

Pinning rules (see also the suite doc block):
- keys: the exact full key string (sha256hex segments per spec);
- static string/JSON values: the exact stored bytes;
- engine-generated values (ban expiry floats, epoch zset members, uuid4
  members): the value SHAPE as a regular expression;
- TTLs: whether one is set and its configured value, never the remaining
  seconds.

Go, PHP, TS and Rust ports pointed at the same Redis MUST produce
byte-identical results.
"""

from __future__ import annotations

import ipaddress
import json
import re
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pipeline_harness import _PipelineRequest, _StubResponse

from guard_core.handlers.behavior_handler import BehaviorRule, BehaviorTracker
from guard_core.handlers.cloud_handler import cloud_handler
from guard_core.handlers.cloud_ip_stores import RedisCloudIpStore
from guard_core.handlers.dynamic_rule_handler import DynamicRuleManager
from guard_core.handlers.ipban_handler import ip_ban_manager, reset_global_state
from guard_core.handlers.ipinfo_handler import IPInfoManager
from guard_core.handlers.ratelimit_handler import RateLimitManager
from guard_core.handlers.redis_handler import RedisManager
from guard_core.handlers.security_headers_handler import security_headers_manager
from guard_core.handlers.suspatterns_handler import sus_patterns_handler
from guard_core.models import DynamicRules, SecurityConfig

REDIS_PREFIX = "guard_core:corpus_rio:"
REDIS_URL = "redis://localhost:6379/0"
RIO_IP = "203.0.113.20"

_NUMERIC_SHAPE = r"^[0-9]+\.[0-9]+(e[+-]?[0-9]+)?$"
_UUID4_HEX_SHAPE = r"^[0-9a-f]{32}$"

FAKE_MMDB_BYTES = b"corpus-mmdb-fixture:\xe9\xff\x00\x80:end"

FIXED_CSP_CONFIG = {
    "default-src": ["'self'"],
    "script-src": ["'self'", "https://cdn.example.com"],
}
FIXED_HSTS_CONFIG = {"max_age": 31536000, "include_subdomains": True}
FIXED_CUSTOM_HEADERS = {"X-Corpus-Header": "corpus-value"}
FIXED_CLOUD_RANGES = ["198.51.100.0/24", "203.0.113.0/24"]
FIXED_CLOUD_REGIONS = {"203.0.113.0/24": "us-east"}
FIXED_CLOUD_STORE_RANGES = ["10.0.0.0/8", "192.168.0.0/16", "2001:db8::/32"]

REDIS_SUITES: dict[str, list[dict[str, Any]]] = {}

REDIS_SUITES["redis_interop"] = [
    {
        "id": "rio_rate_limit_global_tier",
        "operation": {
            "op": "rate_limit",
            "handler": "ratelimit_handler.RateLimitManager",
            "call": "check_rate_limit (Lua path, global tier)",
            "args": {"client_ip": RIO_IP, "rate_limit": 5, "rate_limit_window": 60},
        },
    },
    {
        "id": "rio_rate_limit_endpoint_tier",
        "operation": {
            "op": "rate_limit",
            "handler": "ratelimit_handler.RateLimitManager",
            "call": "check_rate_limit (Lua path, endpoint tier)",
            "args": {
                "client_ip": RIO_IP,
                "rate_limit": 5,
                "rate_limit_window": 60,
                "endpoint_path": "/api",
            },
        },
    },
    {
        "id": "rio_ban_exact_ip",
        "operation": {
            "op": "ban_ip",
            "handler": "ipban_handler.ip_ban_manager",
            "call": "ban_ip",
            "args": {"ip": "203.0.113.21", "duration": 3600, "reason": "rio_ban"},
        },
    },
    {
        "id": "rio_ban_cidr_network",
        "operation": {
            "op": "ban_ip",
            "handler": "ipban_handler.ip_ban_manager",
            "call": "ban_ip",
            "args": {"ip": "10.0.0.0/24", "duration": 1800, "reason": "rio_ban"},
        },
    },
    {
        "id": "rio_behavior_usage_increment",
        "operation": {
            "op": "behavior_usage",
            "handler": "behavior_handler.BehaviorTracker",
            "call": "track_endpoint_usage",
            "args": {
                "endpoint_id": "corpus.endpoint",
                "client_ip": RIO_IP,
                "rule": {"rule_type": "usage", "threshold": 5, "window": 120},
            },
        },
    },
    {
        "id": "rio_behavior_return_increment",
        "operation": {
            "op": "behavior_return",
            "handler": "behavior_handler.BehaviorTracker",
            "call": "track_return_pattern",
            "args": {
                "endpoint_id": "corpus.endpoint",
                "client_ip": RIO_IP,
                "rule": {
                    "rule_type": "return_pattern",
                    "threshold": 3,
                    "window": 120,
                    "pattern": "status:404",
                },
                "response_status": 404,
            },
        },
    },
    {
        "id": "rio_security_headers_csp_config",
        "operation": {
            "op": "security_headers",
            "handler": "security_headers_handler.security_headers_manager",
            "call": "initialize_redis (_cache_configuration, csp only)",
            "args": {"csp_config": FIXED_CSP_CONFIG},
        },
    },
    {
        "id": "rio_security_headers_hsts_config",
        "operation": {
            "op": "security_headers",
            "handler": "security_headers_handler.security_headers_manager",
            "call": "initialize_redis (_cache_configuration, hsts only)",
            "args": {"hsts_config": FIXED_HSTS_CONFIG},
        },
    },
    {
        "id": "rio_security_headers_custom_headers",
        "operation": {
            "op": "security_headers",
            "handler": "security_headers_handler.security_headers_manager",
            "call": "initialize_redis (_cache_configuration, custom only)",
            "args": {"custom_headers": FIXED_CUSTOM_HEADERS},
        },
    },
    {
        "id": "rio_custom_pattern_registry_write",
        "operation": {
            "op": "add_pattern",
            "handler": "suspatterns_handler.sus_patterns_handler",
            "call": "add_pattern (custom)",
            "args": {"pattern": "corpuspattern-[a-z]+"},
        },
    },
    {
        "id": "rio_ipinfo_database_cache_write",
        "operation": {
            "op": "ipinfo_database",
            "handler": "ipinfo_handler.IPInfoManager",
            "call": "initialize (download cache write, fetched bytes pinned)",
            "args": {"max_age": 86400, "fixture": "corpus-mmdb-fixture"},
        },
    },
    {
        "id": "rio_cloud_ranges_v2_write",
        "operation": {
            "op": "cloud_ranges",
            "handler": "cloud_handler.cloud_handler",
            "call": "refresh_async (redis-handler path, fetched ranges pinned)",
            "args": {
                "provider": "corpus",
                "ranges": FIXED_CLOUD_RANGES,
                "regions": FIXED_CLOUD_REGIONS,
                "ttl": 3600,
            },
        },
    },
    {
        "id": "rio_cloud_ip_v2_write",
        "operation": {
            "op": "cloud_ip_store",
            "handler": "cloud_ip_stores.RedisCloudIpStore",
            "call": "set (persist)",
            "args": {
                "provider": "corpus",
                "ranges": FIXED_CLOUD_STORE_RANGES,
                "ttl": None,
            },
        },
    },
    {
        "id": "rio_dynamic_rules_snapshot_write",
        "operation": {
            "op": "dynamic_rules",
            "handler": "dynamic_rule_handler.DynamicRuleManager",
            "call": "update_rules (_persist_last_known_rules)",
            "args": {
                "rules": {
                    "rule_id": "rio-rules",
                    "version": 3,
                    "timestamp": "2026-01-01T00:00:00+00:00",
                }
            },
        },
    },
]


# ---- value/TTL probes ----


async def _connect() -> Any:
    import redis.asyncio as aredis

    client = aredis.from_url(REDIS_URL, decode_responses=True)
    await client.ping()
    return client


async def _flush_prefix(client: Any) -> None:
    keys = await client.keys(f"{REDIS_PREFIX}*")
    if keys:
        await client.delete(*keys)


async def _redis_manager(config: SecurityConfig) -> RedisManager:
    RedisManager._instance = None  # noqa: SLF001 - corpus reset
    manager = RedisManager(config)
    await manager.initialize()
    return manager


def _parse_json(value: str) -> Any:
    try:
        parsed = json.loads(value)
    except (TypeError, ValueError):
        return None
    return parsed if isinstance(parsed, (dict, list)) else None


async def _probe_key(client: Any, key: str) -> dict[str, Any]:
    key_type = await client.type(key)
    ttl_seconds = await client.ttl(key)
    if ttl_seconds > 0:
        ttl: dict[str, Any] = {"set": True, "seconds": int(ttl_seconds)}
    else:
        ttl = {"set": False}
    record: dict[str, Any] = {"key": key, "type": key_type, "ttl": ttl}
    if key_type == "string":
        value: str = await client.get(key)
        record["json"] = _parse_json(value) is not None
        record["value"] = value
    elif key_type == "zset":
        members = await client.zrange(key, 0, -1, withscores=True)
        record["members"] = [
            {"member": member, "score": round(float(score), 6)}
            for member, score in members
        ]
    return record


def _categorize(record: dict[str, Any]) -> dict[str, Any]:
    """Turn a raw probe into the pinned expectation, replacing
    engine-generated volatiles with shape pins."""
    key_type = record["type"]
    pinned: dict[str, Any] = {
        "key": record["key"],
        "type": key_type,
        "ttl": record["ttl"],
    }
    if key_type == "string":
        value: str = record["value"]
        if record.get("json"):
            pinned["type"] = "json"
            pinned["value"] = value
        elif re.fullmatch(_NUMERIC_SHAPE, value):
            # Engine-generated expiry float: pin the format, not the value.
            pinned["value_shape"] = _NUMERIC_SHAPE
        else:
            pinned["value"] = value
    elif key_type == "zset":
        pinned["card"] = len(record["members"])
        entries = record["members"]
        if all(re.fullmatch(_UUID4_HEX_SHAPE, e["member"]) for e in entries):
            # Behavior counters: uuid4-hex members, epoch scores.
            pinned["member_shape"] = _UUID4_HEX_SHAPE
            pinned["score_shape"] = _NUMERIC_SHAPE
        elif all(re.fullmatch(_NUMERIC_SHAPE, e["member"]) for e in entries) and all(
            abs(e["score"] - float(e["member"])) < 1e-6 for e in entries
        ):
            # Rate-limit counters: the epoch float stringified, score equal.
            pinned["member_shape"] = _NUMERIC_SHAPE
            pinned["score_equals_member"] = True
        else:
            pinned["members"] = entries
    return pinned


# ---- operations ----


def _rio_config(**overrides: Any) -> SecurityConfig:
    return SecurityConfig(
        enable_redis=True,
        redis_url=REDIS_URL,
        redis_prefix=REDIS_PREFIX,
        **overrides,
    )


async def _discard(redis_manager: Any) -> None:
    redis_manager._closed = True
    await redis_manager._discard_client()


async def _op_rate_limit(args: dict[str, Any]) -> None:
    config = _rio_config(enable_rate_limiting=True)
    redis_manager = await _redis_manager(config)
    manager = RateLimitManager(config)
    await manager.reset()
    await manager.initialize_redis(redis_manager)
    request = _PipelineRequest(
        {"client_ip": args["client_ip"], "url_path": args.get("endpoint_path", "/api")}
    )

    async def _error(status: int, message: str) -> _StubResponse:
        return _StubResponse(status, message)

    try:
        await manager.check_rate_limit(
            request,
            args["client_ip"],
            _error,
            endpoint_path=args.get("endpoint_path", ""),
            rate_limit=args["rate_limit"],
            rate_limit_window=args["rate_limit_window"],
        )
    finally:
        manager.rate_limit_script_sha = None
        await _discard(redis_manager)


async def _op_ban_ip(args: dict[str, Any]) -> None:
    await reset_global_state()
    config = _rio_config()
    redis_manager = await _redis_manager(config)
    saved_config = ip_ban_manager.config
    ip_ban_manager.config = config
    ip_ban_manager.redis_handler = redis_manager
    try:
        await ip_ban_manager.ban_ip(
            args["ip"], args["duration"], args.get("reason", "rio_ban")
        )
    finally:
        ip_ban_manager.redis_handler = None
        ip_ban_manager.agent_handler = None
        ip_ban_manager.config = saved_config
        await reset_global_state()
        await _discard(redis_manager)


async def _op_behavior_usage(args: dict[str, Any]) -> None:
    config = _rio_config()
    redis_manager = await _redis_manager(config)
    tracker = BehaviorTracker(config)
    tracker.redis_handler = redis_manager
    rule = BehaviorRule(
        rule_type=args["rule"]["rule_type"],
        threshold=args["rule"]["threshold"],
        window=args["rule"]["window"],
    )
    try:
        await tracker.track_endpoint_usage(args["endpoint_id"], args["client_ip"], rule)
    finally:
        await _discard(redis_manager)


async def _op_behavior_return(args: dict[str, Any]) -> None:
    config = _rio_config()
    redis_manager = await _redis_manager(config)
    tracker = BehaviorTracker(config)
    tracker.redis_handler = redis_manager
    rule = BehaviorRule(
        rule_type=args["rule"]["rule_type"],
        threshold=args["rule"]["threshold"],
        window=args["rule"]["window"],
        pattern=args["rule"]["pattern"],
    )
    response = _StubResponse(args["response_status"], "not found")
    try:
        await tracker.track_return_pattern(
            args["endpoint_id"], args["client_ip"], response, rule
        )
    finally:
        await _discard(redis_manager)


async def _op_security_headers(args: dict[str, Any]) -> None:
    config = _rio_config()
    redis_manager = await _redis_manager(config)
    manager = security_headers_manager
    saved = (manager.csp_config, manager.hsts_config, manager.custom_headers)
    manager.csp_config = args.get("csp_config")
    manager.hsts_config = args.get("hsts_config")
    manager.custom_headers = args.get("custom_headers") or {}
    manager.headers_cache.clear()
    try:
        await manager.initialize_redis(redis_manager)
    finally:
        manager.csp_config, manager.hsts_config, manager.custom_headers = saved
        manager.redis_handler = None
        manager.headers_cache.clear()
        await _discard(redis_manager)


async def _op_add_pattern(args: dict[str, Any]) -> None:
    config = _rio_config()
    redis_manager = await _redis_manager(config)
    sus_patterns_handler.redis_handler = redis_manager
    sus_patterns_handler.custom_patterns.clear()
    sus_patterns_handler.compiled_custom_patterns.clear()
    try:
        added = await sus_patterns_handler.add_pattern(args["pattern"], custom=True)
        if not added:
            raise RuntimeError(f"corpus pattern rejected: {args['pattern']!r}")
    finally:
        sus_patterns_handler.redis_handler = None
        sus_patterns_handler.agent_handler = None
        sus_patterns_handler.custom_patterns.clear()
        sus_patterns_handler.compiled_custom_patterns.clear()


async def _op_ipinfo_database(args: dict[str, Any]) -> None:
    import aiohttp

    handler = IPInfoManager("corpus-token", max_age=args["max_age"])
    saved = (
        handler.redis_handler,
        handler.agent_handler,
        handler.db_path,
        handler.reader,
        handler._initialization_attempted,
    )
    scratch = Path("/tmp/guard_core_corpus_rio_scratch")
    redis_manager = await _redis_manager(_rio_config())
    handler.redis_handler = redis_manager
    handler.db_path = scratch / "corpus.mmdb"

    class _FakeResponse:
        def __init__(self, content: bytes) -> None:
            self._content = content

        def raise_for_status(self) -> None:
            return None

        async def read(self) -> bytes:
            return self._content

    class _FakeGet:
        def __init__(self, content: bytes) -> None:
            self._content = content

        async def __aenter__(self) -> _FakeResponse:
            return _FakeResponse(self._content)

        async def __aexit__(self, *exc: Any) -> bool:
            return False

        def __await__(self):
            # aiohttp request context managers are also directly awaitable.
            async def _resolve() -> _FakeResponse:
                return _FakeResponse(self._content)

            return _resolve().__await__()

    class _FakeSession:
        def __init__(self, *a: Any, **k: Any) -> None:
            pass

        async def __aenter__(self) -> _FakeSession:
            return self

        async def __aexit__(self, *exc: Any) -> bool:
            return False

        def get(self, url: str, headers: Any = None) -> _FakeGet:
            return _FakeGet(FAKE_MMDB_BYTES)

    original_session = aiohttp.ClientSession
    aiohttp.ClientSession = _FakeSession  # type: ignore[misc]
    try:
        await handler.initialize()
    finally:
        aiohttp.ClientSession = original_session  # type: ignore[misc]
        (
            handler.redis_handler,
            handler.agent_handler,
            handler.db_path,
            handler.reader,
            handler._initialization_attempted,
        ) = saved
        await _discard(redis_manager)
        shutil.rmtree(scratch, ignore_errors=True)


async def _op_cloud_ranges(args: dict[str, Any]) -> None:
    import guard_core.handlers.cloud_handler as cloud_module

    config = _rio_config()
    redis_manager = await _redis_manager(config)
    saved = (
        cloud_handler.redis_handler,
        cloud_handler._store,
        cloud_module._fetch_provider_ranges,
    )
    cloud_handler.redis_handler = redis_manager
    cloud_handler._store = None

    ranges = {ipaddress.ip_network(cidr) for cidr in args["ranges"]}
    regions = dict(args["regions"])

    async def _fixed_fetch(provider: str) -> tuple[set[Any], dict[str, str]]:
        return set(ranges), dict(regions)

    cloud_module._fetch_provider_ranges = _fixed_fetch  # type: ignore[assignment]
    try:
        await cloud_handler.refresh_async(providers=[args["provider"]], ttl=args["ttl"])
    finally:
        (
            cloud_handler.redis_handler,
            cloud_handler._store,
            cloud_module._fetch_provider_ranges,
        ) = saved
        await _discard(redis_manager)


async def _op_cloud_ip_store(args: dict[str, Any]) -> None:
    config = _rio_config()
    redis_manager = await _redis_manager(config)
    store = RedisCloudIpStore(redis_manager)
    try:
        await store.set(args["provider"], set(args["ranges"]), ttl=args["ttl"])
    finally:
        await _discard(redis_manager)


async def _op_dynamic_rules(args: dict[str, Any]) -> None:
    config = _rio_config(
        enable_agent=True, agent_api_key="corpus-agent-key", enable_dynamic_rules=True
    )
    redis_manager = await _redis_manager(config)
    DynamicRuleManager._instance = None  # noqa: SLF001 - corpus reset
    manager = DynamicRuleManager(config)
    manager.redis_handler = redis_manager
    rules = DynamicRules(
        rule_id=args["rules"]["rule_id"],
        version=args["rules"]["version"],
        timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )

    class _RulesAgent:
        async def get_dynamic_rules(self) -> DynamicRules:
            return rules

        async def send_event(self, event: Any) -> None:
            return None

    manager.agent_handler = _RulesAgent()
    try:
        await manager.update_rules()
    finally:
        DynamicRuleManager._instance = None  # noqa: SLF001 - corpus reset
        await _discard(redis_manager)


_OPERATIONS = {
    "rate_limit": _op_rate_limit,
    "ban_ip": _op_ban_ip,
    "behavior_usage": _op_behavior_usage,
    "behavior_return": _op_behavior_return,
    "security_headers": _op_security_headers,
    "add_pattern": _op_add_pattern,
    "ipinfo_database": _op_ipinfo_database,
    "cloud_ranges": _op_cloud_ranges,
    "cloud_ip_store": _op_cloud_ip_store,
    "dynamic_rules": _op_dynamic_rules,
}


async def run_redis_case(case: dict[str, Any]) -> dict[str, Any]:
    """Execute one operation and pin everything the prefix scan observes."""
    op = _OPERATIONS[case["operation"]["op"]]
    client = await _connect()
    try:
        await _flush_prefix(client)
        await op(case["operation"]["args"])
        keys = sorted(await client.keys(f"{REDIS_PREFIX}*"))
        if not keys:
            raise RuntimeError(f"{case['id']}: operation wrote no keys")
        expected = [_categorize(await _probe_key(client, key)) for key in keys]
        return {
            "id": case["id"],
            "prefix": REDIS_PREFIX,
            "operation": case["operation"],
            "expected": expected,
        }
    finally:
        await _flush_prefix(client)
        await client.aclose()
