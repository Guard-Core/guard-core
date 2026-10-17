---

title: Redis Integration
description: RedisManager internals for connection pooling, auto-reconnection, safe operations, and key namespacing in guard-core
keywords: redis, connection pooling, distributed state, key namespacing, guard-core
---

Redis Integration
=================

Guard-core uses Redis for distributed state management across multiple application instances. The `RedisManager` handler provides connection management, namespaced key operations, and fault-tolerant wrappers.

RedisManager
------------

### Construction

```python
class RedisManager:
    _instance: "RedisManager | None" = None

    def __new__(cls, config: SecurityConfig) -> "RedisManager":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance.logger = logging.getLogger("guard_core.handlers.redis")
            cls._instance.agent_handler = None
        cls._instance.config = config
        cls._instance._closed = False
        return cls._instance
```

`RedisManager` is a singleton, same pattern as every other handler (`IPBanManager`, `CloudManager`, `RateLimitManager`): the `if cls._instance is None:` guard means the same underlying instance is returned on every construction. What does happen on every construction, singleton or not, is that `config` and `_closed` are re-applied to that instance -- so calling `RedisManager(new_config)` swaps the active config on the shared instance without creating a second one. The `redis_handler` module-level variable is the class itself (not an instance), allowing deferred instantiation with a config.

### Connection Lifecycle

**Initialize**:

```python
redis_manager = RedisManager(config)
await redis_manager.initialize()
```

Creates a `redis.asyncio.Redis` connection from `config.redis_url` with `decode_responses=True`, applying the configured socket timeouts (`redis_socket_timeout`, `redis_socket_connect_timeout`), pool cap (`redis_max_connections`), health-check interval (`redis_health_check_interval`), and, when `redis_retries > 0`, a client-level `Retry` with exponential backoff on connection/timeout errors. Pings to verify connectivity. Raises `GuardRedisError(503)` on failure.

Since `RedisManager` is a singleton, calling `initialize()` again on the same instance (including with `enable_redis=False`, or after a failed connection attempt) first closes whatever client is already there via the same `aclose()` path `close()` uses, so the manager never holds more than one live client at a time. That close is best-effort: a failure (for example a client created on a different event loop than the one closing it) is logged as a warning and does not block creating the replacement.

Note that the client-level retry re-sends non-idempotent commands: a lost reply after the server already committed an `INCR` over-counts by one. For guard-core's rate-limit counters that fails closed (mildly over-restrictive, self-heals next window); callers needing exactly-once semantics should not build on `incr()`.

**Close**:

```python
await redis_manager.close()
```

Closes the connection and sets `_closed = True`. Subsequent operations will raise `GuardRedisError`.

### Connection Context Manager

```python
@asynccontextmanager
async def get_connection(self) -> AsyncIterator[Redis]:
```

All operations use this context manager, which:

1. Checks if the connection is closed.
2. Auto-initializes if `_redis` is `None`.
3. Yields the Redis connection.
4. Catches `ConnectionError` and `AttributeError`, wrapping them in `GuardRedisError(503)`.

### Safe Operations

```python
async def safe_operation(self, func, *args, **kwargs) -> Any
```

Wraps any async function that takes a Redis connection as its first argument. Returns `None` if Redis is disabled. Raises `GuardRedisError` on failure.

___

Key Namespacing
---------------

All keys are prefixed with `config.redis_prefix` (default: `"guard_core:"`) and organized by namespace:

```text
{redis_prefix}{namespace}:{key}
```

**Examples**:

| Operation                          | Redis Key                              |
|------------------------------------|----------------------------------------|
| Banned IP lookup                   | `guard_core:banned_ips:192.168.1.1`    |
| Rate limit counter                 | `guard_core:rate_limit:rate:10.0.0.1`  |
| Cloud IP cache                     | `guard_core:cloud_ranges:AWS`          |
| Custom patterns                    | `guard_core:patterns:custom`           |
| Security headers config            | `guard_core:security_headers:csp_config` |
| Behavioral tracking                | `guard_core:behavior_usage:behavior:usage:{sha256(endpoint_id)}:{sha256(client_ip)}` (a sorted set, one key per identity pair; its TTL is the larger of the rule's window and 300 s, refreshed on every hit) |
| Behavioral rule-key index          | `guard_core:behavior_usage:behavior:usage:{sha256("recent")}:{sha256(client_ip)}` (a set of the client's `behavior_usage` rule keys, at most 10,000 members, same TTL as the rule key, read by `guard.behavior.recent_event_count`) |

### Key Operations

| Method                              | Description                                   |
|-------------------------------------|-----------------------------------------------|
| `get_key(namespace, key)`           | Get a namespaced key value                    |
| `set_key(namespace, key, value, ttl)` | Set with optional TTL (uses `SETEX` if TTL provided) |
| `incr(namespace, key, ttl)`         | Atomic increment with optional TTL            |
| `record_sliding_window_hit(namespace, key, timestamp, window_start, ttl)` | Add a timestamped hit to a sorted-set sliding window, prune entries scored before `window_start`, refresh the TTL, and return the remaining count, all in one pipeline |
| `exists(namespace, key)`            | Check key existence                           |
| `delete(namespace, key)`            | Delete a single key                           |
| `keys(pattern)`                     | Find keys matching a pattern (auto-prefixed)  |
| `delete_pattern(pattern)`           | Delete all keys matching a pattern            |

All methods return `None` when Redis is disabled (`config.enable_redis = False`), allowing callers to fall back to local state without error handling.

___

Fault Tolerance
---------------

### Graceful Degradation

When Redis is unavailable, guard-core falls back to in-memory state for all subsystems:

| Subsystem          | Redis State                    | Fallback                        |
|--------------------|--------------------------------|---------------------------------|
| Rate limiting      | Sorted sets per IP             | In-memory `defaultdict(deque)`  |
| IP banning         | Key-value with TTL             | `TTLCache(maxsize=10000)`       |
| Cloud IP ranges    | Cached CIDR strings            | Direct HTTP fetch + memory      |
| Suspicious patterns| Custom pattern list             | Built-in patterns only          |
| Security headers   | Configuration cache            | In-memory configuration         |

### Error Handling

`GuardRedisError` is raised with a `status_code` and `detail`:

```python
class GuardRedisError(GuardCoreError):
    def __init__(self, status_code: int, detail: str) -> None:
        self.status_code = status_code
        self.detail = detail
```

`HandlerInitializer.initialize_redis_handlers` catches `GuardRedisError` raised by `RedisManager.initialize()` during startup and always logs it. When `redis_fail_open=True`, it degrades to the same in-memory path used when Redis is disabled (`ip_ban_manager`, the rate limiter, and `sus_patterns_handler` are never wired to Redis for the life of the process) instead of raising; `RedisManager._redis` stays `None`, so any later call through `safe_operation`/`get_connection` retries the connection on its own. When `redis_fail_open` is `False` (the default), the exception re-raises out of initialization so adapters can turn it into a clean error response (fastapi-guard returns a 503).

When a `GuardRedisError` escapes a security check at request time (a Redis outage mid-request), the pipeline honors `fail_secure` by default: the request is blocked with a 500. Setting `redis_fail_open=True` opts into skipping the failing check and letting the request through, treating Redis outages as an availability concern distinct from other check failures.

The rate limiter is a third case, not just startup and other checks: `_redis_request_count` (`guard_core/handlers/ratelimit_handler.py`, both `check_rate_limit` and `check_rate_limit_by_ip`) used to catch every Redis failure itself and silently fall back to the in-memory window regardless of `redis_fail_open`, so a Redis outage silently turned the shared, cross-worker rate limit into a per-process one (N workers effectively multiplying `rate_limit` by N) with no signal and no way to opt out. It now honors `redis_fail_open` like every other check: `True` keeps the in-memory fallback, but logs a `WARNING` once per process ("Redis unavailable for rate limiting; using the in-memory window...") instead of an `ERROR` on every request; `False` (the default) raises `GuardRedisError` instead of silently falling back, so `fail_secure` decides the outcome exactly as it does for any other check.

___

Configuration
-------------

| Field                            | Type           | Default                   | Description                              |
|----------------------------------|----------------|---------------------------|------------------------------------------|
| `enable_redis`                   | `bool`         | `True`                    | Master switch for Redis integration      |
| `redis_url`                      | `str \| None`  | `"redis://localhost:6379"`| Redis connection URL                     |
| `redis_prefix`                   | `str`          | `"guard_core:"`           | Key prefix for namespace isolation       |
| `redis_socket_connect_timeout`   | `float \| None`| `2.0`                     | Seconds to wait establishing a TCP connection (must be positive; `None` disables) |
| `redis_socket_timeout`           | `float \| None`| `2.0`                     | Seconds to wait on a read/write (must be positive; `None` disables) |
| `redis_health_check_interval`    | `int`          | `30`                      | Seconds between pooled-connection health checks (`0` disables) |
| `redis_max_connections`          | `int \| None`  | `None`                    | Connection-pool cap (`None` uses redis-py's default) |
| `redis_retries`                  | `int`          | `1`                       | Client-level retries with exponential backoff (`0` disables) |
| `redis_fail_open`                | `bool`         | `False`                   | On Redis outage, skip the failing check instead of honoring `fail_secure` |

### Adapter Considerations

- Set `redis_prefix` to a unique value per application to avoid key collisions when sharing a Redis instance.
- When `enable_redis` is `False`, all `RedisManager` methods return `None` without attempting connections.
- The `redis_url` can include authentication: `"redis://user:password@host:port/db"`.
- Any userinfo in `redis_url` is stripped before the value reaches the `redis_connection`/`redis_error` agent telemetry events; only `scheme://host[:port]` is sent. The real connection still uses the unredacted `redis_url`.
