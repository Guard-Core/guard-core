---

title: Rate Limiting
description: RateLimitManager internals, the sliding window algorithm, the multi-tier Redis Lua script, and per-endpoint rate limits in guard-core
keywords: rate limiting, sliding window, redis, lua script, guard-core
---

Rate Limiting
=============

Guard-core implements rate limiting using a sliding window algorithm with dual backends: in-memory for single-instance deployments and Redis for distributed deployments. The `RateLimitManager` handler orchestrates both.

RateLimitManager
----------------

### One manager per config object

`RateLimitManager(config)` returns the live manager for that config object: constructing again with the same object returns the same manager, so the middleware and user code calling `rate_limit_handler(config)` hold the same windows (`request_timestamps`), `redis_handler`, `agent_handler` and `rate_limit_script_sha`. The registry is a `WeakValueDictionary` keyed by (class, identity of the config object), never by value, behind a lock. The manager holds its config, so an identity cannot be reused while the entry lives, and the entry goes when the last holder drops the manager. Two guarded apps in one process (a mounted sub-app, per-tenant configs, a test app) that were built with different config objects never share windows, even when the configs are equal, and a `model_copy()` of a config gets its own manager. Whichever side asks first creates the manager, and a dynamic rule update keeps it, because it mutates the same config object.

To reset the limiter of a guarded app, pass the app's own config object:

```python
handler = rate_limit_handler(config)  # the config object the app was built with
await handler.reset()
```

`reset()` clears the request windows only: the in-memory windows and the Redis `rate_limit:rate:*` keys. It does not clear the auto-ban strikes (`rate_limit:violations:*` and the shared detection strikes) or active bans, and the manager keeps its Redis and agent handlers attached, so the app's limiter keeps counting through Redis and keeps sending its events. To tear a limiter down, build a new config object or re-initialize the app; `reset()` is not a teardown.

`reset()` on a manager that no guarded app was built with logs one WARNING (`this config object is not the one any guarded app was built with; reset() cleared nothing`).

```python
class RateLimitManager:
    def __new__(cls, config: SecurityConfig) -> "RateLimitManager":
        with _managers_lock:
            existing = _managers.get((cls, id(config)))
            if existing is not None:
                return existing
            instance = cls._build(config)
            _managers[(cls, id(config))] = instance
            return instance
```

### Core methods

```python
async def check_rate_limit_tiers(
    self,
    request: GuardRequest,
    client_ip: str,
    create_error_response: Callable[[int, str], Awaitable[GuardResponse]],
    tiers: Sequence[RateLimitTier],
    config: SecurityConfig | None = None,
) -> RateLimitBlock | None
```

`RateLimitCheck` builds one `RateLimitTier(kind, limit, window, bucket)` per limit that applies to the request and checks them all in one step. It returns `None` when the request is allowed, or a `RateLimitBlock` (the blocking tier's index, the request count and the 429 response) when a tier blocks.

`check_rate_limit(request, client_ip, create_error_response, endpoint_path="", rate_limit=None, rate_limit_window=None, config=None)` keeps its signature for direct callers: it checks one tier (the global one, or an endpoint tier when `endpoint_path` is given), sends the `rate_limited` event and returns the 429 response or `None`.

___

Sliding Window Algorithm
------------------------

### What counts

A request enters a window only when every tier of the request has room. A request blocked by any tier is recorded in none, so a client that floods the limiter does not grow its own window (300 blocked requests leave `limit` entries, not 300) and a client that keeps retrying is unblocked as soon as its allowed hits leave the window.

A tier blocks when the number of hits in its window is already at least its limit: the `limit`-th request passes and the `limit + 1`-th is blocked. The block reports `hits + 1` as its request count and sets `Retry-After` to the seconds until the oldest hit in the blocking tier's window leaves it (rounded up, at least 1).

### In-Memory Backend

Uses `collections.defaultdict[str, deque[float]]`, one deque per client and tier, keyed by `"{client_ip}"` for the global tier and `"{client_ip}:{kind}:{sha256(bucket)}"` for the others. Stale timestamps (older than `now - window`) are dropped from every tier's deque first; the request is blocked by the first tier whose deque is already at its limit, and otherwise the current time is appended to every tier. The store is LRU-bounded by `rate_limit_max_tracked_keys` (10,000 by default).

### Redis Backend

Each tier is a Redis sorted set:

- **Key**: `{redis_prefix}rate_limit:rate:{client_ip}` for the global tier, `{redis_prefix}rate_limit:rate:{client_ip}:{kind}:{sha256(bucket)}` for the endpoint, route and geo tiers (`kind` is `endpoint`, `route` or `geo`, the bucket is the matched endpoint key or the route id).
- **Members and scores**: the time of the hit as Redis reports it.
- **TTL**: `window * 2`, refreshed when a hit is recorded.

___

Lua Script for Atomic Operations
---------------------------------

When Redis is available, guard-core loads one Lua script at initialization. It takes one key per tier and the limit and window of each, and answers for the whole request in one round trip:

```lua
local time = redis.call('TIME')
local now = tonumber(time[1]) + tonumber(time[2]) / 1000000

-- for each tier: drop hits older than the window, count what is left
-- if a tier is at its limit: return {tier_number, count, retry_after}, record nothing

-- no tier blocked: ZADD every tier and refresh every TTL
return {0, 0, 0}
```

The script reads the clock from Redis (`TIME`), never from the calling worker, so a host with a skewed clock cannot purge the hits of its peers. Its SHA is cached in `rate_limit_script_sha` and executed with `EVALSHA` once per request, however many tiers the request has; on `NOSCRIPT` the script is reloaded and the call is retried.

**Advantages of the Lua approach**:

- **Atomicity**: the check of every tier and the recording happen as one step, so concurrent requests cannot overshoot a limit.
- **Performance**: one round trip and one connection checkout per request, not one per tier.
- **Consistency**: the limit is exact across workers and replicas.

### Fallback

If the Lua script is not loaded (for example, script load failed), or for `check_rate_limit_by_ip`, the Redis backend reads `TIME`, runs one pipeline that counts every tier, and only when no tier blocks runs a second pipeline that records the hit in every tier. The two pipelines are not atomic together, which is why the script is the primary path.

If Redis fails entirely (connection error), `redis_fail_open` decides: `False` (the default) raises `GuardRedisError` and the pipeline applies `fail_secure`, `True` falls back to the in-memory window with a log warning.

### Connection pool

The Redis client uses a blocking connection pool of `redis_max_connections` connections (100 when unset). A burst above the pool size waits up to `redis_pool_timeout` seconds (1.0 by default) for a free connection instead of failing; when the wait times out the call fails like any other Redis error and `redis_fail_open` decides.

___

Tiers
-----

The `RateLimitCheck` pipeline check builds these tiers in this order, and the first one that blocks decides the response:

| Order | Source                               | Configuration                                    | Bucket |
|-------|--------------------------------------|--------------------------------------------------|--------|
| 1     | Dynamic endpoint rules               | `config.endpoint_rate_limits[path] = (limit, window)` | the matched key |
| 2     | Route decorator                      | `RouteConfig.rate_limit` + `RouteConfig.rate_limit_window` | the route id |
| 3     | Geo-based route limits               | `RouteConfig.geo_rate_limits[country] = (limit, window)` | the route id |
| 4     | Global                               | `config.rate_limit` + `config.rate_limit_window`, only when `enable_rate_limiting` is on | none |

Each tier keeps its own bucket and its own budget, so a route limit and a geo limit on one route never double count. With `enable_rate_limiting=False` the global tier is off and the route, geo and endpoint tiers stay on; startup logs one INFO line naming the routes whose own limits stay on.

The check does not run on excluded paths (`exclude_paths`), and a CORS preflight (`OPTIONS` with `Access-Control-Request-Method`) is never counted. Bans and the IP lists still apply to both, because `ip_security` runs first.

### Geo-Based Rate Limits

When `RouteConfig.geo_rate_limits` is configured, the check resolves the client's country with the middleware's `GeoIPHandler` (the one the IP checks use), then looks up the limit:

1. Exact country match (e.g., `"US"`). The decorator uppercases country keys, so `{"us": ...}` and `{"US": ...}` are the same.
2. Wildcard fallback (`"*"`).
3. If no match, the tier is left out.

___

Auto-ban feed
-------------

With `enable_rate_limit_auto_ban`, each non-passive block counts as one violation toward a ban (see [Rate-limit auto-ban](../api/ban-config.md#rate-limit-auto-ban)). With Redis on, violations are counted in `{redis_prefix}rate_limit:violations:{client_ip}`, a 3600 s sliding window shared by every worker and cleared when the ban lands. A client identity that is not an IP address (the `"unknown"` identity of a request with no client address) is never counted or banned, and an exception in this path is logged while the 429 is kept.

___

Initialization
--------------

```python
rate_limit_manager = RateLimitManager(config)
await rate_limit_manager.initialize_redis(redis_handler)
await rate_limit_manager.initialize_agent(agent_handler)
```

Redis initialization triggers the Lua script load. If it fails, the manager logs an error and proceeds with the pipeline fallback.

___

Reset
-----

```python
await rate_limit_manager.reset()
```

Clears the manager's in-memory `request_timestamps` dictionary and deletes all `rate_limit:rate:*` keys from Redis.
