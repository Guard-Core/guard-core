---

title: Cloud Providers
description: CloudManager internals for fetching, caching, and checking AWS, GCP, and Azure IP ranges in guard-core
keywords: cloud providers, AWS, GCP, Azure, IP ranges, cloud blocking, guard-core
---

Cloud Providers
===============

Guard-core can block requests originating from cloud provider IP ranges. The `CloudManager` handler fetches the official IP range lists for six providers (AWS, GCP, Azure, DigitalOcean, Linode, Vultr), caches them as `ipaddress` network objects, and exposes a fast membership check used by the security pipeline. All six providers are user-blockable via `SecurityConfig.block_cloud_providers` (typed `frozenset[str] | None`); an entry is valid when the part before an optional `:!region` suffix is one of the six provider names, so a region carve-out like `"GCP:!us-central1"` (block the provider except that region) is accepted alongside a bare provider name. Region metadata exists for AWS and GCP only; Azure, DigitalOcean, Linode and Vultr expose no region data through their fetchers, so a carve-out on them exempts nothing and the whole provider stays blocked.

CloudManager
------------

### Singleton Pattern

`CloudManager` uses a singleton so that IP range data is shared across the entire process:

```python
class CloudManager:
    _instance = None
    ip_ranges: dict[str, set[IPv4Network | IPv6Network]]
    last_updated: dict[str, datetime | None]
    _store: CloudIpStoreProtocol | None

    def __new__(cls) -> "CloudManager":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance.ip_ranges = {
                "AWS": set(),
                "GCP": set(),
                "Azure": set(),
                "DigitalOcean": set(),
                "Linode": set(),
                "Vultr": set(),
            }
            cls._instance.last_updated = {p: None for p in _ALL_PROVIDERS}
            cls._instance._store = InMemoryCloudIpStore()
        return cls._instance
```

A module-level instance `cloud_handler` is the canonical access point used throughout guard-core. The module-level `_ALL_PROVIDERS = {"AWS", "GCP", "Azure", "DigitalOcean", "Linode", "Vultr"}` is the default provider set for every fetch and check method. `__new__` also seeds `_store` with an `InMemoryCloudIpStore()` instance, so `_store` is never `None` in normal operation. `CloudManager` also carries a `network_regions: dict[str, dict[str, str]]` attribute (network string to region name, per provider), populated alongside `ip_ranges` on every fetch/refresh; it backs the `:!region` carve-out check in `is_cloud_ip()`.

___

IP Range Fetching
-----------------

Each provider has a dedicated async fetch function that returns `tuple[set[IPv4Network | IPv6Network], dict[str, str]]`: the CIDR network set plus a network-string-to-region map used for `:!region` carve-outs.

### AWS

```python
async def fetch_aws_ip_ranges() -> tuple[
    set[IPv4Network | IPv6Network], dict[str, str]
]:
    async with aiohttp.ClientSession() as session:
        response = await session.get(
            "https://ip-ranges.amazonaws.com/ip-ranges.json",
            timeout=aiohttp.ClientTimeout(total=10),
        )
        data = await response.json(content_type=None)
    networks = set()
    regions = {}
    for ip_range in data["prefixes"]:
        if ip_range["service"] != "AMAZON":
            continue
        network = ipaddress.ip_network(ip_range["ip_prefix"])
        networks.add(network)
        region = ip_range.get("region")
        if region:
            regions[str(network)] = region
    return networks, regions
```

Filters to `service == "AMAZON"` prefixes only, which covers all AWS services.

### GCP

```python
async def fetch_gcp_ip_ranges() -> tuple[
    set[IPv4Network | IPv6Network], dict[str, str]
]:
    async with aiohttp.ClientSession() as session:
        response = await session.get(
            "https://www.gstatic.com/ipranges/cloud.json",
            timeout=aiohttp.ClientTimeout(total=10),
        )
        data = await response.json(content_type=None)
```

GCP publishes IPv4 and IPv6 ranges under different keys in the same JSON file. The function merges both into a single set, recording each network's `scope` field as its region.

### Azure

Azure does not expose a stable JSON endpoint. The fetch function performs a two-step process:

1. Fetches the Microsoft download page for Service Tags (`id=56519`).
2. Extracts the actual JSON download URL from the HTML using a regex.
3. Fetches the JSON and selects the entry whose `name` is `AzureCloud` (the umbrella tag for the whole public cloud; the document lists many other tags such as `ActionGroup` and `Storage`, and `AzureCloud` is not guaranteed to be first), then parses that entry's `properties.addressPrefixes`. A document with no `AzureCloud` tag is treated as a broken download: the fetch logs an error and returns an empty set rather than loading an unrelated tag's ranges.

A browser-like `User-Agent` header is required to avoid being blocked by Microsoft's download portal.

### Error Handling

Every fetch function catches all exceptions, logs the error, and returns an empty set. This prevents a single provider outage from breaking the entire refresh cycle.

___

Caching Strategy
----------------

### In-Memory Cache

IP ranges are stored as `set[IPv4Network | IPv6Network]` in `CloudManager.ip_ranges`, keyed by provider name. This gives O(n) membership testing against the network set using Python's `ipaddress` module (`ip_obj in network`).

### Pluggable Store (`CloudIpStore`)

The persistent caching layer is a pluggable `CloudIpStoreProtocol` backend held in `CloudManager._store`. The default is `InMemoryCloudIpStore` (seeded in `__new__`). Calling `initialize_redis()` swaps it for `RedisCloudIpStore` **only when the current store is still the default `InMemoryCloudIpStore`** (`isinstance(self._store, InMemoryCloudIpStore)`); a custom store installed via `set_store()` is preserved. When swapped, ranges persist across worker restarts and stay shared across replicas. `refresh_async` reads from and writes back to whichever store is active:

```python
async def refresh_async(
    self, providers: set[str] = _ALL_PROVIDERS, ttl: int = 3600
) -> None:
    if self._store is None:
        await self._refresh_providers_via_redis_handler(providers, ttl=ttl)
        return

    for provider in providers:
        cached = await self._store.get(provider)
        if cached is not None:
            self.ip_ranges[provider] = {ipaddress.ip_network(s) for s in cached}
            continue

        ranges = await fetch_func()
        if ranges:
            self.ip_ranges[provider] = ranges
            self.last_updated[provider] = datetime.now(timezone.utc)
            await self._store.set(
                provider,
                {str(network) for network in ranges},
                ttl=ttl,
            )
```

**Flow**:

1. Ask the store for the provider's cached CIDR set (`self._store.get(provider)`).
2. If found, deserialize into `ipaddress` networks and populate the in-memory cache.
3. If not found, fetch from the provider, populate in-memory, and write the CIDR set back to the store with a TTL (`self._store.set(provider, ...)`).

`RedisCloudIpStore` JSON-encodes each provider's CIDR set as a sorted list under the `cloud_ip_v2` namespace. Redis keys follow the pattern `{redis_prefix}cloud_ip_v2:{provider}` (e.g., `guard:cloud_ip_v2:AWS`). See [Cloud IP Store](../api/cloud-ip-store.md) for the store API and namespace details.

### Legacy `cloud_ranges_v2` Path (dead code)

`refresh_async` begins with an `if self._store is None:` branch that delegates to `_refresh_providers_via_redis_handler`, which uses the legacy `cloud_ranges_v2` namespace directly on the Redis handler:

```python
async def _refresh_providers_via_redis_handler(
    self, providers: set[str], ttl: int = 3600
) -> None:
    if self.redis_handler is None:
        await self._refresh_providers(providers)
        return

    for provider in providers:
        cached = await self.redis_handler.get_key("cloud_ranges_v2", provider)
        if cached:
            self.ip_ranges[provider] = {
                ipaddress.ip_network(ip) for ip in cached.split(",")
            }
            continue
        ...
```

This path stores a comma-separated CIDR string under keys like `{redis_prefix}cloud_ranges_v2:{provider}`. It is **unreachable at runtime**: `__new__` always seeds `_store` with an `InMemoryCloudIpStore()` and nothing in the codebase sets it back to `None`, so the `if self._store is None:` guard is never satisfied and `refresh_async` always takes the store-based path above. The branch is retained only as dead/back-compat code; the `InMemoryCloudIpStore`/`RedisCloudIpStore` path is what runs in all deployments.

### Sync vs Async Refresh

| Method          | Redis Required | Usage                                    |
|-----------------|----------------|------------------------------------------|
| `refresh()`     | No             | Async in-memory-only refresh             |
| `refresh_async()` | Optional    | Async refresh with optional Redis cache  |

Calling `refresh()` when Redis is enabled raises `RuntimeError` to enforce using `refresh_async()` instead.

___

IP Checking
-----------

### `is_cloud_ip()`

```python
def is_cloud_ip(self, ip: str, providers: set[str] = _ALL_PROVIDERS) -> bool:
    ip_obj = ipaddress.ip_address(ip)
    blocked, carveouts = _parse_cloud_selectors(providers)
    for provider in blocked:
        allowed_regions = carveouts.get(provider)
        provider_regions = self.network_regions.get(provider, {})
        for network in self.ip_ranges.get(provider, set()):
            if ip_obj in network:
                if (
                    allowed_regions
                    and provider_regions.get(str(network)) in allowed_regions
                ):
                    continue
                return True
    return False
```

`providers` accepts both bare provider names and `"PROVIDER:!region"` selectors; `_parse_cloud_selectors` splits them into the blocked-provider set and a per-provider carve-out region set. Parses the IP once, then iterates over every cached network for the requested providers, skipping a match whose network falls in a carved-out region. Returns `True` on the first non-carved-out match. Invalid IP strings are caught and logged, returning `False`.

### `get_cloud_provider_details()`

```python
def get_cloud_provider_details(
    self, ip: str, providers: set[str] = _ALL_PROVIDERS
) -> tuple[str, str] | None: ...
```

Same logic as `is_cloud_ip()` but returns a `(provider, network)` tuple on match, or `None`. This is used by the event system to include the matched provider and CIDR block in detection events.

### Provider Status

Before ranges are fetched, `ip_ranges[provider]` is an empty set and `is_cloud_ip()` trivially returns `False` for that provider, not blocked, but also not evaluated. The first `is_cloud_ip()` call to observe this logs a `WARNING` (rate-limited to at most once every `_EMPTY_RANGES_WARNING_COOLDOWN` seconds, 300 by default, per provider, so a busy server cannot turn this into a log flood), and `get_status()` makes the same condition queryable instead of only discoverable in logs:

```python
def get_status(self) -> dict[str, dict[str, bool | datetime | int | None]]:
    return {
        provider: {
            "ready": bool(self.ip_ranges.get(provider)),
            "last_refreshed": self.last_updated.get(provider),
            "entries": len(self.ip_ranges.get(provider, set())),
        }
        for provider in _ALL_PROVIDERS
    }
```

`ready` reflects whether the provider currently has any cached ranges to check against, not just whether a refresh was ever attempted, so a provider that later starts failing shows `ready=False` again while `last_refreshed` still shows the last time it worked. See [Provider Status](../configuration/security-config.md#provider-status) for the combined cloud + geo-IP payload, exposed by your adapter's status surface.

___

Refresh Intervals and `cloud_ip_refresh_interval`
--------------------------------------------------

The `SecurityConfig` model exposes:

```python
cloud_ip_refresh_interval: int = Field(
    default=3600,
    ge=60,
    description="Interval in seconds between cloud IP range refreshes",
)
```

The `CloudIpRefreshCheck` pipeline check schedules a refresh when enough time has elapsed:

```python
class CloudIpRefreshCheck(SecurityCheck):
    async def check(self, request: GuardRequest) -> GuardResponse | None:
        route_config = getattr(request.state, "route_config", None)
        cloud_providers_to_check = (
            self.middleware.route_resolver.get_cloud_providers_to_check(route_config)
        )
        if not cloud_providers_to_check:
            return None

        if (
            time.time() - self.middleware.last_cloud_ip_refresh
            > self.config.cloud_ip_refresh_interval
        ):
            previous_refresh = self.middleware.last_cloud_ip_refresh
            self.middleware.last_cloud_ip_refresh = int(time.time())
            scheduled = await self.cloud_handler.schedule_refresh(
                set(cloud_providers_to_check),
                ttl=self.config.cloud_ip_refresh_interval,
                refresh=self.middleware.refresh_cloud_ip_ranges,
            )
            if not scheduled:
                self.middleware.last_cloud_ip_refresh = previous_refresh
        return None
```

This check runs on every request but only performs work when:

- The resolved provider set is non-empty: `get_cloud_providers_to_check()` is route-aware, so a route-level `block_cloud_providers` alone (with the global `SecurityConfig.block_cloud_providers` unset) still triggers a refresh.
- The elapsed time since the last refresh exceeds `cloud_ip_refresh_interval`.

The refresh itself never runs on the request path. `schedule_refresh` fires the middleware's `refresh_cloud_ip_ranges()` as a single-flight background task: while one refresh is in flight, further calls are no-ops, so a slow provider fetch cannot block or stampede request handling. The debounce timestamp is bumped up front so concurrent requests don't all try to schedule, and restored if scheduling fails so the next request retries instead of waiting a full interval. Because the background task calls the middleware protocol method, adapter overrides of `refresh_cloud_ip_ranges` stay on the periodic path.

The in-memory cloud-IP store honors the `ttl` passed at refresh time (the Redis-backed store always did), so cached ranges expire after `cloud_ip_refresh_interval` and the next refresh fetches fresh data in non-Redis deployments too.

The default interval is **3600 seconds (1 hour)**. The minimum allowed value is **60 seconds**.

### Range Change Logging

When a refresh detects changes, `_log_range_changes` logs the delta:

```text
Cloud IP range update for AWS: +12 added, -3 removed
```

### Per-Provider Timestamps

`CloudManager.last_updated` tracks the last successful fetch time per provider as a `datetime | None` dict. This allows consumers to verify freshness independently for each provider.

___

Agent Event Integration
-----------------------

### `send_cloud_detection_event()`

When a cloud IP is blocked and an agent handler is configured, `CloudManager` dispatches a `SecurityEvent`:

```python
async def send_cloud_detection_event(
    self,
    ip: str,
    provider: str,
    network: str,
    action_taken: str = "request_blocked",
) -> None:
    await self._send_cloud_event(
        event_type="cloud_blocked",
        ip_address=ip,
        action_taken=action_taken,
        reason=f"IP belongs to blocked cloud provider: {provider}",
        cloud_provider=provider,
        network=network,
    )
```

The `action_taken` field reflects the mode:

| Mode     | `action_taken`    |
|----------|-------------------|
| Active   | `request_blocked` |
| Passive  | `logged_only`     |

### Event Dispatch from the Pipeline

The `CloudProviderCheck` delegates event dispatch to `SecurityEventBus.send_cloud_detection_events()`:

```python
cloud_details = cloud_handler.get_cloud_provider_details(client_ip, providers)
if cloud_details and cloud_handler.agent_handler:
    provider, network = cloud_details
    await cloud_handler.send_cloud_detection_event(
        client_ip,
        provider,
        network,
        "request_blocked" if not passive_mode else "logged_only",
    )
```

Events are only sent when both conditions are met:

1. `get_cloud_provider_details()` returns a match.
2. An agent handler has been initialized via `initialize_agent()`.

___

Pipeline Integration
--------------------

Two security checks in the pipeline handle cloud provider logic:

| Order | Check                 | Responsibility                                      |
|-------|-----------------------|-----------------------------------------------------|
| 11    | `CloudIpRefreshCheck` | Periodic refresh of IP ranges                       |
| 13    | `CloudProviderCheck`  | Block or log requests from cloud IPs                |

`CloudProviderCheck` respects:

- **Whitelisted IPs**: Skipped if `request.state.is_whitelisted` is `True`, set only for a **global** `whitelist` match and only while `whitelist_access_only` is off (it is on by default since 5.0.0; with it on the field is always `False`, so a whitelisted IP is checked like any other); a route-level `ip_whitelist` match alone does not set it, so it does not skip this check.
- **Route-level bypass**: Skipped if the route config disables the `clouds` check.
- **Provider scoping**: Only checks providers returned by `get_cloud_providers_to_check()`, which can be narrowed per-route via decorators.
- **Passive mode**: Logs but does not block when `config.passive_mode` is enabled.

___

Initialization
--------------

```python
cloud_manager = CloudManager()

await cloud_manager.refresh()

await cloud_manager.initialize_redis(redis_handler, providers={"AWS", "GCP"}, ttl=7200)

await cloud_manager.initialize_agent(agent_handler)
```

`initialize_redis()` triggers an immediate async refresh for the specified providers and caches results with the given TTL. `initialize_agent()` enables event dispatch.
