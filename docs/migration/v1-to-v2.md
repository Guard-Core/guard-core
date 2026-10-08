---

title: Migrating from v1.x to v2.0
description: Upgrade guide for breaking changes shipped in guard-core 2.0.0 - DetectionResult, suspicious_request_counts shape, 3-tuple compiled patterns, and cloud-IP namespace
keywords: migration, upgrade, v2, breaking changes, detection result, suspicious request counts, guard-core
---

Migrating from v1.x to v2.0
===========================

`guard-core 2.0.0` ships operator-facing security controls and a pluggable IP lifecycle. This page lists every breaking change and the matching migration step. See the [v2.0.0 changelog entry](https://github.com/Guard-Core/guard-core/blob/master/CHANGELOG.md) for the full list of additions.

___

Pin guard-core
--------------

```toml
guard-core = ">=2.0.0,<3"
```

All four framework adapters (fastapi-guard, flaskapi-guard, djapi-guard, tornadoapi-guard) need a release pinning `guard-core>=2.0.0`. If you use one of those adapters, upgrade it in lockstep.

___

`detect_penetration_attempt` returns `DetectionResult`
------------------------------------------------------

Both `detect_penetration_attempt()` and `detect_penetration_patterns()` now return a [`DetectionResult`](../api/detection-result.md) dataclass instead of `tuple[bool, str]`. Tuple-unpacking callers must migrate.

```python
detected, trigger = await detect_penetration_attempt(request)

result = await detect_penetration_attempt(request)
detected, trigger = result.is_threat, result.trigger_info
```

Read `result.threat_categories` and `result.threat_scores` for the new per-category metadata. The dataclass is forward-compatible, additional fields can be added without breaking call sites that read by attribute.

___

`suspicious_request_counts` is now nested
-----------------------------------------

`GuardMiddlewareProtocol.suspicious_request_counts` changed shape from `dict[str, int]` to `dict[str, dict[str, int]]`. The outer key is the IP, the inner key is the detection category, the value is the per-category count.

```python
self.suspicious_request_counts[ip] += 1

self.suspicious_request_counts.setdefault(ip, {})
counts = self.suspicious_request_counts[ip]
counts[category] = counts.get(category, 0) + 1

total = sum(self.suspicious_request_counts.get(ip, {}).values())
```

Every adapter middleware that read or wrote this attribute must migrate. The built-in `SuspiciousActivityCheck` already does this, only adapter-side reads need attention.

___

Compiled-pattern tuples are 3-tuples
------------------------------------

`SusPatternsManager` compiled-pattern collections changed from 2-tuples to 3-tuples. The third element is the category label (`"xss"`, `"sqli"`, `"custom"`, ...). Any direct iteration over `compiled_patterns` or `get_all_compiled_patterns()` must unpack three elements.

```python
for pattern, contexts in await mgr.get_all_compiled_patterns():
    ...

for pattern, contexts, category in await mgr.get_all_compiled_patterns():
    ...
```

Custom user patterns added via `add_pattern(..., custom=True)` carry the literal label `"custom"` and run regardless of `enabled_categories` filtering.

___

`_check_value_enhanced` / `_check_request_component` return 3-tuples
--------------------------------------------------------------------

Internal helpers in `guard_core.utils` now return `tuple[bool, str, list[dict]]` instead of `tuple[bool, str]`. None of the framework adapters reach into these helpers directly; the change is flagged in case downstream code does.

___

Cloud-IP cache Redis namespace migration
----------------------------------------

The Redis cache for cloud-provider IP ranges moved from `cloud_ranges` (CSV per provider) to a JSON-encoded-sorted-list namespace prefixed by `redis_prefix`; that namespace is now `cloud_ip_v2` (the legacy read path's namespace was renamed to `cloud_ranges_v2` to match), after a later release added region-carve-out support. The legacy CSV path is gated behind `CloudManager._store is None`, but `CloudManager.__new__` always seeds `_store` with an `InMemoryCloudIpStore()` and nothing resets it to `None`, so that path is unreachable at runtime; the default and `RedisCloudIpStore` both write to `cloud_ip_v2`.

If you have ops tooling, dashboards, or sidecars reading those keys directly, switch to the new namespace. See [Cloud IP Store](../api/cloud-ip-store.md) for details and the protocol contract.

___

Additive (no migration required)
--------------------------------

These additions ship in v2.0.0 but do not require any migration:

- `excluded_detection_headers`, `excluded_detection_params`, `excluded_detection_body_fields` default to empty sets, existing detection coverage is unchanged.
- `enabled_detection_categories` defaults to the full `ALL_DETECTION_CATEGORIES` set.
- `threat_ban_config` defaults to `{}` and falls back to the existing flat `auto_ban_threshold` / `auto_ban_duration` policy.
- `global_behavior_rules` defaults to `[]`.
- `lazy_init` ships in v2.0.0 defaulting to `False` (eager bootstrap: the IPInfo MMDB download and cloud-IP fetches are awaited inline during startup). v2.1.0 refined the `lazy_init=True` warmup so the first request is no longer blocked while those fetches complete; v3.1.0 then made `True` the default (background warmup). Set `lazy_init=False` to await the fetches inline for synchronous-init guarantees.
- `geo_ip_db_max_age` defaults to `86400` (matches the old hardcoded value).
- `cloud_ip_store=None` uses the in-memory store, auto-upgraded to Redis when Redis is enabled.

Adopt these incrementally as needed.
