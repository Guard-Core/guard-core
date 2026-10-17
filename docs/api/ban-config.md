---

title: Ban Configuration
description: API reference for ThreatBanConfig and the per-category ban policy on SecurityConfig
keywords: threat ban config, per-category ban, auto ban, guard-core
---

Ban Configuration
=================

`ThreatBanConfig` is the per-category ban policy model. Combined with `SecurityConfig.threat_ban_config: dict[str, ThreatBanConfig]`, it lets each detection category carry its own threshold and ban duration. Categories not present in the dict fall through to the flat `auto_ban_threshold` / `auto_ban_duration` policy.

___

ThreatBanConfig
---------------

```python
class ThreatBanConfig(BaseModel):
    threshold: int = Field(ge=1)
    duration: int = Field(ge=1)
```

| Field       | Type | Description                                                  |
|-------------|------|--------------------------------------------------------------|
| `threshold` | `int` | Number of detections in this category before auto-ban (>= 1). |
| `duration`  | `int` | Ban duration in seconds (>= 1).                              |

___

SecurityConfig.threat_ban_config
--------------------------------

```python
class SecurityConfig(BaseModel):
    threat_ban_config: dict[str, ThreatBanConfig] = Field(default_factory=dict)
```

Keys must be valid category names from `ALL_DETECTION_CATEGORIES`, plus the pseudo-category `rate_limit` (see [Rate-limit auto-ban](#rate-limit-auto-ban), below). The validator rejects unknown keys with a `ValidationError`.

___

How the policy is applied
-------------------------

Every regex hit increments `suspicious_request_counts[ip][category]`. After a hit, the suspicious-activity check evaluates the bans in this order:

1. **Per-category ban**, for each category in the current detection result, look it up in `threat_ban_config`. If the IP's count for that category has reached or exceeded the entry's `threshold`, ban the IP with `entry.duration` seconds. The audit log carries `reason="penetration_attempt:<category>"`.
2. **Flat-threshold fallback**, if no per-category ban fired, sum all category counts for this IP. If the total has reached `auto_ban_threshold`, ban the IP for `auto_ban_duration` seconds. The audit log carries `reason="penetration_attempt"`.

If neither threshold is met, the request is rejected (status 400) but the IP is not banned.

___

Rate-limit auto-ban
-------------------

`SecurityConfig.enable_rate_limit_auto_ban` (default `False`, off) feeds rate-limit violations into this same ban policy instead of just penetration detection. When enabled together with `enable_ip_banning`, each active-mode (non-passive) rate-limit violation increments the `rate_limit` category of `suspicious_request_counts` and runs the identical threshold logic described above: `threat_ban_config["rate_limit"]` first if present, otherwise the flat `auto_ban_threshold` / `auto_ban_duration` fallback. The ban lands through `ip_ban_manager.ban_ip` with `reason="rate_limit_exceeded"`, distinct from `"penetration_attempt"` so the two triggers stay separable in telemetry and audit logs. `"rate_limit"` (and `"honeypot"`, see below) is a valid `threat_ban_config` key alongside the detection categories, but it is a pseudo-category, not a member of `ALL_DETECTION_CATEGORIES`, and only ever populated when `enable_rate_limit_auto_ban` is on. Passive mode never feeds this counter, matching the detection path.

___

Honeypot bans
-------------

A request that fills a `honeypot_detection` trap field is a bot by definition, so the engine bans the client IP on the first hit. In active mode (not passive) each hit increments the `honeypot` category of `suspicious_request_counts`. The default policy is threshold `1` with `auto_ban_duration`, and `threat_ban_config["honeypot"]` overrides both, for example `ThreatBanConfig(threshold=3, duration=86400)` to ban on the third hit for a day. The ban lands through `ip_ban_manager.ban_ip` with `reason="honeypot_triggered:honeypot"` and respects `enable_ip_banning`. The request still gets the 403 from the validator (decorators.md lists what counts as a filled trap). Passive mode only logs, with no count and no ban. `"honeypot"` is a pseudo-category like `"rate_limit"`, a valid `threat_ban_config` key that is not a member of `ALL_DETECTION_CATEGORIES`. `suspicious_request_counts` is in-memory and per-process, so multi-replica deployments do not share rate-limit auto-ban counts across replicas, the same limitation the detection path already has.

___

Hostile-signal bans
-------------------

A client that keeps failing an identity or access gate is probing, so these failures can feed the same ban policy as penetration detection. The behavior is behind `SecurityConfig.ban_on_hostile_signals`, which is `False` in 4.5.0 and becomes `True` in 5.0.0. Leaving it unset logs one `DeprecationWarning` and one WARNING line at startup. With the flag off, the gates behave as in 4.4.0: the IP and user-agent denials escalate only when the request also matches a penetration-detection pattern, and the other failures count nothing.

With the flag on, each failure in active mode (not passive) increments its own pseudo-category of `suspicious_request_counts`: `auth_failure` (a missing or invalid credential, or a verifier that returns false; a verifier that raises answers 503 and never counts), `required_header` (a missing or mismatched `require_headers` entry), `referrer` (a missing or disallowed referrer), `ip_list` (a block-list hit: a `require_ip` blacklist route entry or the global `blacklist`), `country` (a `block_countries` route entry or the global `blocked_countries`), `cloud` (a route `block_clouds` or the global `block_cloud_providers`), `user_agent` (a route or global blocked user agent) and `ip_spoofing` (an untrusted public peer forging `X-Forwarded-For`, see below). Route and global denials share one category. Misses on an allow-list (`whitelist`, `whitelist_countries`, `require_ip(whitelist=...)`, `allow_countries`) are still denied but never counted, a switch that lives in one place (`ALLOW_LIST_MISSES_ARE_HOSTILE` in `guard_core/_utils/access_control.py`). The default policy for each category is threshold `auto_ban_threshold` with `auto_ban_duration`, and `threat_ban_config[<category>]` overrides both. The ban lands through `ip_ban_manager.ban_ip` with `reason="<category>_triggered:<category>"` and respects `enable_ip_banning` and the ban manager's refusal to ban loopback or trusted-proxy space. Whitelisted clients are never counted. Request size, content type, time window and HTTPS failures are not hostile signals and never count.

`ip_spoofing` counts only the clear cases: an untrusted public peer whose `X-Forwarded-For` claims an address in the global `whitelist`, in the route `require_ip` whitelist or inside `trusted_proxies`, or that sends at least three distinct `X-Forwarded-For` values within 60 seconds. A plain untrusted proxy that sends a constant `X-Forwarded-For` is only logged, at most once per peer per 60 seconds, and is never banned. Private and loopback peers are never counted, so an internal proxy missing from `trusted_proxies` is not banned.

Counters follow two rules in every version, with or without the flag. Only events from the last 3600 seconds count toward a threshold, and applying a ban clears that IP's counters, so a request right after a ban expires does not re-ban the client.

___

Block vs ban
------------

A block is a decision about one request: it is rejected and nothing about the origin is stored, so the next request from the same IP is evaluated from scratch. A ban is a decision about the IP: it is stored with an expiry and every later request from it is rejected by `IpSecurityCheck._check_banned_ip` before the remaining checks run. The caller sees the same 403 either way; the difference is entirely server-side.

| Aspect | Block | Ban |
|--------|-------|-----|
| Client sees | 403 (400 for an unbanned detection hit) | 403 |
| State retained | none | IP plus expiry, in `TTLCache` and in Redis when configured |
| Next request | full pipeline runs again | short-circuits at the ban check |
| Lifetime | that one request | `auto_ban_duration` (default 3600s) or the matching `ThreatBanConfig.duration` |

### Cost of a banned request

The ban lookup is the first thing `IpSecurityCheck` does, and `IpSecurityCheck` is registered ahead of `CloudProviderCheck`, `UserAgentCheck`, `RateLimitCheck` and `SuspiciousActivityCheck`. A banned IP therefore skips the country and cloud-provider lookups, user-agent matching, rate-limit bookkeeping and the whole payload detection sweep. Checks registered before it (route config, emergency mode, HTTPS enforcement, request size, required headers, authentication, referrer, custom validators, time window) still run, so a ban is a cheaper request, not a free one.

### Logging

A banned request is not silent. It emits one `log_activity` line at `log_suspicious_level` with `reason="Banned IP attempted access: <ip>"`, plus one `ip_blocked` event carrying `filter_type="banned"`. A fresh detection hit typically writes two lines (the detection and the block), so bans reduce log volume rather than eliminate it. Suppress the line with `muted_check_logs={"ip_security"}`.

### exclude_paths enforces bans and rate limits, not evidence-gathering

`exclude_paths` is evaluated in `BypassHandler.handle_passthrough`. A matched path no longer skips every check: `handle_passthrough` marks the request `guard_exclusion_scoped` on `request.state` and returns `None`, so the request still reaches `SecurityCheckPipeline.execute`. There, only `route_config`, `ip_security`, and `rate_limit` run for an exclusion-scoped request; every other check, including `suspicious_activity` (detection), is skipped. A banned IP is still blocked by `IpSecurityCheck._check_banned_ip` on an excluded path, a statically blacklisted or whitelisted IP, a blocked country, or a blocked cloud provider is likewise still enforced by `IpSecurityCheck._check_global_ip_restrictions`, and rate limiting still applies. What an excluded path no longer does is generate new evidence against an IP: detection does not run, so no penetration-attempt count is incremented and no auto-ban can fire from it (a block on an excluded path never calls `escalate_identity_violation` either), and `BehavioralProcessor` treats an exclusion-scoped request as having no behavior tracker, so it is never sampled for usage/frequency/return-pattern rules and can never trip a behavioral auto-ban, no matter how many times the path is hit. Reserve `exclude_paths` for endpoints, such as health checks, where skipping detection and behavioral analysis is safe but a standing ban, a static IP/country/cloud restriction, or a rate limit should still apply.

### Matrix-param dot-segments are collapsed before exclusion matching

`normalize_url_path` splits each path segment at its first `;`. When the part before the semicolon is exactly `.` or `..`, the segment is resolved as that dot-segment (and its trailing params discarded) before the traversal collapse runs; every other segment, including a real matrix parameter, is left untouched. So `/static/..;/etc/passwd` now normalises to `/etc/passwd`, which no longer starts with `/static/`, and `path_is_excluded` correctly reports it as **not** excluded when `/static` is configured in `exclude_paths`. `/static/.;x/js/app.js` normalises to `/static/js/app.js` and stays excluded, since `.;x` resolves to `.` and is dropped rather than treated as a real subdirectory. A non-dot segment such as `/orders;customer=42/items` or `/static/app.js;jsessionid=ABC123` is unaffected: its base (`orders`, `app.js`) is not `.` or `..`, so the whole segment, semicolon and params included, is preserved literally, exactly as valid RFC 3986 matrix-parameter syntax requires.

The check runs on the already percent-decoded path, so a percent-encoded semicolon (`%3b`, `%3B`, or a nested encoding such as `%253b`) is resolved to a literal `;` by the existing decode step before the dot-segment check ever runs, and is handled without any special-casing. A backslash-delimited variant (`..;\etc\passwd`) is covered the same way, since backslashes are folded to `/` before segments are split. No other separator receives this treatment: guard-core has found no evidence that any framework it ships an adapter for (Flask/Werkzeug, Starlette/FastAPI, Django) or a fronting nginx strips a comma-delimited, or otherwise-delimited, path parameter the way servlet containers strip `;params`, so `,` and every other character keep their ordinary, literal meaning. This closes the bypass regardless of deployment topology; it no longer depends on the assumption that no servlet-style component sits in front of guard-core.

What remains, and is unchanged by this fix, is the identity trade-off for non-dot matrix-param segments: `path_is_excluded` still requires an exact `/` boundary, so `/static;version=2/app.js` does not match an `/static` exclusion. If a downstream component strips a non-dot segment's params before its own routing, guard-core's view of the path can still diverge from the backend's for that literal segment, but only in the stricter direction, running the full check pipeline on a request guard-core does not recognise as excluded. That is an availability nuance, never a security one; a route that needs to tolerate stripped matrix params on a non-dot segment should use an exact-path entry in `exclude_paths` rather than a prefix.

### Without Redis

Bans live only in the process-local `TTLCache` (`maxsize=10000`, `ttl=3600`). They are still enforced, but each worker process keeps its own set, so an IP banned by one worker is unknown to the others until it misbehaves there too, and a restart clears every ban. A `duration` above `LOCAL_CACHE_TTL_CAP_SECONDS` (3600) raises `ValueError` in this mode, since the local cache cannot outlive its own TTL. With Redis attached, the ban is shared across every process and survives restarts.

### Passive mode

Passive mode never bans. Per-category counters still increment and the detection is still logged and reported, but `_handle_suspicious_passive_mode` returns without calling `ban_ip`, and an already-banned IP is logged with `action_taken="logged_only"` instead of being rejected. Bans also require `enable_ip_banning` to stay `True`.

___

Example
-------

Single-strike ban for SQL injection (week-long), 3-strike ban for XSS (one day), and the default flat policy for everything else:

```python
from guard_core.models import SecurityConfig, ThreatBanConfig

config = SecurityConfig(
    auto_ban_threshold=10,
    auto_ban_duration=3600,
    threat_ban_config={
        "sqli": ThreatBanConfig(threshold=1, duration=604800),
        "xss": ThreatBanConfig(threshold=3, duration=86400),
    },
)
```

A SQL injection hit on the first request bans the IP for one week with `reason="penetration_attempt:sqli"`. An XSS attempt on the third request bans for one day with `reason="penetration_attempt:xss"`. Twenty mixed `cmd_injection` and `recon` hits eventually trip the flat threshold and produce `reason="penetration_attempt"`.

___

See also
--------

- [SecurityConfig - Per-Category Bans](../configuration/security-config.md#per-category-bans)
- [Models - ThreatBanConfig](models.md#threatbanconfig)
- [DetectionResult](detection-result.md)
