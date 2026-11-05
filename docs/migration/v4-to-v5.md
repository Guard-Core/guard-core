---

title: Migrating from v4.x to v5.0
description: Upgrade guide for guard-core 5.0.0 - the flipped defaults, the configurations that now refuse to start, the optional extras, the changed responses and the Redis key changes, each with the setting that restores the 4.x behavior
keywords: migration, upgrade, v5, breaking changes, defaults, fail_on_misconfiguration, extras, redis, rate limit, guard-core
---

Migrating from v4.x to v5.0
===========================

`guard-core 5.0.0` changes what an existing 4.x configuration does without a code change. This page lists what you can notice after upgrading, who is affected, what you see, and the setting that keeps the 4.x behavior where one exists. The [release notes](../release-notes.md) hold the full list, including every fix.

___

Upgrade in this order
---------------------

1. Pin the new version and upgrade the adapter in lockstep: `guard-core = ">=5.0.0,<6"`. Every framework adapter needs a release that pins `guard-core>=5`.
2. Add the extras your configuration needs (see [Optional dependencies are now extras](#optional-dependencies-are-now-extras)).
3. Start the app once and read the WARNING that lists the defaults you left unset (next section). Each entry ends with the line that restores the 4.x behavior.
4. Fix or state each configuration problem that now refuses to start (see [Configurations that now refuse to start](#configurations-that-now-refuse-to-start)).
5. Check the monitors and clients that depend on a status code (see [Responses that changed](#responses-that-changed)).

To keep 4.x behavior while you migrate, state each restore line explicitly. A configuration that states every flipped default logs nothing.

___

The startup WARNING for changed defaults
----------------------------------------

When the config is built, when a field that decides a flip is assigned later, and when the middleware binds, guard-core logs one WARNING on the `guard_core.models` logger for every flipped default your configuration leaves unset. It starts with:

```text
guard-core 5.0.0 changed defaults that this configuration leaves unset: <entries>. Each default is logged once per configuration.
```

Each flip is logged once per configuration. A later evaluation that finds new flips logs one more WARNING with only those. It is a log line only, no `warnings.warn`, and the staged 4.5.0 `DeprecationWarning`s are gone. The six defaults it can name are below.

___

Defaults that flipped
---------------------

### `ban_on_hostile_signals` is now `True`

Affected: every app that left the flag unset.

Failed authentication, missing required headers, bad referrers, block-list hits and clear `X-Forwarded-For` forgery now count toward automatic IP bans, so a client that keeps failing a gate is banned at `auto_ban_threshold`.

The WARNING entry reads: `ban_on_hostile_signals is now True, so failed authentication, missing required headers, bad referrers, block-list hits and clear X-Forwarded-For forgery count toward automatic bans (restore: ban_on_hostile_signals=False)`.

Keep 4.x behavior: `ban_on_hostile_signals=False`.

### `fail_on_misconfiguration` is now `True`

Affected: every app with a configuration or route decorator that logged a misconfiguration WARNING and started under 4.x. See the next section for the list.

The WARNING entry reads: `fail_on_misconfiguration is now True, so a misconfiguration refuses to start (restore: fail_on_misconfiguration=False)`.

Keep 4.x behavior: `fail_on_misconfiguration=False`. Each misconfiguration then logs one WARNING line ending in `fail_on_misconfiguration=False keeps starting with it.` and the app starts.

### `rate_limit` is now 120 per 60 s

Affected: apps with rate limiting on that left `rate_limit` unset. The default was 10 requests per `rate_limit_window` (60 s) and is now 120.

The WARNING entry reads: `rate_limit is now 120 per 60 s, it was 10 (restore: rate_limit=10)`. It is logged only while `enable_rate_limiting` is on.

Keep 4.x behavior: `rate_limit=10`.

### `whitelist_access_only` is now `True`

Affected: apps with a non-empty global `whitelist` that left the flag unset.

The global whitelist now only admits an IP. A whitelisted IP is rate limited, user-agent checked, cloud checked and scanned for attacks like any other client, collects hostile-signal strikes, and a whitelisted address or CIDR can be banned and the ban is enforced. `request.state.is_whitelisted` is `False` for it and `request.state.whitelist_entry` names the matching entry. Emergency mode keeps its own whitelist.

The WARNING entry reads: `whitelist_access_only is now True, so a whitelisted IP is rate limited, user-agent and cloud checked, scanned for attacks and can be banned, and only exempt_ips skips those checks (restore: whitelist_access_only=False)`.

Keep 4.x behavior: `whitelist_access_only=False`. The better fix is to move the hosts that need the skips (monitoring, internal callers) into `exempt_ips`, which keeps its skips.

### A `/` entry in `exclude_paths` covers only the root page

Affected: apps with `"/"` in `exclude_paths` that left `exclude_all_paths` unset. It used to exclude every check for the whole application. It now excludes the root page only.

The WARNING entry reads: `exclude_paths entry '/' now covers only the root page, it covered the whole application (restore: exclude_all_paths=True)`.

Keep 4.x behavior: `exclude_all_paths=True`.

### `enable_redis` is no longer on by default

Affected: apps that never set `enable_redis` and never configured Redis. They used to try a Redis on localhost; they no longer connect.

Left unset, Redis is on exactly when one of `redis_url`, `redis_prefix`, `redis_socket_connect_timeout`, `redis_socket_timeout`, `redis_health_check_interval`, `redis_max_connections`, `redis_pool_timeout`, `redis_retries` or `redis_fail_open` was set explicitly (at construction or by assignment). An explicit `enable_redis` always wins. A falsy `redis_url` means no Redis at every use site.

The WARNING entry reads: `enable_redis is now off unless a Redis connection field (redis_url, redis_prefix and the other redis_* settings) is set, it was always on (restore: enable_redis=True)`. When one of those fields keeps Redis on, the entry reads instead: `enable_redis stays on because <field> is set; it is now off when no Redis connection field is set, it was always on (to state it: enable_redis=True)`.

Keep 4.x behavior: `enable_redis=True`.

### The default `redis_prefix` warning

Not a flip, but new in 5.0.0: while Redis is on and `redis_prefix` is still the default `guard_core:`, one WARNING is logged: `redis_prefix is the default 'guard_core:' while Redis is enabled: every app on the same Redis that keeps the default shares its bans and rate-limit counters. Set a unique redis_prefix per app. This warning is logged once.` Set a unique `redis_prefix` per app.

___

Configurations that now refuse to start
---------------------------------------

With `fail_on_misconfiguration=True` (the new default) these raise a `ValueError` and the app does not start. Each message ends with `Set fail_on_misconfiguration=False to start with it anyway.` and keeps the text it had as a 4.x WARNING.

Config level:

- `rate_limit` below 1, `rate_limit_window` below 1, or an `endpoint_rate_limits` entry with a limit or window below 1.
- `detection_threat_score_threshold` or `detection_semantic_threshold` at or below 0.
- An `exclude_paths` entry containing `*`, `?` or `#`: wildcards are literal characters, so it excludes nothing.
- An `exclude_paths` entry or an `endpoint_rate_limits` key with a dot segment, an empty segment, a backslash or an encoded dot or separator.
- A `security_headers` key that is not a known key.
- A `nat64_prefixes` entry that is not an IPv6 prefix of an RFC 6052 length.
- A Redis handler that lacks members the engine calls. `is_connected()` is one of them, named only under `redis_fail_open=True` and only when the handler has no `_redis` attribute either; a handler that keeps its client elsewhere adds `is_connected() -> bool`, and recovery falls back to `_redis` when it is absent.
- A `threat_ban_config` or `auto_ban_threshold` above the number of strikes one client can produce in the window under the configured `rate_limit` (the threshold could never fire).
- An `ipv6_prefix_length` that differs from the value other workers on the same Redis recorded.
- A country rule or geo rate limit with no geo source, or with `ipinfo_token` but without `maxminddb` and the tree's downloader.

Route decorator level (raised when the decorator is applied, which is at import):

- `@rate_limit` or `@geo_rate_limit` with a limit or window below 1.
- `@suspicious_frequency` with `max_frequency * window` below 1.
- `@time_window` with an invalid `HH:MM` time or an unknown IANA time zone.
- `@require_ip` with an empty whitelist or an entry that is not an IP or CIDR.
- `@allow_countries` with an empty list.
- `@block_clouds` with an unknown provider.
- `@block_countries`, `@allow_countries` and `@geo_rate_limit` when the decorator's config has no `geo_ip_handler` and no `ipinfo_token` (or has the token without `maxminddb` and the downloader). This is checked without any I/O. A decorator built from a config without a geo source but paired with a middleware config that has `ipinfo_token` now raises at import: give the decorator's config the token or the handler.
- `@detection_exclusion(path_params=...)` that names a parameter with no literal segment before it in the route template.

Keep 4.x behavior: `fail_on_misconfiguration=False`, or fix the line. With it off, the country-rule check at declaration does nothing and the init report warns once, as before.

___

Optional dependencies are now extras
------------------------------------

5.0.0 no longer installs `redis`, `maxminddb`, `aiohttp` or `requests` with guard-core. The base install carries only `cachetools`, `pydantic` and `typing-extensions` (plus `pydantic-core` and `urllib3>=2.7.0`). The extras in `pyproject.toml`:

| Extra | Installs | Needed for |
|---|---|---|
| `guard-core[redis]` | `redis` | Redis on |
| `guard-core[cloud]` | `aiohttp>=3.14.4`, `requests`, `urllib3>=2.8.0` | `block_cloud_providers`, `enable_dynamic_rules` |
| `guard-core[geo]` | `aiohttp>=3.14.4`, `maxminddb`, `requests` | country rules and the built-in geo database download |

Each adapter forwards the same extras (`fastapi-guard[redis]`, `flaskapi-guard[geo]`, `djapi-guard[cloud]`, `tornadoapi-guard[redis]`). Every import of the four packages is lazy, so `import guard_core` and an adapter's top-level import work without them, and an app that sets no Redis field, no country rule and no cloud blocking runs on the base install.

Configuring a feature whose package is missing raises a `ValueError` (a `ValidationError` from `SecurityConfig`) at construction, on assignment, on `model_copy` and on a dynamic-rule batch. The messages are:

- Redis: `enable_redis=True requires the 'redis' package. Install it with: pip install guard-core[redis]`
- Cloud: `block_cloud_providers / enable_dynamic_rules requires 'aiohttp' or 'requests'. Install it with: pip install guard-core[cloud]`
- Geo: `geo_ip_handler / country rules require the 'maxminddb' package and 'aiohttp' or 'requests' to download the database. Install them with: pip install guard-core[geo]`

Once an adapter is imported, the hint adds the adapter's own extra, for example `(or flaskapi-guard[geo])`. The config check accepts either downloader. The tree's own downloader is checked when the middleware starts: the async tree needs `aiohttp`, the sync tree (flaskapi-guard, djapi-guard) needs `requests`, and a missing one raises `DownloaderNotInstalledError` naming the extra. A Flask app with only `aiohttp` therefore passes the config check and is refused at startup for cloud blocking or the built-in GeoIP download.

Keep 4.x behavior: install the extra, or install the packages yourself.

___

Responses that changed
----------------------

| Situation | 4.x | 5.0.0 | Restore |
|---|---|---|---|
| Redis outage at request time, `fail_secure=True` and `redis_fail_open=False` | 500 | 503 with `Retry-After: 5` | `redis_fail_open=True` admits the request; otherwise accept 503 in your monitors |
| Request without the `api_key_auth` key | 400 `Missing required header`, `required_header` strike | 401 with `WWW-Authenticate: ApiKey`, counted as `auth_failure` | none |
| Missing or wrong required header | 400 naming the header | 400 `Bad request` (the reason stays in the log line and the event) | none |
| Auth verifier raises | 401 `Authentication required`, no log of the cause, `suspicious` log line, one `authentication_failed` event (`decorator_violation` when no guard decorator handler is registered with the middleware) | 503 `Authentication service unavailable` without a challenge, the cause logged at ERROR with the credential redacted, no strike, one `auth_verifier_error` event | none |
| Route with `require_auth` plus `api_key_auth` | only the bearer verifier ran | each configured credential runs its own verifier, a missing or bad one gives 401 | none |
| Request from an address outside the whitelist that also fails a verifier | 401 or 400 | 403 (IP security and rate limiting run before the identity checks) | none |
| Body past `detection_max_body_inspect_bytes` on a bounded reader | first 256 KiB scanned, rest passed | prefix scan, then 400 under `fail_secure`, a `suspicious_request` event, no strike | `fail_secure=False` |
| Multipart upload past 1 MiB | passed after a prefix scan | 400 under `fail_secure`, a `suspicious_request` event, no strike | raise `detection_max_file_inspect_bytes` (1024 to 10485760) or `@guard_deco.max_request_size(...)` on the route; `fail_secure=False` passes with the event |
| `max_request_size(0)` | no size check | 413 for any request that carries a body byte | pass `None` for no limit |
| Stalled or failed body read | silently skipped | 408 or 400 under `fail_secure`, a log line and a `suspicious_request` event, no strike | `fail_secure=False` |
| `route_resolution_strict`, unknown path or wrong method | 500 `Route resolution failed` | 404 for a path no route serves, 405 for a path another method serves | none |
| Time-window evaluation error | allowed | denied like a request outside the window (`403 Access not allowed at this time`), one ERROR log | fix the restriction |
| Global `enforce_https=True` on a route with only a rate limit or content filter | not redirected | redirected like an undecorated route | none |
| Excluded path such as `/health` in `emergency_mode` | served | `503 Service temporarily unavailable` with `Retry-After: 60` unless in `emergency_exempt_paths` | list the probe paths in `emergency_exempt_paths` (a path and its subtree, never `/`) |
| Usage `throttle` rule (route or global) under a released adapter | recorded trips, never answered | `429 Too many requests` with `Retry-After`; passive mode logs and admits | raise the threshold or window |
| Global blacklist entry on a route with `require_ip(whitelist=...)` or inside a global whitelist network | the allow-list lifted it | the blacklist always denies; `bypass(["ip"])` stays the one override | none |
| `bypass(["all"])` route | no security headers, whole pipeline ran log-only in passive mode | security headers applied, bypass applies in passive mode | none |
| Capitalized `require_auth("Bearer")` or `"Basic"` | verifier got the whole `Authorization` header | verifier gets only the credential; one WARNING per route at registration | write the lowercase type and read the credential in the verifier |

Notes on the ones that need more than a cell:

- Emergency mode: with `emergency_mode` on and an `exclude_paths` entry that looks like a probe path and is not exempted, a startup WARNING reads `[EMERGENCY MODE] exclude_paths holds <paths>, which emergency mode now blocks for every client outside the emergency whitelist. List the probe paths that must stay reachable in emergency_exempt_paths.` Loopback is not exempted automatically.
- `max_request_size(0)` logs one WARNING per route: `max_request_size(0) on <route>: 0 now refuses any request body; use None for no limit`. A negative size raises `ValueError` when the decorator is applied. If you wrote `0` to mean unlimited (nginx's `client_max_body_size 0` convention), pass `None`.
- Capitalized auth type: the WARNING reads `require_auth(type='Bearer') on <route> uses the built-in 'bearer' scheme, as HTTP auth scheme names are case-insensitive. Its verifier receives only the credential, as for type='bearer'; guard-core 4.x handed it the whole Authorization header, so a verifier that parses that header must read the credential instead. Write type='bearer' to say it plainly.`
- Upload sizes: the multipart limit is a separate field from the body limit (`262144` and `1048576` by default). A `Content-Type` is multipart only when its media type is `multipart/form-data`. A route's `max_request_size` above the applicable limit now also sets how many bytes are inspected, and it sizes the read buffer, so raise it only as far as the memory per request you accept.
- Throttle rules: `on_block` now also fires for throttle refusals (`status_code` 429, `check_name` `behavior_throttle`; in passive mode `status_code=None`).
- Monitors that treat 500 as the Redis outage signal must also accept 503. Excluded paths still run the ban lookup, so a health probe on one sees the 503 during an outage.

___

Detection changes
-----------------

Detection is wider in some places and narrower in others. Read this section if you tune `threat_ban_config`, `enabled_detection_categories` or the `excluded_detection_*` settings.

- Text that only names SQL or shell words, or shows `${...}`, `$(...)` and backticks as documentation, is no longer flagged: `select * from the shelf`, `or 1=1 is a tautology`, `export PATH=${HOME}/bin`, `${amount}`, `$(CC) $(CFLAGS)`, a word between backticks. `$(id)`, `` `id` ``, `${IFS}cat`, `' UNION SELECT` and `1 and sleep(0.5)` are still flagged. A value that was flagged only through these rows is no longer blocked, logged as a threat, counted as a strike or reported. There is no setting that brings the old matching back.
- `${7*7}` is reported as `template` only, no longer as `cmd_injection` and `template`. A `threat_ban_config` entry for `cmd_injection` no longer counts it. If you excluded `cmd_injection` for a parameter to let `${...}` through, exclude `template` as well.
- A verdict can carry more categories than in 4.x, and each is excluded and counted on its own. Absolute filesystem paths as a value add `dir_traversal`, named webshell and config-file probes add `recon` or `sensitive_file`, a command or backtick pair in the URL path adds `cmd_injection`, and an SQL injection with a comment adds a semantic `suspicious` entry to `sqli`. Which requests are flagged does not change for these values, but to clear `/appsettings.json` on one parameter you now exclude both `recon` and `sensitive_file`, and a `threat_ban_config` entry for `dir_traversal`, `recon` or `cmd_injection` can apply to a request it did not before.
- Probe-looking paths are judged by your own routes. A script path (`.php`, `.asp`, `.jsp`, `.py`, `.sh` and the other extensions) or a named path (`/management`, `/system/version`, `/language/en`, `README.md`, the CMS directories) in a URL path is flagged unless the route template the adapter matched literally contains the probe token. An adapter that gives no route knowledge behaves as 4.4.0. Adapters record the matched template as `request.state.guard_route_template`. The alternate server extensions (`.phtml`, `.php3` to `.php8`, `.phar`, `.asa`, `.ashx` and others) and tricks such as `;params`, `%00`, a trailing dot or `::$DATA` are now also covered.
- Events carry `route_template` and the metrics `endpoint` tag changed form (LEDGER 6.549). Every request-bound event sends the matched route as `route_template` (`/orgs/{org}/old/{year}`), and `request_count`, `response_time` and `error_rate` carry that normalised template in their `endpoint` tag where 4.x sent the raw one (`/items/{item_id:int}` is now `/items/{item_id}`; a Django `re_path` or Tornado regex template is now `/items/{id}`). A dashboard or alert that filters on the old `endpoint` text needs the new text, and while some agents send the old form and some the new one, one route has two series. A template with regex syntax left over (an alternation outside a group) keeps its raw form as the tag and sends no `route_template`.
- `@time_window('9:00', '17:00')` now means 09:00 to 17:00 (LEDGER 1.08). 4.x compared the text, so an unpadded hour allowed 03:00 and 10:00 alike.
- A Referer or User-Agent that names an internal address skips the `ssrf` category only when the request's Host is internal.
- `blocked_user_agents` patterns see the whole `User-Agent` header, not its first 512 characters.
- `excluded_detection_headers` skips an operator-listed header in every category (it was `ssrf` only for the built-in set, which keeps its `ssrf`-only skip). `excluded_detection_params` also accepts `{param: {categories}}`.
- `honeypot_detection` inspects every method and body shape, and a filled trap bans the client IP on the first hit (`threat_ban_config` category `honeypot`, threshold 1, `auto_ban_duration`). Passive mode only logs.
- The time-based SQLi row accepts a decimal delay (`SLEEP(2.5)`, `pg_sleep(0.5)`), so `1 AND SLEEP(2.5)` is flagged. A bare `UNION SELECT` value is flagged, with `flag_bare_union_select=False` as the opt-out of that row only.
- A repeated JSON key no longer hides an attack in its earlier copy, and a body past the scan budgets is scanned as one block per surface instead of being skipped.
- Field names containing `pass`, `pwd`, `token`, `secret`, `session`, `sid`, `auth`, `key` or `otp` (split on delimiters and camelCase) are redacted in hit logs and event previews.
- A scan that only waited for a regex worker is no longer refused as an attack: under `fail_secure=True` the request answers 400 with a `suspicious_request` event and no strike.
- The default `X-XSS-Protection` is `0`, it was `1; mode=block`. To keep the 4.x header, set `security_headers={"enabled": True, "xss_protection": "1; mode=block"}`.
- A partial `security_headers` block that leaves out `xss_protection` now sends `X-XSS-Protection: 0`, like the defaults (the 4.x adapters' readers fell back to `1; mode=block`). A block that sets it keeps its value.

___

Values refused at construction or startup
-----------------------------------------

These are refused whatever `fail_on_misconfiguration` says. The config ones raise a `ValidationError` at construction (a `ValueError` on assignment).

- CORS: `cors_allow_origins` entries must be `*`, `null` or `scheme://host[:port]` with an optional trailing `/`. `cors_allow_methods`, `cors_allow_headers` and `cors_expose_headers` entries must each be one RFC 9110 token. Split a comma-joined entry such as `"Content-Type, Authorization"` into one entry per name. A remote CORS override that breaks the rule keeps the app's own value, logs one warning and reports `cors_override_refused`. Emitted header values also refuse DEL and anything above U+00FF.
- `security_headers`: a custom header name must be one RFC 9110 token, and every value must be at most 8192 characters, hold no CR or LF, and hold only tab, space, printable ASCII and U+0080 to U+00FF. A block with `enabled: false` is not checked. A named header that is not a string, a `csp` or `hsts` that is not a mapping, or a `custom` block that is not a mapping of strings is refused too.
- A wrong-typed value in a validated field (`log_sensitive_params=42`, the IP lists, `threat_ban_config` and others) now raises a `ValidationError` naming the field, where 4.x raised a raw `TypeError`.
- `@max_request_size` with a negative size raises `ValueError`.
- On the sync engine, `custom_request_check` or `custom_response_modifier` that is an async callable raises `guard_core.exceptions.CallableShapeError` (a `TypeError`) when the middleware starts. A sync callable on the async engine runs inline on the event loop and must not block. A user-supplied async geo handler on the sync engine raises a `ValueError` at startup that names the sync class to use.

___

Redis keys and per-identity state
---------------------------------

- Rate-limit keys change shape. The route, geo and endpoint tiers write `{prefix}rate_limit:rate:{ip}:{kind}:{sha256(bucket)}` (`kind` is `endpoint`, `route` or `geo`) and the violation counter is `{prefix}rate_limit:violations:{ip}`. The bucket is also now keyed by the decorated route's identity. A mixed 4.4.0 and 5.0.0 fleet on one Redis counts the two key shapes apart until every worker is upgraded. Redis 5 or later is needed (the script reads the clock from `TIME`).
- New key families: `{prefix}detection:strikes:{ip}`, `{prefix}detection:strikes:{ip}|{category}` and `{prefix}detection:strikes_index:{ip}` (shared detection strikes), `{prefix}recidive:<identity>` (only with `enable_recidive`), `dynamic_rules:owned_bans`, and `patterns:custom_list` next to the legacy `patterns:custom`, which an earlier engine still reads.
- Behavior counters are kept per client identity. Every behavior key, counter and reader, and a behavioral `ban` rule, use the client's IPv6 network at `ipv6_prefix_length` (a /64 by default) instead of the address. IPv4 clients and `ipv6_prefix_length=128` produce the same keys as 4.4.0. A native IPv6 client moves to its network's key on upgrade, so its behavior windows restart once and neighbours in one /64 now share them. Every worker on one Redis must run the same `ipv6_prefix_length`; a worker that differs is reported through `fail_on_misconfiguration`.
- A rejected request is no longer recorded in the rate-limit window, and excluded paths and CORS preflights skip rate limiting. A client that keeps retrying is unblocked once its allowed hits expire.
- With Redis on, the rate-limit and detection auto-bans count across workers: the threshold is the configured number of violations whatever the worker count (4 workers used to need many more).
- A ban write never shortens a live ban, and a ban's local copy lives at most 3600 s on a worker. A key deleted from Redis without moving the ban version stops being enforced within an hour.
- Redis `KEYS` is gone from every prefix-wide clear and listing (`SCAN` and `UNLINK` instead). The client uses a pool of `redis_max_connections` (100 when unset); an exhausted pool waits up to `redis_pool_timeout` (default `1.0` s).

___

Behavior you may notice in the logs and events
----------------------------------------------

- `enable_rate_limiting=False` turns off the global limit only. `@rate_limit`, `@geo_rate_limit` and `endpoint_rate_limits` stay on, and startup logs one INFO line naming the routes whose limits stay on.
- The IP lists (whitelist, blacklist, `exempt_ips`, route lists, emergency whitelist, `trusted_proxies`) match through one cached index. The `X-Forwarded-For` spoof check inspects at most 32 entries from the left.
- New event types that guard-agent and the SaaS must accept: `auth_verifier_error`, `ip_ban_refused` and `response_body_unavailable`. Events also carry `matched_rule_type` and `matched_rule_id` for dynamic and behavioral rules, and `penetration_attempt` and `pattern_detected` share a random per-request `correlation_id`.
- The `guard.behavior.recent_event_count` telemetry field is no longer 0 with Redis, so severity scores from Redis deployments change in the SaaS.
- The GeoIP database download is bounded (30 s to connect, 30 s without a byte, 300 s in total, 3 attempts). The Lite schema (`country_code`) is read as well as the legacy one. The sync tree needs `urllib3>=2.7.0` and the cloud and geo extras need `aiohttp>=3.13.3`.

___

Code that touches the engine directly
--------------------------------------

- `RateLimitManager._instance` is gone and each middleware has its own manager. Code that reads or resets it raises `AttributeError`. Use `rate_limit_handler(config)` with the app's own config object, which returns the live manager. `RateLimitManager.reset()` keeps the Redis and agent handlers attached.
- Managers are per app: `ip_ban_manager_for(config)`, `sus_patterns_manager_for(config)` and `cloud_handler_for(config)` resolve the manager of an app. The module-level `ip_ban_manager`, `sus_patterns_handler` and `cloud_handler` stay the default ones. `RedisManager` is one manager per `SecurityConfig` object.
- Adapters should implement the optional `read_body_prefix_until_idle(max_bytes, idle_timeout)` and `read_body_prefix(max_bytes)`, `static_file_exists(path)` and `route_template(path)` where the framework can answer them. An adapter without the body readers still works, with one warning naming the missing method.
- `body_read_timeout` is now an idle timeout, not a total one. `async_body_read_max_concurrent` is new (default `None`, no limit) and `sync_body_read_max_concurrent` stays `64`.
- Typing only, no runtime change: `CloudIpStoreFactory` is `Callable[[RedisHandlerProtocol | None], CloudIpStoreProtocol]` (widen a factory parameter to `RedisHandlerProtocol | None`); `GuardRequest.headers` and `GuardResponse.headers` are the structural `GuardRequestHeaders` and `GuardResponseHeaders` protocols; route decorators keep the decorated function's signature (read `_guard_route_id` through `get_route_id(decorated)`); `SecurityConfig.security_headers` is `dict[str, object] | None`, so narrow a nested key before indexing it; `SecurityConfig` is generic in the request type (`SecurityConfig[RequestT]`, default `GuardRequest`).
- `unban_ip(ip)` clears that identity's strikes of both families, so a manually unbanned IP is no longer re-banned by one more strike.
