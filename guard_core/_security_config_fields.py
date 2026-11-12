from collections.abc import Awaitable, Callable
from functools import partial
from pathlib import Path
from types import MappingProxyType
from typing import Annotated, Generic, Literal

from pydantic import (
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    PlainValidator,
    model_validator,
)
from typing_extensions import Self, TypeVar

from guard_core import _tracking_caps
from guard_core._detection_constants import (
    _DEFAULT_MAX_BODY_INSPECT_BYTES,
    _DEFAULT_MAX_FILE_INSPECT_BYTES,
    ALL_DETECTION_CATEGORIES,
)
from guard_core._redis_enablement import REDIS_CONNECTION_FIELDS, resolve_enable_redis
from guard_core._security_config_cloud_store_validators import (
    _validate_cloud_ip_store_value,
)
from guard_core._security_config_field_validators import (
    EmergencyExemptPaths,
    GlobalBehaviorRules,
    PurgeTarget,
)
from guard_core._security_config_field_validators import (
    ThreatBanConfig as ThreatBanConfig,
)
from guard_core._security_config_geo_validators import _validate_geo_ip_handler_value
from guard_core._security_config_json import MappingProxyInJson, NamedInJson
from guard_core._security_config_validators import (
    _validate_excluded_detection_params_value,
)
from guard_core._security_headers_defaults import default_security_headers_config
from guard_core._staged_defaults import (
    DEFAULT_REDIS_PREFIX,
    SIGNAL_TRIGGER_FIELDS,
    signal_changed_defaults,
)
from guard_core._tracking_caps import DEFAULT_MAX_LOCAL_BANS as DEFAULT_MAX_LOCAL_BANS
from guard_core.protocols.cloud_ip_store_protocol import (
    CloudIpStoreFactory,
    CloudIpStoreProtocol,
)
from guard_core.protocols.geo_ip_protocol import GeoIPHandler
from guard_core.protocols.request_protocol import GuardRequest
from guard_core.protocols.response_protocol import GuardResponse
from guard_core.sync.protocols.geo_ip_protocol import SyncGeoIPHandler

RequestT = TypeVar("RequestT", default=GuardRequest)

CustomRequestCheck = (
    Callable[[RequestT], Awaitable[GuardResponse | None]]
    | Callable[[RequestT], GuardResponse | None]
)
CustomResponseModifier = (
    Callable[[GuardResponse], Awaitable[GuardResponse]]
    | Callable[[GuardResponse], GuardResponse]
)

DEFAULT_EXCLUDE_PATHS: tuple[str, ...] = (
    "/docs",
    "/redoc",
    "/openapi.json",
    "/openapi.yaml",
    "/favicon.ico",
    "/static",
)


def _module_cap(name: str) -> Callable[[], int]:
    """Default read from the cap constant of the light module when the config is
    built (the handlers import the config and pull in redis, so they cannot be
    imported here)."""
    return partial(getattr, _tracking_caps, name)


class _SecurityConfigFields(BaseModel, Generic[RequestT]):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    trusted_proxies: tuple[str, ...] = Field(
        default=(),
        description="Trusted proxy IPs or CIDR ranges for X-Forwarded-For",
    )

    trusted_proxy_depth: int = Field(
        default=1,
        description="How many proxies to expect in the X-Forwarded-For chain",
    )

    trust_x_forwarded_proto: bool = Field(
        default=False,
        description="Trust X-Forwarded-Proto header for HTTPS detection",
    )

    passive_mode: bool = Field(
        default=False,
        description="Enable Log-Only mode. Won't block requests, only log.",
    )

    geo_ip_handler: NamedInJson[
        Annotated[
            GeoIPHandler | SyncGeoIPHandler,
            PlainValidator(_validate_geo_ip_handler_value),
        ]
        | None
    ] = Field(
        default=None,
        description="Geographical IP handler to use for IP geolocation",
    )

    enable_redis: bool = Field(
        default=False,
        description=(
            "Enable/disable Redis for distributed state management. Left unset "
            "since 5.0.0, Redis is on exactly when at least one Redis connection "
            "field was set explicitly (redis_url, redis_prefix, "
            "redis_socket_connect_timeout, redis_socket_timeout, "
            "redis_health_check_interval, redis_max_connections, "
            "redis_pool_timeout, redis_retries or redis_fail_open) and off "
            "otherwise (before, it was always on); a field assigned after "
            "construction counts, and an explicit enable_redis always wins. A "
            "falsy redis_url means no Redis whatever enable_redis says. Pass "
            "enable_redis=True to restore the old default."
        ),
    )

    redis_url: str | None = Field(
        default="redis://localhost:6379",
        repr=False,
        description="Redis URL for distributed state management",
    )

    redis_prefix: str = Field(
        default=DEFAULT_REDIS_PREFIX,
        description="Prefix for Redis keys to avoid collisions with other apps",
    )

    redis_socket_connect_timeout: float | None = Field(
        default=2.0,
        gt=0.0,
        description=(
            "Seconds to wait establishing a Redis TCP connection before giving up. "
            "Must be positive: 0 would put the socket in non-blocking mode, not "
            "disable the timeout. None disables the timeout (a partitioned/"
            "black-holed Redis then blocks the request indefinitely), so a bounded "
            "default is strongly recommended."
        ),
    )

    redis_socket_timeout: float | None = Field(
        default=2.0,
        gt=0.0,
        description=(
            "Seconds to wait on a Redis read/write before raising. Must be "
            "positive: 0 would put the socket in non-blocking mode, not disable "
            "the timeout. None means no timeout. Keep this low: every blocked "
            "Redis call blocks a request."
        ),
    )

    redis_health_check_interval: int = Field(
        default=30,
        ge=0,
        description=(
            "Seconds between health checks on pooled connections; recycles stale "
            "sockets so the first request after an idle period doesn't fail. "
            "0 disables health checks."
        ),
    )

    redis_max_connections: int | None = Field(
        default=None,
        ge=1,
        description=("Cap on the Redis connection pool size. None uses a pool of 100."),
    )

    redis_pool_timeout: float = Field(
        default=1.0,
        gt=0.0,
        description=(
            "Seconds a Redis call waits for a free connection when every "
            "connection in the pool is in use, before it fails and "
            "redis_fail_open decides the outcome. The pool holds "
            "redis_max_connections connections (100 when that is None)."
        ),
    )

    redis_retries: int = Field(
        default=1,
        ge=0,
        description=(
            "Number of retries (with exponential backoff) on transient Redis "
            "connection/timeout errors before surfacing it. 0 disables retries."
        ),
    )

    whitelist: tuple[str, ...] | None = Field(
        default=None,
        description=(
            "Allowed IP addresses or CIDR ranges. A non-empty whitelist is "
            "restrictive: only listed IPs pass the global IP check. An explicit "
            "whitelist match does not lift the blacklist: a blacklisted entry is "
            "denied under any allow-list, and dynamic IP bans still apply."
        ),
    )

    blacklist: tuple[str, ...] = Field(
        default=(),
        description=(
            "Blocked IP addresses or CIDR ranges. Enforced ahead of country and "
            "cloud-provider checks. An explicit whitelist match does not lift it: a "
            "blacklisted entry is denied under any allow-list."
        ),
    )

    exempt_ips: tuple[str, ...] = Field(
        default=(),
        description=(
            "IP addresses or CIDR ranges that skip rate limiting and the "
            "user-agent and cloud-provider checks. Not restrictive: every other "
            "IP is checked as usual. The blacklist, dynamic IP bans, per-route IP "
            "rules and penetration detection still apply to listed IPs."
        ),
    )

    whitelist_countries: frozenset[str] = Field(
        default=frozenset(),
        description=(
            "Allowed country codes (ISO 3166-1 alpha-2). A non-empty set is "
            "restrictive: only listed countries pass the global country check, "
            "and an unresolved country is blocked. An explicit match overrides "
            "blocked_countries."
        ),
    )

    blocked_countries: frozenset[str] = Field(
        default=frozenset(),
        description="Country codes that are always blocked",
    )

    blocked_user_agents: list[str] = Field(
        default_factory=list,
        description=(
            "Blocked user agents. Each pattern scans the whole User-Agent header in "
            "512-character windows that overlap by 256, so a match of up to 256 "
            "characters (lookahead included) gets the verdict of a full-string search"
        ),
    )

    auto_ban_threshold: int = Field(
        default=10,
        ge=1,
        description="Number of suspicious requests before auto-ban",
    )

    auto_ban_duration: int = Field(
        default=3600,
        ge=1,
        description="Duration of auto-ban in seconds (default: 1 hour)",
    )

    threat_ban_config: MappingProxyInJson = Field(
        default_factory=partial(MappingProxyType, {}),
        description=(
            "Per-category ban thresholds and durations. Categories are the "
            "penetration-detection categories plus the pseudo-category "
            "'rate_limit' (used only when enable_rate_limit_auto_ban is on), "
            "'honeypot' (a filled honeypot_detection trap field bans on the first "
            "hit with auto_ban_duration unless an entry here overrides it) and the "
            "hostile-signal categories 'auth_failure', 'required_header', "
            "'referrer', 'ip_list', 'country', 'cloud', 'user_agent' "
            "(route and global block-list denials share one category) and "
            "'ip_spoofing' (an untrusted public peer forging an X-Forwarded-For "
            "that claims a whitelisted or trusted-proxy address, or sending three "
            "distinct values within a minute). Each counts one active-mode event "
            "and defaults to auto_ban_threshold / auto_ban_duration; counts "
            "cover the last hour and reset when a ban is applied. Unlisted "
            "categories fall back to auto_ban_threshold / auto_ban_duration."
        ),
    )

    ban_on_hostile_signals: bool = Field(
        default=True,
        description=(
            "Count failed authentication, missing required headers, bad "
            "referrers, block-list hits and clear X-Forwarded-For forgery toward "
            "automatic bans. On by default since 5.0.0 (it was off before); pass "
            "ban_on_hostile_signals=False to restore the old behavior."
        ),
    )

    fail_on_misconfiguration: bool = Field(
        default=True,
        description=(
            "Refuse to start when the configuration or a route decorator is "
            "misconfigured (a rate limit below 1, a zero detection threshold, an "
            "empty route allow-list and the like). On by default since 5.0.0 "
            "(it was off before, and a misconfiguration only logged a WARNING); "
            "pass fail_on_misconfiguration=False to restore that: each "
            "misconfiguration then logs one WARNING line and the app starts. The "
            "WARNING record names the line that builds the config, registers the "
            "route or binds the middleware (pathname and lineno)."
        ),
    )

    enable_rate_limit_auto_ban: bool = Field(
        default=False,
        description=(
            "Feed rate-limit violations into the same auto-ban engine used for "
            "penetration detection: each active-mode (non-passive) violation "
            "increments the 'rate_limit' category of the existing suspicious-count "
            "structure and runs the same threshold logic (threat_ban_config"
            "['rate_limit'] override first, then the flat auto_ban_threshold / "
            "auto_ban_duration). Requires enable_ip_banning to actually ban. "
            "Default off: zero behavior change unless enabled."
        ),
    )

    rate_limit_max_tracked_keys: int = Field(
        default_factory=_module_cap("_MAX_TRACKED_RATE_LIMIT_KEYS"),
        ge=1,
        description=(
            "Cap on the in-memory rate-limit windows one process keeps (one per "
            "client and limit). The oldest window is dropped when the cap is "
            "reached, so a client whose window was dropped starts a fresh one: "
            "size it above the number of distinct clients a process sees within "
            "the longest rate_limit_window. Redis-backed windows are not capped."
        ),
    )

    behavior_max_tracked_endpoints: int = Field(
        default_factory=_module_cap("_MAX_TRACKED_ENDPOINTS"),
        ge=1,
        description=(
            "Cap on the behavior-rule endpoint buckets one process keeps (one per "
            "endpoint and rule), and on the per-client rule-hit index kept in Redis "
            "(the rule keys indexed for each client, which feed the client's "
            "cross-rule recent-hits total). In memory the least recently used "
            "bucket is dropped when the cap is reached, so every client's count on "
            "it restarts and a usage, frequency or return rule's log or ban "
            "threshold can be missed; a behavior_bucket_evicted event (kind "
            "endpoint) is sent, sampled once per minute. In Redis a full index "
            "evicts nothing: the hit still counts for its own rule and only the "
            "client's cross-rule recent-hits total misses it (kind rule_hit_index, "
            "outcome refused)."
        ),
    )

    behavior_max_tracked_clients_per_endpoint: int = Field(
        default_factory=_module_cap("_MAX_TRACKED_CLIENTS_PER_ENDPOINT"),
        ge=1,
        description=(
            "Cap on the clients one behavior-rule endpoint bucket keeps in memory. "
            "The least recently used client is dropped when the cap is reached, so "
            "that client's count restarts and a usage, frequency or return rule's "
            "log or ban threshold can be missed; a behavior_bucket_evicted event "
            "(kind endpoint_client) is sent, sampled once per minute. Memory only."
        ),
    )

    behavior_throttle_max_tracked_buckets: int = Field(
        default_factory=_module_cap("MAX_TRACKED_BUCKETS"),
        ge=1,
        description=(
            "Cap on the throttle rule buckets one process keeps in memory. The "
            "least recently used bucket is dropped when the cap is reached, so "
            "every client's throttle count on it restarts and a throttled client "
            "is admitted again; a behavior_bucket_evicted event (kind "
            "throttle_bucket) is sent, sampled once per minute. Memory only."
        ),
    )

    behavior_throttle_max_tracked_clients_per_bucket: int = Field(
        default_factory=_module_cap("MAX_TRACKED_CLIENTS_PER_BUCKET"),
        ge=1,
        description=(
            "Cap on the clients one throttle bucket keeps in memory. The least "
            "recently used client is dropped when the cap is reached, so that "
            "client's throttle count restarts and a throttled client is admitted "
            "again; a behavior_bucket_evicted event (kind throttle_client) is "
            "sent, sampled once per minute. Memory only."
        ),
    )

    behavior_throttle_max_trip_markers: int = Field(
        default_factory=_module_cap("MAX_TRIP_MARKERS"),
        ge=1,
        description=(
            "Cap on the throttle episode markers one process keeps in memory. The "
            "oldest marker still running is dropped when the cap is reached; the "
            "client stays throttled and only its running episode is reported as "
            "new again; a behavior_bucket_evicted event (kind trip_marker) is "
            "sent, sampled once per minute. Memory only."
        ),
    )

    ban_counters_max_tracked_ips: int = Field(
        default_factory=_module_cap("_MAX_TRACKED_SUSPICIOUS_IPS"),
        ge=1,
        description=(
            "Cap on the client IPs whose automatic-ban violation counters one "
            "process keeps. The least recently counted IP is dropped when the cap "
            "is reached and its counters start again from zero."
        ),
    )

    ipv6_prefix_length: int = Field(
        default=64,
        ge=48,
        le=128,
        description=(
            "Prefix length at which a native IPv6 client is one identity for rate "
            "limits and bans: every address of the same prefix shares one window "
            "and one ban, so rotating addresses inside an assigned /64 gains "
            "nothing. 128 keeps one identity per address (4.4.0 behaviour). IPv4 "
            "clients, Teredo and NAT64 addresses stay per address and 6to4 "
            "addresses group by their embedded IPv4 site. All workers sharing one "
            "Redis prefix must use the same value; a rolling change is not "
            "supported."
        ),
    )

    global_behavior_rules: GlobalBehaviorRules = Field(
        default=(),
        description=(
            "Behaviour rules applied to every route, in addition to any "
            "decorator-specified rules. Useful for global 404 tracking."
        ),
    )

    behavior_scan_response_body: bool = Field(
        default=False,
        description=(
            "Read response bodies to evaluate return_pattern behaviour rules "
            "whose pattern is not a status: pattern (json:, regex:, or a bare "
            "substring). Default off: with this False, no response body is "
            "ever read for pattern matching, and such rules never match -- "
            "construction rejects one instead of accepting a rule that would "
            "silently no-op (see the return_pattern validator below). "
            "status: patterns match on status_code alone and are unaffected "
            "by this flag. Because the response body is application-produced "
            "rather than attacker-supplied, enabling this on an endpoint that "
            "streams large responses (a file download, an export, an SSE "
            "stream) means every response through that endpoint is now read "
            "up to behavior_max_response_body_inspect_bytes on every request; "
            "size the cap and pick routes accordingly."
        ),
    )

    behavior_max_response_body_inspect_bytes: int = Field(
        default=262144,
        description=(
            "Maximum bytes read from the start of a response body and held "
            "for return_pattern inspection when behavior_scan_response_body "
            "is True. This bounds what guard-core retains, not what the "
            "application produces: an adapter's BoundedResponseBodyReader "
            "implementation must buffer at most this many bytes internally "
            "and must still deliver the response's full, unbounded body to "
            "the client afterward -- a streaming response stays streaming. "
            "Only this leading prefix is ever scanned; a payload placed "
            "after it, or a signature split across the boundary, is not "
            "detected. That tradeoff is inherent to bounded-memory scanning. "
            "Distinct from detection_max_body_inspect_bytes, which bounds "
            "request bodies for penetration detection, not response bodies "
            "for behaviour rules."
        ),
        ge=1024,
        le=10485760,
    )

    body_read_timeout: float = Field(
        default=3.0,
        description=(
            "Seconds a request-body read may sit idle. Detection reads the body "
            "through the adapter's read_body_prefix_until_idle(max_bytes, "
            "idle_timeout) and passes this value as idle_timeout, so a client "
            "that keeps sending is never cut off and a client that stops "
            "sending for this long is: the adapter raises BodyReadStalledError "
            "and guard-core answers 408 when fail_secure is on, or logs it, "
            "sends an event and lets the request through when it is off (no "
            "strike either way). A read that fails, such as a dropped "
            "connection or an adapter error, answers 400 under fail_secure. An "
            "adapter without that method is read through read_body_prefix, "
            "then body, awaited in full with no deadline of its own, and one "
            "warning names the missing method; the server's own timeout is the "
            "only bound there. In both trees this is also how long a read "
            "waits for a free slot (async_body_read_max_concurrent, "
            "sync_body_read_max_concurrent) before the same 408 outcome. The "
            "sync tree reads on the request thread and never on another "
            "thread: a sync adapter applies the idle timeout to its stream or "
            "maps the server's socket timeout to BodyReadStalledError. The "
            "async tree also bounds the response-body behaviour-rule read with "
            "asyncio.wait_for."
        ),
        gt=0.0,
        le=30.0,
    )

    sync_body_read_max_concurrent: int = Field(
        default=64,
        description=(
            "Maximum number of request bodies the sync tree (guard_core.sync) "
            "reads at once, each on its own request thread. Once the limit is "
            "reached, a further request waits for a slot for up to "
            "body_read_timeout, then gets the fail_secure outcome: 408 with a "
            "log line and an event and no strike when fail_secure is on, a log "
            "line and an event and the request passes unscanned when it is "
            "off. The async tree does not read this field; it is bounded by "
            "async_body_read_max_concurrent. The bound is per process."
        ),
        ge=1,
        le=10000,
    )

    async_body_read_max_concurrent: int | None = Field(
        default=None,
        description=(
            "Maximum number of request bodies the async tree reads at once. "
            "None (the default) means no limit, as in v4.4.0: a read never "
            "waits for a slot, so a flood of slow clients is bounded by "
            "body_read_timeout and the server's own limits only. When set to "
            "N, the (N+1)th concurrent read waits for a slot for up to "
            "body_read_timeout, then gets the fail_secure outcome: 408 with a "
            "log line and an event and no strike when fail_secure is on, a "
            "log line and an event and the request passes unscanned when it "
            "is off, never a silent skip. Size it with care: N slow clients "
            "that hold every slot make each other body wait for one. The sync "
            "tree reads sync_body_read_max_concurrent instead. The bound is "
            "per process; event loops on several threads share it as a soft "
            "limit."
        ),
        ge=1,
        le=10000,
    )

    custom_log_file: str | None = Field(
        default=None,
        description="The path to a custom log file for logging security events",
    )

    log_suspicious_level: (
        Literal["INFO", "DEBUG", "WARNING", "ERROR", "CRITICAL"] | None
    ) = Field(default="WARNING", description="Log level for suspicious requests")

    log_request_level: (
        Literal["INFO", "DEBUG", "WARNING", "ERROR", "CRITICAL"] | None
    ) = Field(default=None, description="Log level for requests")

    log_country_check_level: (
        Literal["INFO", "DEBUG", "WARNING", "ERROR", "CRITICAL"] | None
    ) = Field(
        default="INFO",
        description=(
            "Log level for per-request country verdicts that are not blocks "
            "(whitelisted / not-affected). Set to None to silence them. "
            "Blocked-country hits log at log_suspicious_level instead; "
            "no-rules and no-geolocation cases always log at DEBUG."
        ),
    )

    log_format: Literal["text", "json"] = Field(
        default="text",
        description="Log output format: 'text' or 'json' for structured JSON",
    )

    custom_error_responses: dict[int, str] = Field(
        default_factory=dict, description="Custom error for specific HTTP status codes"
    )

    rate_limit: int = Field(
        default=120,
        description=(
            "Maximum requests per rate_limit_window. The default is 120 per 60 s "
            "since 5.0.0 (it was 10); pass rate_limit=10 to restore that."
        ),
    )

    rate_limit_window: int = Field(
        default=60, description="Rate limiting time window (seconds)"
    )

    enforce_https: bool = Field(
        default=False, description="Whether to enforce HTTPS connections"
    )

    security_headers: dict[str, object] | None = Field(
        default_factory=default_security_headers_config,
        description="Security headers configuration",
    )

    custom_request_check: NamedInJson[CustomRequestCheck[RequestT] | None] = Field(
        default=None,
        description=(
            "Perform additional checks on the request. An async or a sync callable "
            "in async deployments (a sync one runs inline on the event loop and "
            "must not block), a sync callable in WSGI deployments (guard_core.sync)."
        ),
    )

    auth_verifier: NamedInJson[
        Callable[[RequestT, str], Awaitable[object]]
        | Callable[[RequestT, str], object]
        | None
    ] = Field(
        default=None,
        description=(
            "Default verifier callable for require_auth and api_key_auth: "
            "verifier(request, credential) -> Principal | None. "
            "Sync or async in async deployments; "
            "sync-only in WSGI deployments."
        ),
    )

    custom_response_modifier: NamedInJson[CustomResponseModifier | None] = Field(
        default=None,
        description=(
            "A custom function to modify the response before it's sent. An async "
            "or a sync callable in async deployments (a sync one runs inline on the "
            "event loop and must not block), a sync callable in WSGI deployments "
            "(guard_core.sync)."
        ),
    )

    custom_response_modifier_max_body_bytes: int = Field(
        default=262144,
        description=(
            "Largest declared Content-Length for which the response given to "
            "custom_response_modifier exposes .body. Above it, with no declared "
            "length, for text/event-stream, and for HEAD, 204 and 304 responses, "
            ".body raises guard_core.exceptions.ResponseBodyUnavailableError (an "
            "AttributeError) and header edits still apply. When the gate allows "
            "the read, guard-core calls the modifier once, and if it read .body, "
            "calls it a second time with the bytes (code before the first .body "
            "access can run twice); a modifier with side effects is marked with "
            "guard_core.core.responses.reads_response_body and is called once. "
            "At most this many bytes are held, once per response, and shared "
            "with a return_pattern scan. The response still reaches the client "
            "in full. Default equals behavior_max_response_body_inspect_bytes."
        ),
        ge=1024,
        le=10485760,
    )

    enable_cors: bool = Field(default=False, description="Enable/disable CORS")

    cors_allow_origins: list[str] = Field(
        default_factory=partial(list, ("*",)),
        description="Origins allowed in CORS requests",
    )

    cors_allow_methods: list[str] = Field(
        default_factory=partial(
            list, ("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS")
        ),
        description="Methods allowed in CORS requests",
    )

    cors_allow_headers: list[str] = Field(
        default_factory=partial(list, ("*",)),
        description="Headers allowed in CORS requests",
    )

    cors_allow_credentials: bool = Field(
        default=False, description="Whether to allow credentials in CORS requests"
    )

    cors_expose_headers: list[str] = Field(
        default_factory=list, description="Headers exposed in CORS responses"
    )

    cors_max_age: int = Field(
        default=600, description="Maximum age of CORS preflight results"
    )

    block_cloud_providers: frozenset[str] | None = Field(
        default=None,
        description=(
            "Cloud providers to block: AWS, GCP, Azure, DigitalOcean, Linode, "
            "Vultr. A bare provider ('GCP') blocks the whole provider; a region "
            "carve-out ('GCP:!us-central1') blocks the provider except that "
            "region. Region metadata exists for AWS and GCP only; the other "
            "providers publish no region data, so a carve-out on them exempts "
            "nothing and the whole provider stays blocked. An unrecognized "
            "provider name raises ValueError rather than being silently dropped."
        ),
    )

    cloud_ip_refresh_interval: int = Field(
        default=3600,
        description="Interval in seconds between cloud IP range refreshes",
        ge=60,
        le=86400,
    )

    lazy_init: bool = Field(
        default=True,
        description=(
            "When True (default), guard-core defers cloud-IP HTTP fetches and "
            "geo-IP MMDB downloads to a background task, so the application does "
            "not block on multi-second network calls. This only takes effect when "
            "Redis is enabled (enable_redis=True and a redis_handler is wired) "
            "and the consuming adapter calls initialize_redis_handlers() at "
            "startup: fastapi-guard's SecurityMiddleware and "
            "PureASGISecurityMiddleware do it when the ASGI lifespan startup runs "
            "(before the server listens, no opt-out), while adapters without a "
            "lifespan scope (Flask, Django, Tornado) do it on the first request. "
            "Without Redis, or without that startup call, cloud/geo "
            "initialization instead happens through their on-demand paths and "
            "this flag has no effect. "
            "First requests may see partially-populated cloud-IP ranges until "
            "the background task completes (typically 1-3 seconds). "
            "Set to False only if you require synchronous-init guarantees and "
            "are willing to block app startup until all initial network calls finish."
        ),
    )

    geo_ip_db_max_age: int = Field(
        default=86400,
        ge=3600,
        le=604800,
        description=(
            "Maximum age in seconds, from the file's modification time, before "
            "the IPInfo MMDB is downloaded again in the background."
        ),
    )

    whitelist_access_only: bool = Field(
        default=True,
        description=(
            "Make the global whitelist access-only: it admits a listed IP and "
            "nothing more. On since 5.0.0: the IP is checked by rate limiting, the "
            "user-agent check, the cloud-provider check and attack detection like "
            "any other client (request.state.is_whitelisted is False and request."
            "state.whitelist_entry names the matching entry), collects "
            "hostile-signal strikes, and a whitelisted address or CIDR can be "
            "banned and the ban is enforced. exempt_ips keeps its skips. Emergency "
            "mode keeps its own whitelist. Pass whitelist_access_only=False to "
            "restore the old behavior, where a whitelisted IP also skips those "
            "checks (request.state.is_whitelisted is True for it)."
        ),
    )

    banned_ips_max_entries: int = Field(
        default=_tracking_caps.DEFAULT_MAX_LOCAL_BANS,
        ge=1,
        description=(
            "Cap on the bans one process keeps in memory (addresses and grouped "
            "identities, 100,000 by default, about 25 MiB when full), >= 1. At the "
            "cap the ban closest to expiry is evicted first, the first and "
            "every hundredth unexpired eviction is logged, and every eviction of "
            "a ban that has no Redis copy is sent as an ip_ban_evicted event. "
            "With Redis the bans themselves are not capped."
        ),
    )

    enable_recidive: bool = Field(
        default=False,
        description=(
            "Lengthen the automatic ban of a client that is banned again within "
            "recidive_window. The k-th earlier ban in the window multiplies the "
            "duration by recidive_factor ** k, capped at recidive_max_duration "
            "and never below the duration the call asked for. Counts only the "
            "bans applied by the automatic ban engine to an address or a grouped "
            "identity; operator CIDR bans, dynamic-rule bans and manual bans "
            "neither escalate nor count. Off by default."
        ),
    )

    recidive_factor: float = Field(
        default=2.0,
        gt=1,
        description=(
            "Multiplier per earlier ban in the window, > 1 (a factor of 1 would "
            "change nothing). Used when enable_recidive is on."
        ),
    )

    recidive_window: int = Field(
        default=86400,
        ge=1,
        description=(
            "Seconds a ban counts toward the next one, measured from the end of "
            "the last ban. An unban clears the history; a natural expiry keeps it "
            "for this long. Used when enable_recidive is on."
        ),
    )

    recidive_max_duration: int = Field(
        default=604800,
        ge=1,
        description=(
            "Cap in seconds on an escalated ban duration (7 days by default); "
            "must be >= auto_ban_duration when enable_recidive is on. A duration "
            "the call asked for that is already above the cap is applied as it "
            "is, escalation never shortens a ban."
        ),
    )

    nat64_prefixes: list[str] = Field(
        default_factory=list,
        description=(
            "Network-specific NAT64 prefixes (RFC 6052, lengths /32, /40, /48, /56, "
            "/64 and /96) of the translator in front of the app. A client "
            "arriving as an address inside one is attributed to the global IPv4 "
            "address embedded in it, so IPv4 lists, cloud ranges, bans and rate "
            "limits see the real client. The well-known prefix 64:ff9b::/96 is "
            "always decoded; an embedded non-global IPv4 address (10.0.0.5) is "
            "never unwrapped. An entry of another length or family is reported "
            "as a misconfiguration at startup and ignored."
        ),
    )

    country_rules_exempt_private_peers: bool = Field(
        default=False,
        description=(
            "Exempt a private, link-local or carrier-grade-NAT peer from the "
            "country rules when its request carries no X-Forwarded-For header. "
            "Off by default: behind Docker Desktop or rootless Docker every "
            "internet client reaches the app as a private peer without that "
            "header, so the exemption would switch the country rules off for "
            "them. A peer that sends X-Forwarded-For is never exempt."
        ),
    )

    block_empty_user_agent: bool = Field(
        default=False,
        description=(
            "Block a request whose User-Agent header is absent, empty or blank, "
            "as a global user-agent denial (403, a user_agent_blocked event, and a "
            "hostile-signal count under ban_on_hostile_signals). Off by default: "
            "some legitimate clients and health probes send no User-Agent."
        ),
    )

    flag_bare_union_select: bool = Field(
        default=True,
        description=(
            "Flag a scanned value that is only UNION SELECT (or UNION ALL SELECT) "
            "with no select list, as sqli. On by default since 5.0.0, as v4.4.0 "
            "flagged it. False turns off only this row, for every parameter of "
            "the app, and gives the 5.0.0 head from before this row (351 of the "
            "354 UNION lines of the public SQLi corpus; v4.4.0 flags all 354); "
            "it does not restore any 4.x behaviour. A free-text field that must "
            "accept those two words as a benign value is better excluded per "
            "parameter with excluded_detection_params, which drops every sqli "
            "row on that parameter. The row is anchored on the whole value, so "
            "prose that merely contains the words (how to union select two "
            "tables) is never flagged."
        ),
    )

    cloud_ip_store: NamedInJson[
        Annotated[CloudIpStoreProtocol, PlainValidator(_validate_cloud_ip_store_value)]
        | CloudIpStoreFactory
        | None
    ] = Field(
        default=None,
        description=(
            "Override the default cloud IP store. Accepts either an instance "
            "implementing CloudIpStoreProtocol, or a callable that takes the "
            "Redis handler and returns a store (used to defer construction "
            "until the redis_handler is available). When None (default), "
            "guard-core auto-constructs a RedisCloudIpStore if Redis is enabled."
        ),
    )

    exclude_paths: list[str] = Field(
        default_factory=partial(list, DEFAULT_EXCLUDE_PATHS),
        description=(
            "Paths to exclude from security checks. An entry covers that path "
            "and everything under it; the literal '/' entry covers only the "
            "root page since 5.0.0 (before, it covered the whole application: "
            "use exclude_all_paths=True to keep that)."
        ),
    )

    exclude_all_paths: bool = Field(
        default=False,
        description=(
            "Skip every security check for every request. Before 5.0.0 the "
            "literal '/' entry in exclude_paths did this; since 5.0.0 that "
            "entry covers only the root page, and this field is how to exclude "
            "the whole application. A request path with a routing anomaly is "
            "still never excluded."
        ),
    )

    enable_ip_banning: bool = Field(
        default=True, description="Enable/disable IP banning functionality"
    )

    enable_rate_limiting: bool = Field(
        default=True, description="Enable/disable rate limiting functionality"
    )

    enable_penetration_detection: bool = Field(
        default=True, description="Enable/disable penetration attempt detection"
    )

    fail_secure: bool = Field(
        default=True,
        description=(
            "Block the request when any security check raises an unexpected exception. "
            "True (default) returns HTTP 500 so check bugs surface; "
            "False logs and falls through (fail-open) - "
            "opt-in only for staging diagnostics."
        ),
    )

    redis_fail_open: bool = Field(
        default=False,
        description=(
            "On GuardRedisError (Redis unreachable), skip the failing check "
            "and let the request through instead of honoring fail_secure. "
            "Defaults to False so fail_secure is the single source of truth "
            "for every check failure, including Redis outages. Set True to "
            "opt into treating Redis outages as an availability concern "
            "distinct from other check failures."
        ),
    )

    route_resolution_strict: bool = Field(
        default=False,
        description=(
            "Block the request when the adapter reports that it could not "
            "resolve the route, instead of running the pipeline with no "
            "per-route config. A missing route config normally means the route "
            "carries no decorators, so the default (False) preserves that and "
            "lets undecorated routes and unrouted requests through. Set True "
            "when every request must be attributable to a known route, so a "
            "resolution failure cannot silently skip per-route checks - note "
            "that this also blocks requests to paths the app does not serve: "
            "guard-core answers 404 for a path no route serves and 405 for a "
            "wrong method, never the app's own page. CORS preflights are "
            "answered before this check."
        ),
    )

    ipinfo_token: str | None = Field(
        default=None,
        repr=False,
        description="IPInfo API token used to fetch IP geolocation data from "
        "the IPInfo API.",
    )

    ipinfo_db_path: Path | None = Field(
        default=Path("data/ipinfo/country_asn.mmdb"),
        description="Path to the local IPInfo MMDB database file used for IP "
        "geolocation.",
    )

    ipinfo_download_url: str = Field(
        default="https://ipinfo.io/data/free/country_asn.mmdb",
        pattern=r"^https://[^/\s]+",
        description="HTTPS URL the IPInfo MMDB database is downloaded from, "
        "sent with the ipinfo_token as a Bearer header. The default is the "
        "file IPInfo labels Legacy; IPInfo's current file is "
        "https://ipinfo.io/data/ipinfo_lite.mmdb. Only https:// is accepted.",
    )

    enable_agent: bool = Field(
        default=False, description="Enable Guard Agent telemetry and monitoring"
    )

    agent_api_key: str | None = Field(
        default=None, repr=False, description="API key for Guard Agent SaaS platform"
    )

    agent_strict: bool = Field(
        default=False,
        description=(
            "When True, an enabled agent that cannot be initialized raises "
            "instead of degrading to agent-off. A missing guard-agent package or "
            "an invalid agent configuration raises at SecurityConfig "
            "construction, whatever fail_on_misconfiguration says. The remaining "
            "runtime case (building the agent handler) surfaces when the "
            "middleware stack is built, and a server started with its lifespan "
            "required fails to start."
        ),
    )

    on_error: NamedInJson[
        Callable[[str, BaseException, dict[str, object]], None] | None
    ] = Field(
        default=None,
        description=(
            "Optional best-effort callback invoked when a middleware/agent step "
            "fails, receiving (stage, exception, context). stage is one of "
            "'agent_init', 'geoip', 'transport_send', 'encryption'. A callback "
            "that raises is caught and logged, never propagated."
        ),
    )

    on_block: NamedInJson[Callable[[GuardRequest, dict[str, object]], None] | None] = (
        Field(
            default=None,
            description=(
                "Optional best-effort callback invoked exactly once per blocked or "
                "passive-mode-flagged request, receiving (request, payload). payload "
                "keys: check_name, reason, trigger_info, passive_mode, client_ip, "
                "path, method, status_code (None on the passive-mode path, where no "
                "response is ever sent). Not fired for custom_request_check or "
                "route_config.custom_validators (application-authored, the app "
                "already knows), except a honeypot_detection hit, which fires with "
                "check_name 'honeypot'. Also not fired for the HTTPS-enforcement "
                "redirect (a redirect is not a block), or an adapter's "
                "Redis-unavailable response (see on_error). Sync or async in async "
                "deployments; sync-only in WSGI deployments, where an async callback "
                "raises TypeError. A callback that raises is caught and logged, never "
                "propagated."
            ),
        )
    )

    agent_endpoint: str = Field(
        default="https://api.guard-core.com",
        description="Guard Agent SaaS platform endpoint",
    )

    agent_project_id: str | None = Field(
        default=None, description="Project ID for organizing telemetry data"
    )

    agent_buffer_size: int = Field(
        default=100, description="Number of events to buffer before auto-flush"
    )

    agent_flush_interval: int = Field(
        default=30, description="Interval in seconds between automatic buffer flushes"
    )

    agent_enable_events: bool = Field(
        default=True, description="Enable sending security events to SaaS platform"
    )

    agent_enable_metrics: bool = Field(
        default=True, description="Enable sending performance metrics to SaaS platform"
    )

    agent_timeout: int = Field(
        default=30, description="Timeout in seconds for agent HTTP requests"
    )

    agent_retry_attempts: int = Field(
        default=3, description="Number of retry attempts for failed requests"
    )

    agent_project_encryption_key: str | None = Field(
        default=None,
        repr=False,
        description=(
            "Per-project AES-256-GCM key used to encrypt the telemetry payload "
            "between the agent and the SaaS. When set, the agent posts to "
            "/api/v1/events/encrypted instead of /api/v1/events. Required for "
            "API keys that have encryption enforced server-side."
        ),
    )

    agent_guard_version: str | None = Field(
        default=None,
        description=(
            "Framework wrapper version (e.g. fastapi-guard's __version__) "
            "propagated to the agent so the SaaS can attribute telemetry to "
            "the wrapper version, not just the agent version. Set this to "
            "your framework integration's __version__ at construction time."
        ),
    )

    agent_high_watermark_ratio: float | None = Field(
        default=None,
        description=(
            "Buffer occupancy ratio that triggers an early flush. "
            "None defers to the agent's own default."
        ),
    )

    agent_max_concurrent_flushes: int | None = Field(
        default=None,
        description=(
            "Maximum concurrent early-flush operations. "
            "None defers to the agent's own default."
        ),
    )

    agent_buffer_overflow_policy: Literal["drop", "block", "raise"] | None = Field(
        default=None,
        description=(
            "Behavior when the agent's in-memory buffer is full. 'drop' "
            "silently evicts the oldest entry, 'block' awaits free space and "
            "backpressures the caller, 'raise' throws BufferFullError so "
            "callers can react. None defers to the agent's own default "
            "('drop')."
        ),
    )

    agent_backoff_factor: float | None = Field(
        default=None,
        description=(
            "Backoff factor for agent HTTP retries. "
            "None defers to the agent's own default."
        ),
    )

    agent_sensitive_headers: list[str] | None = Field(
        default=None,
        description=(
            "Header names excluded from telemetry payloads. "
            "None defers to the agent's own default."
        ),
    )

    agent_max_payload_size: int | None = Field(
        default=None,
        description=(
            "Maximum payload size in bytes to include in telemetry events. "
            "None defers to the agent's own default."
        ),
    )

    agent_compression_enabled: bool | None = Field(
        default=None,
        description=(
            "Gzip-compress outgoing telemetry batch bodies above "
            "agent_compression_threshold bytes. "
            "None defers to the agent's own default."
        ),
    )

    agent_compression_threshold: int | None = Field(
        default=None,
        description=(
            "Minimum body size in bytes before gzip compression applies. "
            "None defers to the agent's own default."
        ),
    )

    agent_install_id: str | None = Field(
        default=None,
        description=(
            "Override the agent install ID. "
            "None auto-generates one, the agent's own default."
        ),
    )

    agent_payload_signing_secret: str | None = Field(
        default=None,
        repr=False,
        description="HMAC-SHA256 secret used to sign the X-Payload-Signature header.",
    )

    enable_dynamic_rules: bool = Field(
        default=False,
        description=(
            "Lets the SaaS dashboard change protection at runtime without a "
            "code change: a rule bans the IPs in its ip_blacklist (for "
            "ip_ban_duration seconds), unbans the IPs in its ip_whitelist, adds "
            "its suspicious_patterns to detection, adds its blocked_countries, "
            "block_cloud_providers and blocked_user_agents to the ones you "
            "configured (a rule never removes a static entry), merges its "
            "endpoint_rate_limits per endpoint with the static map (the rule's "
            "value wins on the endpoints it names, static limits on the others "
            "keep applying), and replaces whitelist_countries, rate_limit, "
            "rate_limit_window, enable_penetration_detection, enable_ip_banning, "
            "enable_rate_limiting, enable_rate_limit_auto_ban, auto_ban_threshold, "
            "auto_ban_duration, emergency_mode, emergency_whitelist and "
            "emergency_whitelist_only while it is active. "
            "Requires enable_agent."
        ),
    )

    dynamic_rule_interval: int = Field(
        default=300,
        ge=60,
        description="Interval in seconds between dynamic rule updates",
    )

    purge_dynamic_rules_on_start: PurgeTarget = Field(
        default=None,
        description=(
            "'rule_id:version' of a dashboard rule set to drop locally at every "
            "start, whatever enable_dynamic_rules says: when the last-known "
            "snapshot holds that set, the bans it owns are lifted (down to a "
            "shorter ban they hid, if any), its patterns removed and its "
            "snapshots deleted, and a marker keeps every worker from applying it "
            "again until the SaaS answers a fresh check. A WARNING at every start "
            "reminds you to unset it once the SaaS is back."
        ),
    )

    dynamic_rules_cache_path: Path | None = Field(
        default=None,
        description="Optional local JSON file persisting the last-known dynamic "
        "rules snapshot so a restart during a SaaS outage restores the last "
        "applied rules instead of base config. Redis holds the primary snapshot "
        "whenever a redis_handler is present; the file is an additional "
        "opt-in fallback that is only written and read when this path is set.",
    )

    agent_status_interval: int = Field(
        default=300,
        ge=60,
        le=86400,
        description="Interval in seconds between agent status reports to the SaaS",
    )

    emergency_mode: bool = Field(
        default=False, description="Emergency lockdown mode (set by dynamic rules)"
    )

    emergency_whitelist: list[str] = Field(
        default_factory=list,
        description="Emergency whitelist IPs (set by dynamic rules)",
    )

    emergency_whitelist_only: bool = Field(
        default=True,
        description="During emergency mode, admit only emergency_whitelist IPs. "
        "False keeps the lockdown but also admits whitelist, exempt_ips and the "
        "ip_whitelist entries of the active dynamic rule "
        "(set by dynamic rules)",
    )

    emergency_exempt_paths: EmergencyExemptPaths = Field(
        default_factory=list,
        description="Paths (and their subtrees) that emergency mode leaves open "
        "to every client, such as a health probe path. Emergency mode covers "
        "every other path, exclude_paths entries included. Loopback is never "
        "exempted automatically.",
    )

    endpoint_rate_limits: dict[str, tuple[int, int]] = Field(
        default_factory=dict,
        description=(
            "Per-endpoint rate limits {path: (requests, window)}, also set by "
            "dynamic rules. A limit follows the handler, not the path: each "
            "adapter resolves every key through its own router and a request "
            "matches a key when it reaches the same handler with the same path "
            "parameters, so a concrete-id key stays per resource. Two paths on "
            "one handler share one budget (@app.route('/login') and "
            "@app.route('/signin') on one view count against one limit, which "
            "stops a stacked path from getting a fresh budget), and a generic "
            "view stacked on many paths shares one budget too, so give each "
            "limited path its own handler. A key that resolves to no route "
            "falls back to the normalized path. See the 5.0.0 release note "
            "'An endpoint limit follows the handler, not the path'."
        ),
    )

    detection_compiler_timeout: float = Field(
        default=2.0,
        description=(
            "Time (seconds) one pattern may use, judged by the CPU the pattern itself "
            "used (a custom pattern by its worker's CPU when the worker finishes, a "
            "built-in pattern by the scan's own CPU), so waiting for the GIL or a free "
            "worker is not counted. The six windowed built-in rows run on the request "
            "thread, and a started custom scan is cut only at "
            "detection_max_scan_seconds of wall time. Waiting for a free worker is "
            "bounded by the same value and ends the scan as incomplete (503 with a "
            "Retry-After of this many seconds, an event and no strike under "
            "fail_secure, a pass with the event otherwise); a pool held by stuck "
            "workers is still replaced."
        ),
        ge=0.1,
        le=10.0,
    )

    detection_max_scan_seconds: float = Field(
        default=10.0,
        description=(
            "Cap on the CPU time (seconds) spent regex scanning one request, "
            "not wall time, summed across every field and every pattern. Once reached, "
            "remaining patterns and values are not scanned and the request "
            "receives a weighted pattern_timeout threat that counts toward the "
            "anomaly score, so padding a request cannot skip detection."
        ),
        ge=0.1,
        le=60.0,
    )

    detection_pattern_validation_cache_path: str | None = Field(
        default=None,
        description=(
            "Optional file path for a disk-backed pattern-validation cache. "
            "When set, the empirical cost-verdict outcome of "
            "validate_pattern_safety (probe synthesis plus timed subprocess "
            "probes) is cached keyed by pattern, flags, and engine version, "
            "so a process boot reuses prior certifications instead of "
            "re-timing every custom pattern; the cheap deterministic layers "
            "(dangerous constructs, compile check, structural detectors) "
            "always re-run. Cache entries from a different engine version "
            "are ignored and overwritten. Leave unset (the default) to keep "
            "every validation fully empirical. Aimed at shared-nothing "
            "workers and hosts where subprocess spawn latency makes "
            "startup validation prohibitively slow."
        ),
    )

    detection_max_content_length: int = Field(
        default=10000,
        description=(
            "Budget for the semantic (ML) analyzer's slice of preprocessed "
            "content, and the divisor behind how many attack-indicator regions "
            "extract_attack_regions keeps during truncation. It does NOT bound "
            "truncate_safely's own output size or the regex-pattern scan window: "
            "that memory bound is the larger of detection_max_body_inspect_bytes "
            "and detection_max_file_inspect_bytes, so raising or lowering this "
            "field never changes how much content the penetration-detection "
            "regex patterns see."
        ),
        ge=1000,
        le=100000,
    )

    detection_max_body_inspect_bytes: int = Field(
        default=_DEFAULT_MAX_BODY_INSPECT_BYTES,
        description=(
            "Maximum bytes read from the start of the request body and inspected "
            "for penetration detection. A body up to this cap is scanned in "
            "full. A body past it is never passed unscanned: an adapter with a "
            "bounded reader (read_body_prefix) has its first N bytes scanned and, "
            "when they are clean, the request gets the body-read failure "
            "outcome; an adapter without one has the body left unread and gets "
            "the same outcome. That outcome is a 400 when fail_secure is on, an "
            "event and no strike; with fail_secure off it is logged and the "
            "request passes on the prefix scan alone. Raise the cap to scan "
            "larger bodies in full, at the cost of more memory held per "
            "inspected request and more CPU time spent pattern-matching it, "
            "since the full-body scan window and truncate_safely's own output "
            "size both follow this same cap. A route whose max_request_size is "
            "above this cap uses that value as its own inspect cap. For a "
            "request that is not multipart/form-data this is the memory bound "
            "for the whole preprocessing path: gzip-bomb decompression inside "
            "base64 decoding and the short-base64 additive view are bounded by "
            "it too, not by any separate constant. "
            "Distinct from detection_max_content_length (the semantic-analyzer "
            "budget) and max_request_size (the 413 size gate). A request whose "
            "Content-Type is multipart/form-data does not use this cap: it uses "
            "detection_max_file_inspect_bytes, so this field is not the memory "
            "bound for uploads. The full-body scan window and the pattern "
            "validation cap follow the larger of the two limits, so lowering "
            "only this field does not lower what a multipart request holds or "
            "scans. A route's max_request_size, which v4.4.0 used only for the "
            "413 gate, now also sets how many bytes are inspected when it is "
            "above the applicable limit: about 0.7 to 0.85 CPU seconds per MB "
            "of text and, on the async tree, an event-loop stall of about 0.18 "
            "s per MB of clean body (0.37 s at 2 MB, 0.71 to 0.74 s at 4 MB)."
        ),
        ge=1024,
        le=10485760,
    )

    detection_max_file_inspect_bytes: int = Field(
        default=_DEFAULT_MAX_FILE_INSPECT_BYTES,
        description=(
            "The inspect limit for a request whose Content-Type is "
            "multipart/form-data, which is where file uploads arrive; every "
            "other request body keeps detection_max_body_inspect_bytes. The "
            "default is 1048576 (1 MiB). A multipart body up to this limit is "
            "scanned in full. A body past it is never passed unscanned: it is "
            "refused with a 400 when fail_secure is on, as an event and no strike, "
            "and with fail_secure off it is logged and passes on the prefix scan "
            "alone, exactly as for detection_max_body_inspect_bytes. Raise it to "
            "accept larger uploads, at the cost of more memory held per inspected "
            "upload and more CPU time spent pattern-matching it. A route whose "
            "max_request_size is above this limit uses that value as its own "
            "inspect limit. Distinct from max_request_size (the 413 size gate). "
            "To accept uploads larger than the limit, raise it for every upload "
            "(SecurityConfig(detection_max_file_inspect_bytes=5_000_000)) or for "
            "one route (@guard_deco.max_request_size(5 * 1024 * 1024)). Cost, "
            "measured with 64 read slots busy: 0.66 to 0.85 CPU seconds per MB "
            "of text multipart and 0.10 to 0.18 per MB of binary multipart (the "
            "v4.4.0 figure of 0.0114 is not equal work, it scanned a smaller "
            "window). Memory: about 7.5 to 13.8 MB per in-flight 1 MiB upload, "
            "and a peak of 386.6 to 908.5 MB at 1 MiB with 64 slots busy. The "
            "async tree has no read-slot cap by default "
            "(async_body_read_max_concurrent is None), so its memory is that "
            "per-upload figure times the uploads in flight. The scan window and "
            "the pattern validation cap follow the larger of this limit and "
            "detection_max_body_inspect_bytes. A route's max_request_size, "
            "which v4.4.0 used only for the 413 gate, now also sets how many "
            "bytes are inspected when it is above the applicable limit, at the "
            "same cost (about 0.7 to 0.85 CPU seconds per MB of text and, on "
            "the async tree, an event-loop stall of about 0.18 s per MB of "
            "clean body: 0.37 s at 2 MB, 0.71 to 0.74 s at 4 MB)."
        ),
        ge=1024,
        le=10485760,
    )

    detection_max_scan_values: int = Field(
        default=512,
        description=(
            "Maximum number of individual values (query parameters, header "
            "values, JSON keys and leaf values, form fields, multipart parts) "
            "scanned per request across the whole penetration-detection pass. "
            "Once reached, each surface (query, headers, body) scans its "
            "remaining values once more as one block, in scan order, instead "
            "of skipping them, and a one-time warning is logged naming the "
            "client IP. Bounds worst-case CPU "
            "on a request padded with many benign values ahead of a real "
            "payload; the standard detection benchmarks never approach this "
            "cap. Each named value costs two scan units, one for its name and "
            "one for its value, so a cap of 1 could never scan a value; the "
            "minimum is 2."
        ),
        ge=2,
        le=100_000,
    )

    detection_max_scan_chars: int = Field(
        default=65536,
        description=(
            "Maximum total characters, across every value handed to the "
            "pattern engine per request (query parameters, header values, "
            "JSON keys and leaf values, form fields, multipart parts, "
            "including JSON embedded within a single value), counted at the "
            "same accounting point as detection_max_scan_values. Once "
            "reached, the remaining values of each surface are scanned once "
            "more as one block instead of being skipped, and a one-time "
            "warning is logged naming the client IP, the same signal "
            "detection_max_scan_values gives. "
            "Bounds worst-case CPU on a request whose values are individually "
            "large (a handful of large values can cost as much CPU as many "
            "small ones), a gap detection_max_scan_values alone does not "
            "close (GHSA-3hfx-8m47-5f9h residual)."
        ),
        ge=1024,
        le=262144,
    )

    detection_max_json_depth: int = Field(
        default=32,
        description=(
            "Maximum nesting depth of a JSON request body walked structurally "
            "during penetration detection. A dict or list encountered at this "
            "depth is not descended into: it is serialized back to text and "
            "scanned as a single value instead, bounded by "
            "detection_max_content_length, so content hidden below the cap is "
            "still scanned, just as text rather than structurally. Once "
            "reached, a one-time warning is logged naming the client IP. "
            "Bounds worst-case call-stack and CPU usage on a deeply nested "
            "JSON body; the standard detection benchmarks never approach this "
            "cap."
        ),
        ge=1,
        le=1000,
    )

    detection_binary_min_run_length: int = Field(
        default=16,
        description=(
            "Minimum length a consecutive printable-character run inside a "
            "binary-dense multipart file-part payload must reach before that "
            "run is handed to the pattern scan. A part payload is binary-"
            "dense when binary artifact characters make up at least a fifth "
            "of it; text uploads and short or mostly-text payloads never "
            "reach that ratio and keep their full scan, and whole-body "
            "fallback scans are never island-reduced because raw-body "
            "signature coverage (pickle opcodes, wide-encoding payloads, "
            "null-byte shapes) must stay intact. Compressed or encrypted "
            "bytes decode into text views where attack-shaped printable "
            "fragments are statistical noise whose rate grows with file "
            "size, so runs below this length are skipped instead of "
            "matched. Text genuinely embedded in an upload (a script "
            "inside a PDF, a stored path inside an archive, a whole "
            "text-file upload) forms runs past the threshold and is still "
            "scanned in full. File names, multipart field names, and part "
            "headers are always scanned regardless. The tradeoff is that "
            "an attack pattern whose printable characters are shorter than "
            "this run, or split by embedded binary bytes, inside a binary-"
            "dense upload payload is not detected."
        ),
        ge=4,
        le=1024,
    )

    detection_preserve_attack_patterns: bool = Field(
        default=True,
        description="Preserve attack patterns during content truncation",
    )

    detection_semantic_threshold: float = Field(
        default=0.7,
        description=(
            "Score the semantic analyzer must reach for a finding (0.0-1.0). "
            "This is the knob for semantic findings; detection_threat_score_threshold "
            "does not apply to them."
        ),
        ge=0.0,
        le=1.0,
    )

    detection_anomaly_threshold: float = Field(
        default=3.0,
        description="Standard deviations from mean to consider anomaly",
        ge=1.0,
        le=10.0,
    )

    detection_slow_pattern_threshold: float = Field(
        default=0.1,
        description="Execution time to consider pattern slow (seconds)",
        ge=0.01,
        le=1.0,
    )

    detection_monitor_history_size: int = Field(
        default=1000,
        description="Number of recent metrics to keep in history",
        ge=100,
        le=10000,
    )

    detection_max_tracked_patterns: int = Field(
        default=1000,
        description="Maximum number of patterns to track for performance",
        ge=100,
        le=5000,
    )

    detection_anomaly_emission_cooldown: float = Field(
        default=60.0,
        description=(
            "Min seconds between anomaly events for the same pattern. "
            "Raise to reduce noise on low-traffic apps."
        ),
        ge=1.0,
        le=3600.0,
    )

    detection_min_samples_for_anomaly: int = Field(
        default=30,
        description=(
            "Minimum samples recorded for a pattern before statistical-anomaly "
            "detection engages. Raise to reduce false fires on low-traffic apps."
        ),
        ge=10,
        le=1000,
    )

    detection_threat_score_threshold: float = Field(
        default=1.0,
        description=(
            "Regex anomaly score required to flag a request as a threat. A "
            "semantic finding flags a request regardless of this value; raising it "
            "does NOT silence semantic findings, tune detection_semantic_threshold "
            "for those."
        ),
        ge=0.0,
        le=10.0,
    )

    muted_event_types: frozenset[str] = Field(
        default=frozenset(),
        description="Event types to mute from telemetry dispatch",
    )

    muted_metric_types: frozenset[str] = Field(
        default=frozenset(),
        description="Metric types to mute from telemetry dispatch",
    )

    muted_check_logs: frozenset[str] = Field(
        default=frozenset(),
        description="Security check names to mute from pipeline logging",
    )

    log_sensitive_headers: frozenset[str] = Field(
        default=frozenset(),
        description=(
            "Header names redacted from guard log lines, matched case-insensitively. "
            "Merged with the hardcoded default set."
        ),
    )

    log_sensitive_params: frozenset[str] = Field(
        default=frozenset(),
        description=(
            "Query parameter names whose values are redacted from guard log lines "
            "(the URL segment and the detection engine's per-parameter line), "
            "matched case-insensitively. Merged with the hardcoded default set."
        ),
    )

    log_sensitive_body_fields: frozenset[str] = Field(
        default=frozenset(),
        description=(
            "Body field names whose values are redacted from the detection engine's "
            "per-field line: JSON keys at any depth, x-www-form-urlencoded and "
            "multipart text-part names, matched case-insensitively. Merged with the "
            "hardcoded default set."
        ),
    )

    enable_otel: bool = Field(
        default=False,
        description="Enable OpenTelemetry span/metric export (requires [otel] extra)",
    )

    otel_service_name: str = Field(
        default="guard-core",
        description="Service name for OpenTelemetry resource",
    )

    otel_exporter_endpoint: str | None = Field(
        default=None,
        description="OTLP HTTP endpoint for OpenTelemetry export",
    )

    otel_resource_attributes: dict[str, str] = Field(
        default_factory=dict,
        description=(
            "Additional OpenTelemetry resource attributes "
            "(e.g. deployment.environment, service.version)."
        ),
    )

    enable_logfire: bool = Field(
        default=False,
        description="Enable Logfire span/metric export (requires [logfire] extra)",
    )

    logfire_service_name: str = Field(
        default="guard-core",
        description="Service name for Logfire integration",
    )

    enable_enrichment: bool = Field(
        default=False,
        description=(
            "Populate guard.* metadata on every event and every metric with "
            "project identity, deterministic threat score, matched dynamic "
            "rule, and per-IP behavioral correlation keys. Requires "
            "enable_agent=True, enrichment is the guard-agent-gated tier "
            "of the telemetry pipeline."
        ),
    )

    excluded_detection_headers: set[str] = Field(
        default_factory=set,
        description=(
            "Headers the operator lists are not scanned in any category, name "
            "or value, like excluded_detection_params and "
            "excluded_detection_body_fields. The hardcoded default set "
            "(identity and proxy headers) stays scanned for every category "
            "except ssrf unless the operator lists the name too."
        ),
    )
    excluded_semantic_detection_headers: set[str] = Field(
        default_factory=set,
        description=(
            "Opt-in: header names whose values skip the semantic analyzer "
            "only, matched case-insensitively. Regex category scanning of "
            "these headers is unchanged. Useful for apps whose JWT session "
            "cookies score near detection_semantic_threshold (for example "
            "cookie, authorization). Default empty."
        ),
    )
    excluded_detection_params: Annotated[
        set[str] | dict[str, set[str]],
        BeforeValidator(_validate_excluded_detection_params_value),
    ] = Field(
        default_factory=set,
        description=(
            "Query parameters to exclude from penetration detection scanning. "
            "A set of names excludes every category; a mapping of name to a "
            "set of detection categories excludes only those categories for "
            "that parameter, for example {'q': {'sqli'}}."
        ),
    )
    excluded_detection_body_fields: Annotated[
        set[str] | dict[str, set[str]],
        BeforeValidator(
            partial(
                _validate_excluded_detection_params_value,
                field_name="excluded_detection_body_fields",
            )
        ),
    ] = Field(
        default_factory=set,
        description=(
            "JSON body keys to exclude from penetration detection scanning. "
            "Matched at any nesting depth, and applied to x-www-form-urlencoded "
            "and multipart text-part field names as well. A set of names "
            "excludes every category; a mapping of name to a set of detection "
            "categories excludes only those categories for that field, for "
            "example {'note': {'sensitive_file'}}."
        ),
    )
    detection_scan_body: bool = Field(
        default=True,
        description=(
            "Scan the request body during penetration detection. Set False to "
            "restrict detection to the URL path, query params, and headers; the "
            "body is then never read or matched, regardless of its shape."
        ),
    )
    enabled_detection_categories: frozenset[str] = Field(
        default_factory=partial(frozenset, ALL_DETECTION_CATEGORIES),
        description=(
            "Detection categories to scan for. Defaults to all. "
            f"Valid values: {sorted(ALL_DETECTION_CATEGORIES)}"
        ),
    )

    @model_validator(mode="after")
    def resolve_enable_redis_default(self) -> Self:
        if "enable_redis" not in self.__pydantic_fields_set__:
            resolve_enable_redis(self)
        return self

    def __setattr__(self, name: str, value: object) -> None:
        super().__setattr__(name, value)
        if name in REDIS_CONNECTION_FIELDS:
            resolve_enable_redis(self)
        if name in SIGNAL_TRIGGER_FIELDS or name in REDIS_CONNECTION_FIELDS:
            signal_changed_defaults(self)
