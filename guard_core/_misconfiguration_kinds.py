import logging
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Literal

Severity = Literal["error", "warn"]
Scope = Literal["config", "dynamic_rules", "decorators", "runtime"]


@dataclass(frozen=True)
class KindInfo:
    severity: Severity
    scope: Scope
    subject: str
    description: str
    fatal_only: bool = False


KINDS: dict[str, KindInfo] = {}


def _kind(
    kind: str,
    severity: Severity,
    scope: Scope,
    subject: str,
    description: str,
    *,
    fatal_only: bool = False,
) -> str:
    KINDS[kind] = KindInfo(severity, scope, subject, description, fatal_only)
    return kind


NO_SUBJECT = "null"

K_RATE_LIMIT_BELOW_ONE = _kind(
    "rate_limit.below_one",
    "error",
    "config",
    NO_SUBJECT,
    "enable_rate_limiting is on and rate_limit is below 1",
)
K_RATE_LIMIT_WINDOW_BELOW_ONE = _kind(
    "rate_limit_window.below_one",
    "error",
    "config",
    NO_SUBJECT,
    "enable_rate_limiting is on and rate_limit_window is below 1",
)
K_ENDPOINT_LIMIT_BELOW_ONE = _kind(
    "endpoint_rate_limits.below_one",
    "error",
    "config",
    "the endpoint_rate_limits key",
    "enable_rate_limiting is on and an entry has a limit or a window below 1",
)
K_THREAT_SCORE_THRESHOLD_NON_POSITIVE = _kind(
    "detection_threat_score_threshold.non_positive",
    "error",
    "config",
    NO_SUBJECT,
    "detection_threat_score_threshold is 0 or below",
)
K_SEMANTIC_THRESHOLD_NON_POSITIVE = _kind(
    "detection_semantic_threshold.non_positive",
    "error",
    "config",
    NO_SUBJECT,
    "detection_semantic_threshold is 0 or below",
)
K_EXCLUDE_PATHS_GLOB = _kind(
    "exclude_paths.glob_wildcard",
    "error",
    "config",
    "the exclude_paths entry",
    "an entry holds *, ? or #, which are literal characters, not a glob",
)
K_EXCLUDE_PATHS_ROUTING_ANOMALY = _kind(
    "exclude_paths.routing_anomaly",
    "error",
    "config",
    "the exclude_paths entry",
    "an entry has a dot segment, an empty segment, a backslash or an encoded dot "
    "or separator in any decoding round",
)
K_ENDPOINT_KEY_ROUTING_ANOMALY = _kind(
    "endpoint_rate_limits.routing_anomaly",
    "error",
    "config",
    "the endpoint_rate_limits key",
    "a key has a dot segment, an empty segment, a backslash or an encoded dot or "
    "separator in any decoding round",
)
K_ENDPOINT_KEY_ROUTER_TEMPLATE = _kind(
    "endpoint_rate_limits.router_template",
    "error",
    "config",
    "the endpoint_rate_limits key",
    "a key is a router template, a regex route or a glob, which matches only that "
    "literal text",
)
K_CORS_WILDCARD_WITH_CREDENTIALS = _kind(
    "cors.wildcard_origin_with_credentials",
    "error",
    "config",
    NO_SUBJECT,
    "enable_cors with cors_allow_credentials and a wildcard origin",
)
K_SECURITY_HEADERS_UNKNOWN_KEY = _kind(
    "security_headers.unknown_key",
    "error",
    "config",
    "the security_headers key",
    "a key (or hsts key) is not a known key, so it has no effect",
)
K_EXCLUDE_PATHS_UNEXEMPTED_PROBE = _kind(
    "exclude_paths.unexempted_probe",
    "warn",
    "config",
    NO_SUBJECT,
    "emergency_mode blocks a health probe path held in exclude_paths and not "
    "listed in emergency_exempt_paths",
)
K_EXCLUDE_ALL_PATHS_ENABLED = _kind(
    "exclude_all_paths.enabled",
    "warn",
    "config",
    NO_SUBJECT,
    "exclude_all_paths is True, which excludes the whole application",
)
K_TRUSTED_PROXIES_PREFIX_ZERO = _kind(
    "trusted_proxies.prefix_zero",
    "warn",
    "config",
    NO_SUBJECT,
    "trusted_proxies holds a /0 network",
)
K_WHITELIST_PREFIX_ZERO = _kind(
    "whitelist.prefix_zero",
    "warn",
    "config",
    NO_SUBJECT,
    "whitelist holds a /0 network",
)
K_EXEMPT_IPS_PREFIX_ZERO = _kind(
    "exempt_ips.prefix_zero",
    "warn",
    "config",
    NO_SUBJECT,
    "exempt_ips holds a /0 network",
)
K_CHANGED_DEFAULT_BAN_ON_HOSTILE_SIGNALS = _kind(
    "changed_default.ban_on_hostile_signals",
    "warn",
    "config",
    NO_SUBJECT,
    "ban_on_hostile_signals is left unset and its default changed in 5.0.0",
)
K_CHANGED_DEFAULT_FAIL_ON_MISCONFIGURATION = _kind(
    "changed_default.fail_on_misconfiguration",
    "warn",
    "config",
    NO_SUBJECT,
    "fail_on_misconfiguration is left unset and its default changed in 5.0.0",
)
K_CHANGED_DEFAULT_RATE_LIMIT = _kind(
    "changed_default.rate_limit",
    "warn",
    "config",
    NO_SUBJECT,
    "rate_limit is left unset and its default changed in 5.0.0",
)
K_CHANGED_DEFAULT_WHITELIST_ACCESS_ONLY = _kind(
    "changed_default.whitelist_access_only",
    "warn",
    "config",
    NO_SUBJECT,
    "whitelist_access_only is left unset beside a whitelist and its default "
    "changed in 5.0.0",
)
K_CHANGED_DEFAULT_SLASH_EXCLUSION = _kind(
    "changed_default.slash_exclusion",
    "warn",
    "config",
    NO_SUBJECT,
    "exclude_paths holds / and exclude_all_paths is left unset",
)
K_CHANGED_DEFAULT_ENABLE_REDIS = _kind(
    "changed_default.enable_redis",
    "warn",
    "config",
    NO_SUBJECT,
    "enable_redis is left unset and its default changed in 5.0.0",
)
K_REDIS_PREFIX_LEFT_DEFAULT = _kind(
    "redis_prefix.left_default",
    "warn",
    "config",
    NO_SUBJECT,
    "Redis is enabled with the default redis_prefix",
)
K_ENABLED_DETECTION_CATEGORIES_EMPTY = _kind(
    "enabled_detection_categories.empty",
    "warn",
    "config",
    NO_SUBJECT,
    "enable_penetration_detection is on and enabled_detection_categories is empty",
)
K_AUTO_BAN_THRESHOLD_UNREACHABLE = _kind(
    "auto_ban_threshold.unreachable",
    "error",
    "runtime",
    NO_SUBJECT,
    "auto_ban_threshold is above the strikes one client can produce in the window",
)
K_THREAT_BAN_THRESHOLD_UNREACHABLE = _kind(
    "threat_ban_config.unreachable",
    "error",
    "runtime",
    "the threat_ban_config category",
    "a category threshold is above the strikes one client can produce in the window",
)
K_NAT64_INVALID_ENTRY = _kind(
    "nat64_prefixes.invalid_entry",
    "error",
    "runtime",
    "the nat64_prefixes entry",
    "an entry is not an IPv6 prefix of an RFC 6052 length",
)
K_REDIS_HANDLER_IS_CONNECTED_ASYNC = _kind(
    "redis_handler.is_connected_async",
    "error",
    "runtime",
    NO_SUBJECT,
    "redis_fail_open is on and the handler defines is_connected as async",
)
K_REDIS_HANDLER_MISSING_MEMBERS = _kind(
    "redis_handler.missing_members",
    "error",
    "runtime",
    NO_SUBJECT,
    "the Redis handler lacks members of the handler protocol",
)
K_ROUTE_COUNTRY_RULE_WITHOUT_GEOIP = _kind(
    "route.country_rule_without_geoip",
    "error",
    "runtime",
    "the route id",
    "a route uses a country rule and no GeoIP source is configured",
)
K_IPV6_PREFIX_LENGTH_REDIS_MISMATCH = _kind(
    "ipv6_prefix_length.redis_mismatch",
    "error",
    "runtime",
    NO_SUBJECT,
    "ipv6_prefix_length differs from the value recorded in Redis",
)
K_ENDPOINT_KEY_MATCHES_NO_ROUTE = _kind(
    "endpoint_rate_limits.matches_no_route",
    "warn",
    "runtime",
    "the endpoint_rate_limits key",
    "a key matches no registered route",
)
K_EXCLUDE_PATHS_MATCHES_NO_ROUTE = _kind(
    "exclude_paths.matches_no_route",
    "warn",
    "runtime",
    "the exclude_paths entry",
    "an entry matches no registered route",
)
K_RESOLVE_ROUTE_RAISED = _kind(
    "endpoint_rate_limits.resolve_route_raised",
    "warn",
    "runtime",
    "the endpoint_rate_limits key",
    "resolve_route raised for a key",
)
K_STATIC_ROUTE_PREFIXES_RAISED = _kind(
    "exclude_paths.static_route_prefixes_raised",
    "warn",
    "runtime",
    NO_SUBJECT,
    "static_route_prefixes raised during the exclude_paths route check",
)
K_TIME_WINDOW_INVALID_TIME = _kind(
    "decorator.time_window.invalid_time",
    "error",
    "decorators",
    "the argument name (start_time or end_time)",
    "start_time or end_time is not HH:MM",
)
K_TIME_WINDOW_UNKNOWN_TIMEZONE = _kind(
    "decorator.time_window.unknown_timezone",
    "error",
    "decorators",
    "the timezone as given",
    "the timezone is not an IANA zone",
)
K_BEHAVIOR_RULE_NON_POSITIVE = _kind(
    "decorator.behavior_rule.non_positive",
    "error",
    "decorators",
    "the decorator name",
    "a behavior decorator has a threshold or a window below 1",
)
K_SUSPICIOUS_FREQUENCY_PRODUCT_BELOW_ONE = _kind(
    "decorator.suspicious_frequency.product_below_one",
    "error",
    "decorators",
    NO_SUBJECT,
    "max_frequency times window is below 1",
)
K_DECORATOR_RATE_LIMIT_BELOW_ONE = _kind(
    "decorator.rate_limit.below_one",
    "error",
    "decorators",
    NO_SUBJECT,
    "requests or window is below 1",
)
K_GEO_RATE_LIMIT_BELOW_ONE = _kind(
    "decorator.geo_rate_limit.below_one",
    "error",
    "decorators",
    "the country key as given",
    "an entry has a limit or a window below 1",
)
K_REQUIRE_IP_EMPTY_WHITELIST = _kind(
    "decorator.require_ip.empty_whitelist",
    "error",
    "decorators",
    NO_SUBJECT,
    "a whitelist is given and empty",
)
K_REQUIRE_IP_INVALID_ENTRY = _kind(
    "decorator.require_ip.invalid_entry",
    "error",
    "decorators",
    "the entry as given",
    "a whitelist or blacklist entry is not an IP address or CIDR network",
)
K_BLOCK_COUNTRIES_EMPTY_LIST = _kind(
    "decorator.block_countries.empty_list",
    "error",
    "decorators",
    NO_SUBJECT,
    "the country list is empty",
)
K_ALLOW_COUNTRIES_EMPTY_LIST = _kind(
    "decorator.allow_countries.empty_list",
    "error",
    "decorators",
    NO_SUBJECT,
    "the country list is empty",
)
K_BLOCK_CLOUDS_EMPTY_LIST = _kind(
    "decorator.block_clouds.empty_list",
    "error",
    "decorators",
    NO_SUBJECT,
    "a provider list is given and empty",
)
K_BLOCK_CLOUDS_UNKNOWN_PROVIDER = _kind(
    "decorator.block_clouds.unknown_provider",
    "error",
    "decorators",
    "the unknown selectors as given, sorted and joined by a comma and a space",
    "a provider selector is unknown",
)
K_COUNTRY_RULE_NO_GEOIP_SOURCE = _kind(
    "decorator.country_rule.no_geoip_source",
    "error",
    "decorators",
    "the decorator, for example @block_countries",
    "a country rule is declared and no GeoIP source is configured; checked only "
    "while fail_on_misconfiguration is True, so it is fatal and never merely "
    "reported",
    fatal_only=True,
)
K_COUNTRY_RULE_GEOIP_DOWNLOAD_EXTRAS_MISSING = _kind(
    "decorator.country_rule.geoip_download_extras_missing",
    "error",
    "decorators",
    "the decorator, for example @block_countries",
    "ipinfo_token is set and the GeoIP download extras are not installed; host "
    "dependent, never pinned in the corpus",
    fatal_only=True,
)
K_DETECTION_EXCLUSION_PARAM_NOT_IN_TEMPLATE = _kind(
    "decorator.detection_exclusion.param_not_in_template",
    "error",
    "decorators",
    "the declared parameter name",
    "a path_params name of @detection_exclusion is not a parameter of the route "
    "template, so it exempts nothing",
)
K_DETECTION_EXCLUSION_PARAM_WITHOUT_LITERAL_SEGMENT = _kind(
    "decorator.detection_exclusion.param_without_literal_segment",
    "error",
    "decorators",
    "the declared parameter name",
    "a path_params name of @detection_exclusion has no literal segment before it "
    "in the route template, so it would exempt the whole path from the probe rows",
)
K_DYNAMIC_IP_BLACKLIST_INVALID_ENTRY = _kind(
    "dynamic_rules.ip_blacklist.invalid_entry",
    "error",
    "dynamic_rules",
    "the entry as given",
    "an entry is not an IP address or CIDR range",
)
K_DYNAMIC_IP_WHITELIST_INVALID_ENTRY = _kind(
    "dynamic_rules.ip_whitelist.invalid_entry",
    "error",
    "dynamic_rules",
    "the entry as given",
    "an entry is not an IP address or CIDR range",
)
K_DYNAMIC_EMERGENCY_WHITELIST_INVALID_ENTRY = _kind(
    "dynamic_rules.emergency_whitelist.invalid_entry",
    "error",
    "dynamic_rules",
    "the entry as given",
    "an entry is not an IP address or CIDR range",
)
K_DYNAMIC_GLOBAL_RATE_LIMIT_BELOW_ONE = _kind(
    "dynamic_rules.global_rate_limit.below_one",
    "error",
    "dynamic_rules",
    NO_SUBJECT,
    "global_rate_limit is below 1",
)
K_DYNAMIC_GLOBAL_RATE_WINDOW_BELOW_ONE = _kind(
    "dynamic_rules.global_rate_window.below_one",
    "error",
    "dynamic_rules",
    NO_SUBJECT,
    "global_rate_window is below 1",
)
K_DYNAMIC_IP_BAN_DURATION_BELOW_ONE = _kind(
    "dynamic_rules.ip_ban_duration.below_one",
    "error",
    "dynamic_rules",
    NO_SUBJECT,
    "ip_ban_duration is below 1",
)
K_DYNAMIC_AUTO_BAN_DURATION_BELOW_ONE = _kind(
    "dynamic_rules.auto_ban_duration.below_one",
    "error",
    "dynamic_rules",
    NO_SUBJECT,
    "auto_ban_duration is below 1",
)
K_DYNAMIC_BLOCKED_COUNTRIES_INVALID_CODE = _kind(
    "dynamic_rules.blocked_countries.invalid_code",
    "error",
    "dynamic_rules",
    "the code as given",
    "an entry is not a two-letter country code",
)
K_DYNAMIC_WHITELIST_COUNTRIES_INVALID_CODE = _kind(
    "dynamic_rules.whitelist_countries.invalid_code",
    "error",
    "dynamic_rules",
    "the code as given",
    "an entry is not a two-letter country code",
)
K_DYNAMIC_BLOCKED_CLOUD_PROVIDERS_UNKNOWN = _kind(
    "dynamic_rules.blocked_cloud_providers.unknown_provider",
    "error",
    "dynamic_rules",
    "the provider as given",
    "a provider selector is unknown",
)

ALL_KINDS = frozenset(KINDS)
HOST_DEPENDENT_KINDS = frozenset({K_COUNTRY_RULE_GEOIP_DOWNLOAD_EXTRAS_MISSING})


class Problem(str):
    """A misconfiguration message that carries a stable kind.

    The text stays the plain English line every caller already compares and joins.
    A str method returns a plain str, so the kind is read where the Problem is
    built, never after the text went through formatting.
    """

    kind: str
    subject: str | None
    severity: Severity

    def __new__(
        cls, message: str, *, kind: str, subject: str | None = None
    ) -> "Problem":
        info = KINDS.get(kind)
        if info is None:
            raise ValueError(f"unregistered misconfiguration kind {kind!r}")
        problem = super().__new__(cls, message)
        problem.kind = kind
        problem.subject = subject
        problem.severity = info.severity
        return problem

    def __reduce__(self) -> tuple[object, ...]:
        return (_rebuild_problem, (str(self), self.kind, self.subject))


def _rebuild_problem(message: str, kind: str, subject: str | None) -> Problem:
    return Problem(message, kind=kind, subject=subject)


class MisconfigurationError(ValueError):
    """Raised once with every error-severity problem found."""

    def __init__(self, message: str, problems: list[Problem]) -> None:
        super().__init__(message)
        self.problems = problems

    def __reduce__(self) -> tuple[object, ...]:
        return (type(self), (str(self), self.problems))

    @property
    def kinds(self) -> list[str]:
        return [problem.kind for problem in self.problems]


def kinds_log_extra(kind: str, *subjects: str | None) -> dict[str, object]:
    return {"problems": tuple((kind, subject) for subject in subjects)}


def problem_log_extra(*problems: Problem) -> dict[str, object]:
    return {"problems": tuple((p.kind, p.subject) for p in problems)}


def listed_problems_log_extra(problems: Sequence[str]) -> dict[str, object]:
    """The log extra of a public ``list[str]`` whose items are Problems."""
    return problem_log_extra(*[p for p in problems if isinstance(p, Problem)])


def log_problem(
    logger: logging.Logger, problem: Problem, *, stacklevel: int = 1
) -> None:
    logger.warning(problem, extra=problem_log_extra(problem), stacklevel=stacklevel + 1)
