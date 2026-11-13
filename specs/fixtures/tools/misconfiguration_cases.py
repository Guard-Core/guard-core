"""Curated inputs of the misconfiguration suites (inputs only, never expectations).

Every case declares ``intends``: the multiset of kinds the engine must report for
it (and, for a kind that is only fatal, raise). The generator drives the real
engine and FAILS when it observes anything else, so a regeneration can never
freeze a bug as ``[]``. The ``expected`` block of the corpus is what the engine
then observes: the kind and subject pairs, never a message.
"""

from __future__ import annotations

from typing import TypedDict

from fixture_types import JsonObject, JsonValue
from typing_extensions import NotRequired


class MisconfigurationCaseInput(TypedDict):
    id: str
    input: JsonObject
    intends: list[str]
    note: NotRequired[str]


# Stated by every config case, so the 5.0.0 changed-default notices stay out of the
# cases that are about something else.
QUIET: JsonObject = {
    "enable_redis": False,
    "rate_limit": 10,
    "ban_on_hostile_signals": False,
}


def _config_case(
    case_id: str, intends: list[str], **fields: JsonValue
) -> MisconfigurationCaseInput:
    return {"id": case_id, "input": {"config": {**QUIET, **fields}}, "intends": intends}


def _bare_config_case(
    case_id: str, intends: list[str], config: JsonObject, **extra: JsonValue
) -> MisconfigurationCaseInput:
    return {"id": case_id, "input": {"config": config, **extra}, "intends": intends}


# Every spelling of a key that the router would serve as a different path.
ANOMALY_KEYS = [
    ("dot_segment", "/a/../b"),
    ("single_dot_segment", "/a/./b"),
    ("empty_segment", "/a//b"),
    ("backslash", "/a\\b"),
    ("encoded_dot_segment", "/a/%2e%2e/b"),
    ("double_encoded_dot", "/a/%252e%252e/b"),
    ("encoded_slash", "/a/%2F/b"),
]
# Route syntax of every framework family; each is a key that matches only its own
# literal text, so it limits nothing.
TEMPLATE_KEYS = [
    ("brace_name", "/users/{id}"),
    ("angle_name", "/users/<id>"),
    ("colon_name", "/users/:id"),
    ("named_group", "/users/(?P<id>[0-9]+)"),
    ("regex_group_class", "/users/([0-9]+)"),
    ("regex_group_star", "/users/(.*)"),
    ("regex_group_plus", "/users/(.+)"),
    ("regex_anchored", "^/users/([0-9]+)$"),
    ("regex_bare_class", "/files/[0-9]+"),
    ("regex_dot_star", "/users/.*"),
    ("regex_dot_plus", "/users/.+"),
    ("glob_star", "/api/*"),
    ("glob_star_root", "/static/*"),
    ("glob_double_star", "/api/**"),
]
# A key that holds a character a regex route would, and is a plain path.
PLAIN_KEYS = [
    ("plain_path", "/users/1"),
    ("plain_dash_dot", "/a-b_c.d"),
    ("plain_open_brace", "/a{b"),
    ("plain_close_open_brace", "/a}b{"),
    ("plain_open_angle", "/a<b"),
    ("plain_parenthesis_word", "/wiki/Foo_(bar)"),
    ("plain_plus_plus", "/c++"),
    ("plain_trailing_dollar", "/a$"),
    ("plain_price_dollar", "/price$"),
    ("plain_inner_parenthesis", "/x(y)z"),
    ("plain_colon_in_segment", "/v1/models/gpt:generate"),
    ("plain_dotted_file", "/files/a.b"),
    ("plain_numeric_group", "/files/(1)"),
    ("plain_query_mark", "/search?q=1"),
]
# The one key that is both a backslash spelling and a regex route.
BOTH_KEY = ("regex_backslash_group", "/users/(\\d+)")


def _anomaly_kind(scope: str) -> str:
    return f"{scope}.routing_anomaly"


def config_cases() -> list[MisconfigurationCaseInput]:
    cases: list[MisconfigurationCaseInput] = [
        _config_case("defaults_quiet", []),
        _config_case("rate_limit_boundary_one", [], rate_limit=1),
        _config_case(
            "rate_limiting_off_ignores_zero_limits",
            [],
            enable_rate_limiting=False,
            rate_limit=1,
            rate_limit_window=0,
        ),
        _config_case(
            "rate_limit_below_one",
            ["rate_limit.below_one"],
            enable_rate_limiting=True,
            rate_limit=0,
        ),
        _config_case(
            "rate_limit_window_below_one",
            ["rate_limit_window.below_one"],
            rate_limit_window=0,
        ),
        _config_case(
            "endpoint_limit_below_one",
            ["endpoint_rate_limits.below_one"],
            endpoint_rate_limits={"/login": [0, 60]},
        ),
        _config_case(
            "endpoint_window_below_one",
            ["endpoint_rate_limits.below_one"],
            endpoint_rate_limits={"/login": [5, 0]},
        ),
        _config_case(
            "endpoint_limit_boundary_one",
            [],
            endpoint_rate_limits={"/login": [1, 1]},
        ),
        _config_case(
            "threat_score_threshold_zero",
            ["detection_threat_score_threshold.non_positive"],
            detection_threat_score_threshold=0.0,
        ),
        _config_case(
            "semantic_threshold_zero",
            ["detection_semantic_threshold.non_positive"],
            detection_semantic_threshold=0.0,
        ),
        _config_case("thresholds_positive", [], detection_threat_score_threshold=0.5),
        _config_case(
            "exclude_path_glob_star",
            ["exclude_paths.glob_wildcard"],
            exclude_paths=["/static/*"],
        ),
        _config_case(
            "exclude_path_glob_question",
            ["exclude_paths.glob_wildcard"],
            exclude_paths=["/a?b"],
        ),
        _config_case(
            "exclude_path_glob_hash",
            ["exclude_paths.glob_wildcard"],
            exclude_paths=["/a#b"],
        ),
        _config_case(
            "exclude_path_plain", [], exclude_paths=["/health", "/static/app.js"]
        ),
        _config_case(
            "exclude_path_default_entries_skip_the_anomaly_check",
            [],
            exclude_paths=["/favicon.ico", "/robots.txt"],
        ),
        _config_case(
            "cors_wildcard_origin_with_credentials",
            ["cors.wildcard_origin_with_credentials"],
            enable_cors=True,
            cors_allow_credentials=True,
            cors_allow_origins=["*"],
        ),
        _config_case(
            "cors_wildcard_origin_without_credentials",
            [],
            enable_cors=True,
            cors_allow_credentials=False,
            cors_allow_origins=["*"],
        ),
        _config_case(
            "cors_wildcard_credentials_with_cors_off",
            [],
            enable_cors=False,
            cors_allow_credentials=True,
            cors_allow_origins=["*"],
        ),
        _config_case(
            "security_headers_unknown_key",
            ["security_headers.unknown_key"],
            security_headers={"x_made_up": "1"},
        ),
        _config_case(
            "security_headers_unknown_hsts_key",
            ["security_headers.unknown_key"],
            security_headers={"hsts": {"max_age": 3600, "bogus": True}},
        ),
        _config_case(
            "security_headers_known_keys",
            [],
            security_headers={"hsts": {"max_age": 3600}},
        ),
        _config_case(
            "security_headers_off_skips_the_key_check",
            [],
            security_headers={"enabled": False, "x_made_up": "1"},
        ),
        _config_case(
            "emergency_mode_unexempted_probe",
            ["exclude_paths.unexempted_probe"],
            emergency_mode=True,
            exclude_paths=["/health"],
        ),
        _config_case(
            "emergency_mode_exempted_probe",
            [],
            emergency_mode=True,
            exclude_paths=["/health"],
            emergency_exempt_paths=["/health"],
        ),
        _config_case(
            "exclude_all_paths_enabled",
            ["exclude_all_paths.enabled"],
            exclude_all_paths=True,
        ),
        _config_case(
            "trusted_proxies_prefix_zero",
            ["trusted_proxies.prefix_zero"],
            trusted_proxies=["0.0.0.0/0"],
        ),
        _config_case(
            "trusted_proxies_prefix_zero_v6",
            ["trusted_proxies.prefix_zero"],
            trusted_proxies=["::/0"],
        ),
        _config_case(
            "whitelist_prefix_zero",
            ["whitelist.prefix_zero"],
            whitelist=["0.0.0.0/0"],
            whitelist_access_only=False,
        ),
        _config_case(
            "exempt_ips_prefix_zero",
            ["exempt_ips.prefix_zero"],
            exempt_ips=["0.0.0.0/0"],
        ),
        _config_case(
            "narrow_networks_are_not_prefix_zero",
            [],
            trusted_proxies=["10.0.0.0/8"],
            whitelist=["10.1.0.0/16"],
            whitelist_access_only=False,
            exempt_ips=["192.168.0.0/16"],
        ),
        _bare_config_case(
            "changed_default_ban_on_hostile_signals",
            ["changed_default.ban_on_hostile_signals"],
            {"enable_redis": False, "rate_limit": 10},
        ),
        _bare_config_case(
            "changed_default_rate_limit",
            ["changed_default.rate_limit"],
            {"enable_redis": False, "ban_on_hostile_signals": False},
        ),
        _bare_config_case(
            "changed_default_enable_redis",
            ["changed_default.enable_redis"],
            {"rate_limit": 10, "ban_on_hostile_signals": False},
        ),
        _bare_config_case(
            "changed_default_whitelist_access_only",
            ["changed_default.whitelist_access_only"],
            {**QUIET, "whitelist": ["10.0.0.1"]},
        ),
        _bare_config_case(
            "changed_default_slash_exclusion",
            ["changed_default.slash_exclusion"],
            {**QUIET, "exclude_paths": ["/"]},
        ),
        _bare_config_case(
            "changed_default_fail_on_misconfiguration",
            ["changed_default.fail_on_misconfiguration"],
            dict(QUIET),
            flag_stated=False,
        ),
        _bare_config_case(
            "changed_defaults_every_flip_at_once",
            [
                "changed_default.ban_on_hostile_signals",
                "changed_default.enable_redis",
                "changed_default.fail_on_misconfiguration",
                "changed_default.rate_limit",
            ],
            {},
            flag_stated=False,
        ),
        _bare_config_case(
            "redis_prefix_left_default",
            ["redis_prefix.left_default"],
            {
                **QUIET,
                "enable_redis": True,
                "redis_url": "redis://localhost:6379",
            },
        ),
        _bare_config_case(
            "redis_prefix_set",
            [],
            {
                **QUIET,
                "enable_redis": True,
                "redis_url": "redis://localhost:6379",
                "redis_prefix": "myapp:",
            },
        ),
        _config_case(
            "combined_two_rate_limit_problems",
            ["rate_limit.below_one", "rate_limit_window.below_one"],
            rate_limit=0,
            rate_limit_window=0,
        ),
        _config_case(
            "combined_the_same_kind_twice",
            ["endpoint_rate_limits.below_one", "endpoint_rate_limits.below_one"],
            endpoint_rate_limits={"/a": [0, 60], "/b": [5, 0]},
        ),
        _config_case(
            "combined_across_every_error_family",
            [
                "cors.wildcard_origin_with_credentials",
                "detection_semantic_threshold.non_positive",
                "endpoint_rate_limits.router_template",
                "exclude_paths.glob_wildcard",
                "rate_limit.below_one",
                "security_headers.unknown_key",
            ],
            rate_limit=0,
            detection_semantic_threshold=0.0,
            exclude_paths=["/x/*"],
            endpoint_rate_limits={"/users/{id}": [5, 60]},
            enable_cors=True,
            cors_allow_credentials=True,
            cors_allow_origins=["*"],
            security_headers={"x_made_up": "1"},
        ),
        _config_case(
            "combined_errors_with_a_warning",
            ["exclude_all_paths.enabled", "rate_limit.below_one"],
            rate_limit=0,
            exclude_all_paths=True,
        ),
        _config_case(
            "combined_two_warnings_only",
            ["exempt_ips.prefix_zero", "trusted_proxies.prefix_zero"],
            trusted_proxies=["0.0.0.0/0"],
            exempt_ips=["0.0.0.0/0"],
        ),
    ]
    for name, key in ANOMALY_KEYS:
        cases.append(
            _config_case(
                f"exclude_path_anomaly_{name}",
                ["exclude_paths.routing_anomaly"],
                exclude_paths=[key],
            )
        )
        cases.append(
            _config_case(
                f"endpoint_key_anomaly_{name}",
                [_anomaly_kind("endpoint_rate_limits")],
                endpoint_rate_limits={key: [5, 60]},
            )
        )
    for name, key in TEMPLATE_KEYS:
        cases.append(
            _config_case(
                f"endpoint_key_template_{name}",
                ["endpoint_rate_limits.router_template"],
                endpoint_rate_limits={key: [5, 60]},
            )
        )
    for name, key in PLAIN_KEYS:
        cases.append(
            _config_case(
                f"endpoint_key_{name}", [], endpoint_rate_limits={key: [5, 60]}
            )
        )
    name, key = BOTH_KEY
    cases.append(
        _config_case(
            f"endpoint_key_{name}",
            [
                "endpoint_rate_limits.router_template",
                "endpoint_rate_limits.routing_anomaly",
            ],
            endpoint_rate_limits={key: [5, 60]},
        )
    )
    return cases


def _dynamic_case(
    case_id: str, intends: list[str], **rules: JsonValue
) -> MisconfigurationCaseInput:
    return {"id": case_id, "input": {"dynamic_rules": rules}, "intends": intends}


def dynamic_rules_cases() -> list[MisconfigurationCaseInput]:
    cases: list[MisconfigurationCaseInput] = [
        _dynamic_case("empty_rules", []),
        _dynamic_case(
            "valid_rules",
            [],
            ip_blacklist=["203.0.113.0/24", "2001:db8::1"],
            ip_whitelist=["198.51.100.7"],
            emergency_whitelist=["192.0.2.1"],
            global_rate_limit=1,
            global_rate_window=1,
            ip_ban_duration=1,
            auto_ban_duration=1,
            blocked_countries=["US", "de"],
            whitelist_countries=["FR"],
            blocked_cloud_providers=["AWS", "gcp"],
            endpoint_rate_limits={"/login": [5, 60]},
        ),
        _dynamic_case(
            "ip_blacklist_invalid",
            ["dynamic_rules.ip_blacklist.invalid_entry"],
            ip_blacklist=["not-an-ip", "10.0.0.1"],
        ),
        _dynamic_case(
            "ip_whitelist_invalid",
            ["dynamic_rules.ip_whitelist.invalid_entry"],
            ip_whitelist=["10.0.0.256"],
        ),
        _dynamic_case(
            "emergency_whitelist_invalid",
            ["dynamic_rules.emergency_whitelist.invalid_entry"],
            emergency_whitelist=["10.0.0.0/33"],
        ),
        _dynamic_case(
            "global_rate_limit_below_one",
            ["dynamic_rules.global_rate_limit.below_one"],
            global_rate_limit=0,
        ),
        _dynamic_case(
            "global_rate_window_below_one",
            ["dynamic_rules.global_rate_window.below_one"],
            global_rate_window=0,
        ),
        _dynamic_case(
            "ip_ban_duration_below_one",
            ["dynamic_rules.ip_ban_duration.below_one"],
            ip_ban_duration=0,
        ),
        _dynamic_case(
            "auto_ban_duration_below_one",
            ["dynamic_rules.auto_ban_duration.below_one"],
            auto_ban_duration=-5,
        ),
        _dynamic_case(
            "blocked_countries_invalid_code",
            ["dynamic_rules.blocked_countries.invalid_code"],
            blocked_countries=["USA", "US"],
        ),
        _dynamic_case(
            "whitelist_countries_invalid_code",
            ["dynamic_rules.whitelist_countries.invalid_code"],
            whitelist_countries=["1X"],
        ),
        _dynamic_case(
            "blocked_cloud_providers_unknown",
            ["dynamic_rules.blocked_cloud_providers.unknown_provider"],
            blocked_cloud_providers=["notacloud", "aws"],
        ),
        _dynamic_case(
            "endpoint_limit_below_one",
            ["endpoint_rate_limits.below_one"],
            endpoint_rate_limits={"/login": [0, 60]},
        ),
        _dynamic_case(
            "endpoint_window_below_one",
            ["endpoint_rate_limits.below_one"],
            endpoint_rate_limits={"/login": [5, 0]},
        ),
        _dynamic_case(
            "combined_every_dynamic_kind",
            [
                "dynamic_rules.auto_ban_duration.below_one",
                "dynamic_rules.blocked_cloud_providers.unknown_provider",
                "dynamic_rules.blocked_countries.invalid_code",
                "dynamic_rules.emergency_whitelist.invalid_entry",
                "dynamic_rules.global_rate_limit.below_one",
                "dynamic_rules.global_rate_window.below_one",
                "dynamic_rules.ip_ban_duration.below_one",
                "dynamic_rules.ip_blacklist.invalid_entry",
                "dynamic_rules.ip_whitelist.invalid_entry",
                "dynamic_rules.whitelist_countries.invalid_code",
                "endpoint_rate_limits.below_one",
            ],
            ip_blacklist=["x"],
            ip_whitelist=["y"],
            emergency_whitelist=["z"],
            global_rate_limit=0,
            global_rate_window=0,
            ip_ban_duration=0,
            auto_ban_duration=0,
            blocked_countries=["USA"],
            whitelist_countries=["FRA"],
            blocked_cloud_providers=["nope"],
            endpoint_rate_limits={"/a": [0, 0]},
        ),
        _dynamic_case(
            "combined_the_same_kind_twice",
            [
                "dynamic_rules.ip_blacklist.invalid_entry",
                "dynamic_rules.ip_blacklist.invalid_entry",
            ],
            ip_blacklist=["a", "b"],
        ),
    ]
    for name, key in ANOMALY_KEYS:
        cases.append(
            _dynamic_case(
                f"endpoint_key_anomaly_{name}",
                [_anomaly_kind("endpoint_rate_limits")],
                endpoint_rate_limits={key: [5, 60]},
            )
        )
    for name, key in TEMPLATE_KEYS:
        cases.append(
            _dynamic_case(
                f"endpoint_key_template_{name}",
                ["endpoint_rate_limits.router_template"],
                endpoint_rate_limits={key: [5, 60]},
            )
        )
    for name, key in PLAIN_KEYS:
        cases.append(
            _dynamic_case(
                f"endpoint_key_{name}", [], endpoint_rate_limits={key: [5, 60]}
            )
        )
    name, key = BOTH_KEY
    cases.append(
        _dynamic_case(
            f"endpoint_key_{name}",
            [
                "endpoint_rate_limits.router_template",
                "endpoint_rate_limits.routing_anomaly",
            ],
            endpoint_rate_limits={key: [5, 60]},
        )
    )
    return cases


def _decorator_case(
    case_id: str,
    intends: list[str],
    *steps: tuple[str, JsonObject],
    geo: str | None = None,
    **config: JsonValue,
) -> MisconfigurationCaseInput:
    decorators: list[JsonValue] = [{"name": name, "args": args} for name, args in steps]
    return {
        "id": case_id,
        "input": {
            "config": {**QUIET, **config},
            "geo": geo,
            "decorators": decorators,
        },
        "intends": intends,
    }


def decorator_cases() -> list[MisconfigurationCaseInput]:
    return [
        _decorator_case(
            "time_window_invalid_start",
            ["decorator.time_window.invalid_time"],
            ("time_window", {"start_time": "25:00", "end_time": "17:00"}),
        ),
        _decorator_case(
            "time_window_invalid_both_times",
            [
                "decorator.time_window.invalid_time",
                "decorator.time_window.invalid_time",
            ],
            ("time_window", {"start_time": "9am", "end_time": "5pm"}),
        ),
        _decorator_case(
            "time_window_unknown_timezone",
            ["decorator.time_window.unknown_timezone"],
            (
                "time_window",
                {"start_time": "09:00", "end_time": "17:00", "timezone": "Mars/Base"},
            ),
        ),
        _decorator_case(
            "time_window_valid",
            [],
            (
                "time_window",
                {"start_time": "09:00", "end_time": "17:00", "timezone": "UTC"},
            ),
        ),
        _decorator_case(
            "time_window_invalid_time_and_timezone",
            [
                "decorator.time_window.invalid_time",
                "decorator.time_window.unknown_timezone",
            ],
            (
                "time_window",
                {"start_time": "99:99", "end_time": "17:00", "timezone": "Nope/Zone"},
            ),
        ),
        _decorator_case(
            "usage_monitor_threshold_below_one",
            ["decorator.behavior_rule.non_positive"],
            ("usage_monitor", {"max_calls": 0, "window": 60}),
        ),
        _decorator_case(
            "return_monitor_window_below_one",
            ["decorator.behavior_rule.non_positive"],
            (
                "return_monitor",
                {"pattern": "secret", "max_occurrences": 3, "window": 0},
            ),
            behavior_scan_response_body=True,
        ),
        _decorator_case(
            "usage_monitor_boundary_one",
            [],
            ("usage_monitor", {"max_calls": 1, "window": 1}),
        ),
        _decorator_case(
            "suspicious_frequency_product_below_one",
            ["decorator.suspicious_frequency.product_below_one"],
            ("suspicious_frequency", {"max_frequency": 0.001, "window": 10}),
        ),
        _decorator_case(
            "suspicious_frequency_boundary_one",
            [],
            ("suspicious_frequency", {"max_frequency": 0.1, "window": 10}),
        ),
        _decorator_case(
            "rate_limit_requests_below_one",
            ["decorator.rate_limit.below_one"],
            ("rate_limit", {"requests": 0, "window": 60}),
        ),
        _decorator_case(
            "rate_limit_window_below_one",
            ["decorator.rate_limit.below_one"],
            ("rate_limit", {"requests": 5, "window": 0}),
        ),
        _decorator_case(
            "rate_limit_boundary_one",
            [],
            ("rate_limit", {"requests": 1, "window": 1}),
        ),
        _decorator_case(
            "geo_rate_limit_entry_below_one",
            ["decorator.geo_rate_limit.below_one"],
            ("geo_rate_limit", {"limits": {"US": [0, 60], "DE": [5, 60]}}),
            geo="stub",
        ),
        _decorator_case(
            "geo_rate_limit_two_entries_below_one",
            [
                "decorator.geo_rate_limit.below_one",
                "decorator.geo_rate_limit.below_one",
            ],
            ("geo_rate_limit", {"limits": {"US": [0, 60], "DE": [5, 0]}}),
            geo="stub",
        ),
        _decorator_case(
            "geo_rate_limit_valid_with_a_geo_source",
            [],
            ("geo_rate_limit", {"limits": {"US": [5, 60]}}),
            geo="stub",
        ),
        _decorator_case(
            "require_ip_empty_whitelist",
            ["decorator.require_ip.empty_whitelist"],
            ("require_ip", {"whitelist": []}),
        ),
        _decorator_case(
            "require_ip_invalid_whitelist_entry",
            ["decorator.require_ip.invalid_entry"],
            ("require_ip", {"whitelist": ["10.0.0.1", "not-an-ip"]}),
        ),
        _decorator_case(
            "require_ip_invalid_blacklist_entry",
            ["decorator.require_ip.invalid_entry"],
            ("require_ip", {"blacklist": ["10.0.0.999"]}),
        ),
        _decorator_case(
            "require_ip_empty_whitelist_and_invalid_blacklist",
            [
                "decorator.require_ip.empty_whitelist",
                "decorator.require_ip.invalid_entry",
            ],
            ("require_ip", {"whitelist": [], "blacklist": ["bad"]}),
        ),
        _decorator_case(
            "require_ip_valid",
            [],
            ("require_ip", {"whitelist": ["10.0.0.0/8"], "blacklist": ["::1"]}),
        ),
        _decorator_case(
            "block_countries_empty_list",
            ["decorator.block_countries.empty_list"],
            ("block_countries", {"countries": []}),
        ),
        _decorator_case(
            "allow_countries_empty_list",
            ["decorator.allow_countries.empty_list"],
            ("allow_countries", {"countries": []}),
        ),
        _decorator_case(
            "block_countries_with_a_geo_source",
            [],
            ("block_countries", {"countries": ["US"]}),
            geo="stub",
        ),
        _decorator_case(
            "block_clouds_empty_list",
            ["decorator.block_clouds.empty_list"],
            ("block_clouds", {"providers": []}),
        ),
        _decorator_case(
            "block_clouds_unknown_provider",
            ["decorator.block_clouds.unknown_provider"],
            ("block_clouds", {"providers": ["aws", "notacloud"]}),
        ),
        _decorator_case(
            "block_clouds_unknown_providers_are_one_report",
            ["decorator.block_clouds.unknown_provider"],
            ("block_clouds", {"providers": ["zzz", "nope"]}),
        ),
        _decorator_case(
            "block_clouds_every_provider",
            [],
            ("block_clouds", {}),
        ),
        _decorator_case(
            "block_countries_without_a_geo_source",
            ["decorator.country_rule.no_geoip_source"],
            ("block_countries", {"countries": ["US"]}),
        ),
        _decorator_case(
            "allow_countries_without_a_geo_source",
            ["decorator.country_rule.no_geoip_source"],
            ("allow_countries", {"countries": ["US"]}),
        ),
        _decorator_case(
            "geo_rate_limit_without_a_geo_source",
            ["decorator.country_rule.no_geoip_source"],
            ("geo_rate_limit", {"limits": {"US": [5, 60]}}),
        ),
        _decorator_case(
            "combined_two_decorators_with_problems",
            [
                "decorator.block_countries.empty_list",
                "decorator.rate_limit.below_one",
            ],
            ("rate_limit", {"requests": 0, "window": 60}),
            ("block_countries", {"countries": []}),
        ),
    ]


def _runtime_case(
    case_id: str, intends: list[str], seam: str, **fields: JsonValue
) -> MisconfigurationCaseInput:
    return {"id": case_id, "input": {"seam": seam, **fields}, "intends": intends}


# rate_limit 10 per 60 s: one client can produce 610 strikes in the 3600 s window.
_BAN_CONFIG: JsonObject = {
    **QUIET,
    "rate_limit_window": 60,
    "auto_ban_threshold": 100,
}


def runtime_cases() -> list[MisconfigurationCaseInput]:
    return [
        _runtime_case(
            "ban_threshold_reachable",
            [],
            "ban_thresholds",
            config=_BAN_CONFIG,
        ),
        _runtime_case(
            "auto_ban_threshold_unreachable",
            ["auto_ban_threshold.unreachable"],
            "ban_thresholds",
            config={**_BAN_CONFIG, "auto_ban_threshold": 100000},
        ),
        _runtime_case(
            "threat_ban_threshold_unreachable",
            ["threat_ban_config.unreachable"],
            "ban_thresholds",
            config={
                **_BAN_CONFIG,
                "threat_ban_config": {"sqli": {"threshold": 100000, "duration": 3600}},
            },
        ),
        _runtime_case(
            "ban_threshold_bound_unknown_with_rate_limiting_off",
            [],
            "ban_thresholds",
            config={
                **_BAN_CONFIG,
                "enable_rate_limiting": False,
                "auto_ban_threshold": 100000,
            },
        ),
        _runtime_case(
            "ban_thresholds_unreachable_together",
            ["auto_ban_threshold.unreachable", "threat_ban_config.unreachable"],
            "ban_thresholds",
            config={
                **_BAN_CONFIG,
                "auto_ban_threshold": 100000,
                "threat_ban_config": {"xss": {"threshold": 100000, "duration": 3600}},
            },
        ),
        _runtime_case(
            "nat64_invalid_entry",
            ["nat64_prefixes.invalid_entry"],
            "nat64",
            config={**QUIET, "nat64_prefixes": ["10.0.0.0/8", "64:ff9b::/96"]},
        ),
        _runtime_case(
            "nat64_wrong_length",
            ["nat64_prefixes.invalid_entry"],
            "nat64",
            config={**QUIET, "nat64_prefixes": ["64:ff9b::/95"]},
        ),
        _runtime_case(
            "nat64_two_invalid_entries",
            ["nat64_prefixes.invalid_entry", "nat64_prefixes.invalid_entry"],
            "nat64",
            config={**QUIET, "nat64_prefixes": ["bad", "64:ff9b::/95"]},
        ),
        _runtime_case(
            "nat64_valid_entry",
            [],
            "nat64",
            config={**QUIET, "nat64_prefixes": ["64:ff9b::/96"]},
        ),
        _runtime_case(
            "redis_handler_complete",
            [],
            "redis_handler",
            config={**QUIET, "redis_fail_open": True},
            redis_handler={"is_connected": "sync"},
        ),
        _runtime_case(
            "redis_handler_is_connected_async",
            ["redis_handler.is_connected_async"],
            "redis_handler",
            config={**QUIET, "redis_fail_open": True},
            redis_handler={"is_connected": "async"},
        ),
        _runtime_case(
            "redis_handler_async_is_connected_with_fail_open_off",
            [],
            "redis_handler",
            config={**QUIET, "redis_fail_open": False},
            redis_handler={"is_connected": "async"},
        ),
        _runtime_case(
            "redis_handler_missing_members",
            ["redis_handler.missing_members"],
            "redis_handler",
            config={**QUIET, "redis_fail_open": True},
            redis_handler={"is_connected": "sync", "lacks": ["get_key"]},
        ),
        _runtime_case(
            "redis_handler_async_is_connected_and_missing_members",
            [
                "redis_handler.is_connected_async",
                "redis_handler.missing_members",
            ],
            "redis_handler",
            config={**QUIET, "redis_fail_open": True},
            redis_handler={"is_connected": "async", "lacks": ["get_key"]},
        ),
        _runtime_case(
            "country_rule_without_geoip",
            ["route.country_rule_without_geoip"],
            "country_decorators",
            config=dict(QUIET),
            routes={"api.blocked": {"blocked_countries": ["US"]}},
        ),
        _runtime_case(
            "country_rules_without_geoip_on_two_routes",
            [
                "route.country_rule_without_geoip",
                "route.country_rule_without_geoip",
                "route.country_rule_without_geoip",
            ],
            "country_decorators",
            config=dict(QUIET),
            routes={
                "api.a": {"whitelist_countries": ["US"]},
                "api.b": {
                    "blocked_countries": ["DE"],
                    "geo_rate_limits": {"FR": [5, 60]},
                },
            },
        ),
        _runtime_case(
            "route_without_a_country_rule",
            [],
            "country_decorators",
            config=dict(QUIET),
            routes={"api.plain": {}},
        ),
        _runtime_case(
            "ipv6_prefix_length_matches_redis",
            [],
            "ipv6_prefix_length",
            config={**QUIET, "ipv6_prefix_length": 64},
            redis_recorded_ipv6_prefix_length=64,
        ),
        _runtime_case(
            "ipv6_prefix_length_first_worker_records",
            [],
            "ipv6_prefix_length",
            config={**QUIET, "ipv6_prefix_length": 64},
            redis_recorded_ipv6_prefix_length=None,
        ),
        _runtime_case(
            "ipv6_prefix_length_differs_from_redis",
            ["ipv6_prefix_length.redis_mismatch"],
            "ipv6_prefix_length",
            config={**QUIET, "ipv6_prefix_length": 64},
            redis_recorded_ipv6_prefix_length=56,
        ),
        _runtime_case(
            "endpoint_key_matches_no_route",
            ["endpoint_rate_limits.matches_no_route"],
            "endpoint_key_routes",
            endpoint_rate_limit_keys=["/typo"],
            resolve_route="no_match",
        ),
        _runtime_case(
            "two_endpoint_keys_match_no_route",
            [
                "endpoint_rate_limits.matches_no_route",
                "endpoint_rate_limits.matches_no_route",
            ],
            "endpoint_key_routes",
            endpoint_rate_limit_keys=["/typo", "/other"],
            resolve_route="no_match",
        ),
        _runtime_case(
            "resolve_route_raises",
            ["endpoint_rate_limits.resolve_route_raised"],
            "endpoint_key_routes",
            endpoint_rate_limit_keys=["/login"],
            resolve_route="raises",
        ),
        _runtime_case(
            "exclude_path_matches_no_route",
            ["exclude_paths.matches_no_route"],
            "exclude_paths_routes",
            config={**QUIET, "exclude_paths": ["/typo"]},
            static_route_prefixes=["/api/"],
        ),
        _runtime_case(
            "exclude_path_matches_a_route",
            [],
            "exclude_paths_routes",
            config={**QUIET, "exclude_paths": ["/api"]},
            static_route_prefixes=["/api/"],
        ),
        _runtime_case(
            "static_route_prefixes_raises",
            ["exclude_paths.static_route_prefixes_raised"],
            "exclude_paths_routes",
            config={**QUIET, "exclude_paths": ["/typo"]},
            static_route_prefixes="raises",
        ),
        *_declared_path_param_cases(),
    ]


def _declared_case(
    case_id: str, intends: list[str], template: str, declared: list[str]
) -> MisconfigurationCaseInput:
    return _runtime_case(
        case_id,
        intends,
        "declared_path_params",
        config=dict(QUIET),
        template=template,
        declared=declared,
    )


def _declared_path_param_cases() -> list[MisconfigurationCaseInput]:
    missing = "decorator.detection_exclusion.param_not_in_template"
    rootless = "decorator.detection_exclusion.param_without_literal_segment"
    return [
        _declared_case(
            "declared_param_not_in_brace_template",
            [missing],
            "/items/{item_id:int}",
            ["ghost"],
        ),
        _declared_case(
            "declared_param_not_in_angle_template",
            [missing],
            "/items/<int:item_id>",
            ["ghost"],
        ),
        _declared_case(
            "declared_param_not_in_named_group_template",
            [missing],
            "/items/(?P<item_id>[0-9]+)",
            ["ghost"],
        ),
        _declared_case(
            "declared_param_rootless_catch_all", [rootless], "/{tail:path}", ["tail"]
        ),
        _declared_case(
            "declared_param_rootless_angle", [rootless], "/<name>", ["name"]
        ),
        _declared_case(
            "declared_params_missing_and_rootless",
            [missing, rootless],
            "/{tail:path}",
            ["tail", "ghost"],
        ),
        _declared_case(
            "declared_params_both_missing",
            [missing, missing],
            "/items/{item_id}",
            ["ghost", "phantom"],
        ),
        _declared_case(
            "declared_param_in_brace_template", [], "/items/{item_id}", ["item_id"]
        ),
        _declared_case(
            "declared_param_in_brace_converter_template",
            [],
            "/items/{item_id:int}",
            ["item_id"],
        ),
        _declared_case(
            "declared_param_in_angle_converter_template",
            [],
            "/items/<int:item_id>",
            ["item_id"],
        ),
        _declared_case(
            "declared_param_in_django_slug_converter_template",
            [],
            "/blog/<slug:post>/edit",
            ["post"],
        ),
        _declared_case(
            "declared_param_in_tornado_named_group_template",
            [],
            "/items/(?P<item_id>[0-9]+)",
            ["item_id"],
        ),
        _declared_case(
            "declared_param_in_catch_all_after_a_literal",
            [],
            "/files/{path:path}",
            ["path"],
        ),
        _declared_case("no_declared_params", [], "/items/{item_id}", []),
    ]


MISCONFIGURATION_SUITES = {
    "misconfiguration_config": config_cases,
    "misconfiguration_dynamic_rules": dynamic_rules_cases,
    "misconfiguration_decorators": decorator_cases,
    "misconfiguration_runtime": runtime_cases,
}
