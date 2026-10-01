"""Curated events-suite cases for the guard-core conformance corpus.

One case per engine event type (plus one passive-mode variant), covering the
complete event surface in ``guard_core/core/events/event_types.py``. Inputs
are curated by hand; every expected envelope is captured from the live
reference engine through ``events_harness.run_events_case`` - never
hand-written. The single xfail case documents the one event type that has
no deterministic in-process trigger (see its xfail_reason).
"""

from __future__ import annotations

from typing import Any

EVENTS_IP = "203.0.113.10"
ATTACK = "<script>alert(1)</script>"
ANOMALY_PATTERN = "corpuspattern-[a-z]+"

EVENTS_SUITES: dict[str, list[dict[str, Any]]] = {}

EVENTS_SUITES["event_stream"] = [
    # ---- penetration_attempt (active + passive variants) ----
    {
        "id": "evt_penetration_attempt_blocked",
        "config": {},
        "drives": [{"client_ip": EVENTS_IP, "url_path": "/api", "body": ATTACK}],
    },
    {
        "id": "evt_penetration_attempt_passive",
        "config": {"passive_mode": True},
        "drives": [{"client_ip": EVENTS_IP, "url_path": "/api", "body": ATTACK}],
    },
    # ---- ip_blocked (global filter tier) ----
    {
        "id": "evt_ip_blocked_global_blacklist",
        "config": {"blacklist": ["203.0.113.11"]},
        "drives": [{"client_ip": "203.0.113.11", "url_path": "/api"}],
    },
    # ---- ip_banned + ip_blocked (banned filter tier) ----
    {
        "id": "evt_ip_banned_then_blocked",
        "config": {},
        "drives": [
            {"call": "ban_ip", "ip": "203.0.113.12", "reason": "corpus_ban"},
            {"client_ip": "203.0.113.12", "url_path": "/api"},
        ],
    },
    # ---- ip_ban_failed (escalation ban failure, fault-injected ban_ip) ----
    {
        "id": "evt_ip_ban_failed_escalation",
        "config": {
            "blacklist": ["203.0.113.13"],
            "enable_ip_banning": True,
            "auto_ban_threshold": 1,
        },
        "drives": [
            {"call": "ipban_fault"},
            {"client_ip": "203.0.113.13", "url_path": "/api", "body": ATTACK},
        ],
    },
    # ---- ip_unbanned ----
    {
        "id": "evt_ip_unbanned",
        "config": {},
        "drives": [
            {"call": "ban_ip", "ip": "203.0.113.14", "reason": "corpus_ban"},
            {"call": "unban_ip", "ip": "203.0.113.14"},
        ],
    },
    # ---- cloud_blocked (stubbed cloud lookup) ----
    {
        "id": "evt_cloud_blocked_provider",
        "config": {},
        "routes": {"/api": {"block_cloud_providers": ["AWS"]}},
        "drives": [
            {"call": "cloud_stub", "provider": "AWS", "network": "203.0.113.0/24"},
            {"client_ip": EVENTS_IP, "url_path": "/api"},
        ],
    },
    # ---- https_enforced ----
    {
        "id": "evt_https_enforced_redirect",
        "config": {"enforce_https": True},
        "drives": [{"client_ip": EVENTS_IP, "url_path": "/api"}],
    },
    # ---- decorator_violation (route auth) ----
    {
        "id": "evt_decorator_violation_auth_required",
        "config": {},
        "routes": {"/api": {"auth_required": "bearer"}},
        "drives": [{"client_ip": EVENTS_IP, "url_path": "/api"}],
    },
    # ---- behavioral_violation ----
    {
        "id": "evt_behavioral_violation_usage_log",
        "config": {},
        "drives": [
            {
                "call": "behavior_action",
                "rule": {"rule_type": "usage", "threshold": 5, "window": 60},
                "ip": "203.0.113.15",
                "details": "Usage threshold exceeded: 5 calls in 60s",
            }
        ],
    },
    # ---- pattern_detected ----
    {
        "id": "evt_pattern_detected_xss",
        "config": {},
        "drives": [
            {
                "call": "detect",
                "content": ATTACK,
                "ip": "203.0.113.7",
                "context": "request_body",
            }
        ],
    },
    # ---- dynamic_rule_updated + dynamic_rule_applied ----
    {
        "id": "evt_dynamic_rules_update_apply",
        "config": {
            "agent_api_key": "corpus-agent-key",
            "enable_agent": True,
            "enable_dynamic_rules": True,
        },
        "drives": [
            {
                "call": "dynamic_rules",
                "rules": {"rule_id": "corpus-rules", "version": 7},
            }
        ],
    },
    # ---- emergency_mode_activated (dynamic rules lockdown) ----
    {
        "id": "evt_emergency_mode_activated",
        "config": {
            "agent_api_key": "corpus-agent-key",
            "enable_agent": True,
            "enable_dynamic_rules": True,
        },
        "drives": [
            {
                "call": "dynamic_rules",
                "rules": {
                    "rule_id": "corpus-rules",
                    "version": 9,
                    "emergency_mode": True,
                    "emergency_whitelist": ["198.51.100.5"],
                },
            }
        ],
    },
    # ---- access_denied (decorator surface) ----
    {
        "id": "evt_access_denied_decorator",
        "config": {},
        "drives": [
            {
                "call": "decorator_event",
                "send": "send_access_denied_event",
                "client_ip": EVENTS_IP,
                "url_path": "/api",
                "kwargs": {
                    "reason": "corpus access denied",
                    "decorator_type": "access_control",
                    "violation_type": "corpus",
                },
            }
        ],
    },
    # ---- authentication_failed (decorator surface) ----
    {
        "id": "evt_authentication_failed_decorator",
        "config": {},
        "drives": [
            {
                "call": "decorator_event",
                "send": "send_authentication_failed_event",
                "client_ip": EVENTS_IP,
                "url_path": "/api",
                "kwargs": {"reason": "corpus auth failed", "auth_type": "bearer"},
            }
        ],
    },
    # ---- content_filtered (route max_request_size) ----
    {
        "id": "evt_content_filtered_max_size",
        "config": {},
        "routes": {"/upload": {"max_request_size": 10}},
        "drives": [
            {
                "client_ip": EVENTS_IP,
                "url_path": "/upload",
                "method": "POST",
                "body": "x" * 64,
            }
        ],
    },
    # ---- country_blocked (stubbed GeoIP answer) ----
    {
        "id": "evt_country_blocked_geo",
        "config": {},
        "drives": [
            {
                "call": "geo_country_stub",
                "ip": "198.51.100.9",
                "country": "CN",
                "blocked_countries": ["CN"],
            }
        ],
    },
    # ---- csp_violation ----
    {
        "id": "evt_csp_violation_report",
        "config": {},
        "drives": [
            {
                "call": "csp_report",
                "report": {
                    "csp-report": {
                        "document-uri": "https://example.com/page",
                        "violated-directive": "script-src",
                        "blocked-uri": "https://evil.example/x.js",
                    }
                },
            }
        ],
    },
    # ---- custom_request_check ----
    {
        "id": "evt_custom_request_check_reject",
        "config": {"custom_request_check": "corpus_reject_all"},
        "drives": [{"client_ip": EVENTS_IP, "url_path": "/api"}],
    },
    # ---- decoding_error: no deterministic in-process trigger ----
    {
        "id": "evt_decoding_error_unreachable",
        "xfail": True,
        "xfail_reason": (
            "decoding_error fires only when urllib.parse.unquote or "
            "html.unescape raises on a str; neither raises for any str "
            "input, so the event has no deterministic in-process driver. "
            "Needs a decode-backend fault-injection surface."
        ),
        "config": {},
        "drives": [],
        "expected": [],
    },
    # ---- emergency_mode_block ----
    {
        "id": "evt_emergency_mode_block",
        "config": {"emergency_mode": True},
        "drives": [{"client_ip": EVENTS_IP, "url_path": "/api"}],
    },
    # ---- geo_lookup_failed (download failure injection) ----
    {
        "id": "evt_geo_lookup_failed_download",
        "config": {},
        "drives": [{"call": "geo_download_failure"}],
    },
    # ---- path_excluded ----
    {
        "id": "evt_path_excluded_health",
        "config": {"exclude_paths": ["/health"]},
        "drives": [
            {"call": "path_excluded", "client_ip": EVENTS_IP, "url_path": "/health"}
        ],
    },
    # ---- pattern_added ----
    {
        "id": "evt_pattern_added_custom",
        "config": {},
        "drives": [{"call": "add_pattern", "pattern": ANOMALY_PATTERN}],
    },
    # ---- pattern_removed (seeded registry, no add event) ----
    {
        "id": "evt_pattern_removed_custom",
        "config": {},
        "drives": [{"call": "remove_pattern", "pattern": ANOMALY_PATTERN}],
    },
    # ---- rate_limited (global tier, manager-side event) ----
    {
        "id": "evt_rate_limited_global",
        "config": {"rate_limit": 1, "rate_limit_window": 60},
        "drives": [
            {"client_ip": EVENTS_IP, "url_path": "/api"},
            {"client_ip": EVENTS_IP, "url_path": "/api"},
        ],
    },
    # ---- dynamic_rule_violation (endpoint tier) ----
    {
        "id": "evt_dynamic_rule_violation_endpoint",
        "config": {"endpoint_rate_limits": {"/api": [1, 60]}},
        "drives": [
            {"client_ip": EVENTS_IP, "url_path": "/api"},
            {"client_ip": EVENTS_IP, "url_path": "/api"},
        ],
    },
    # ---- rate_limit_script_reloaded (NOSCRIPT recovery against Redis) ----
    {
        "id": "evt_rate_limit_script_reloaded",
        "config": {},
        "drives": [
            {
                "call": "rate_limit_script_reload",
                "client_ip": "203.0.113.16",
                "url_path": "/api",
            }
        ],
    },
    # ---- redis_connection ----
    {
        "id": "evt_redis_connection_established",
        "config": {},
        "drives": [{"call": "redis_connect"}],
    },
    # ---- redis_error (connection refused on a dead port) ----
    {
        "id": "evt_redis_error_connection_failed",
        "config": {},
        "drives": [{"call": "redis_connect_error"}],
    },
    # ---- route_unresolved ----
    {
        "id": "evt_route_unresolved_strict",
        "config": {"route_resolution_strict": True},
        "drives": [
            {
                "client_ip": EVENTS_IP,
                "url_path": "/api",
                "guard_route_unresolved": True,
            }
        ],
    },
    # ---- security_bypass ----
    {
        "id": "evt_security_bypass_all",
        "config": {},
        "routes": {"/open": {"bypassed_checks": ["all"]}},
        "drives": [{"call": "bypass", "client_ip": EVENTS_IP, "url_path": "/open"}],
    },
    # ---- security_headers_applied ----
    {
        "id": "evt_security_headers_applied_default",
        "config": {},
        "drives": [{"call": "headers_applied", "path": "/api"}],
    },
    # ---- user_agent_blocked ----
    {
        "id": "evt_user_agent_blocked_global",
        "config": {"blocked_user_agents": ["evilbot/1.0"]},
        "drives": [
            {
                "client_ip": EVENTS_IP,
                "url_path": "/api",
                "headers": {"User-Agent": "evilbot/1.0"},
            }
        ],
    },
    # ---- suspicious_request (X-Forwarded-For from an untrusted proxy) ----
    {
        "id": "evt_suspicious_request_untrusted_proxy",
        "config": {"trusted_proxies": ["192.0.2.1"]},
        "drives": [
            {
                "client_ip": "203.0.113.17",
                "url_path": "/api",
                "headers": {"X-Forwarded-For": "198.51.100.77"},
                "drop_cached_client_ip": True,
            }
        ],
    },
    # ---- detection_engine_callback_error (raising anomaly callback) ----
    {
        "id": "evt_detection_engine_callback_error",
        "config": {},
        "drives": [
            {
                "call": "monitor_callback_fault",
                "pattern": ANOMALY_PATTERN,
                "execution_time": 0.5,
            }
        ],
    },
    # ---- pattern_anomaly_timeout ----
    {
        "id": "evt_pattern_anomaly_timeout",
        "config": {},
        "drives": [
            {
                "call": "monitor_anomaly",
                "samples": [
                    {
                        "pattern": ANOMALY_PATTERN,
                        "execution_time": 0.0,
                        "timeout": True,
                    }
                ],
            }
        ],
    },
    # ---- pattern_anomaly_slow_execution ----
    {
        "id": "evt_pattern_anomaly_slow_execution",
        "config": {},
        "drives": [
            {
                "call": "monitor_anomaly",
                "slow_pattern_threshold": 0.1,
                "samples": [{"pattern": ANOMALY_PATTERN, "execution_time": 0.5}],
            }
        ],
    },
    # ---- pattern_anomaly_statistical_anomaly ----
    {
        "id": "evt_pattern_anomaly_statistical",
        "config": {},
        "drives": [
            {
                "call": "monitor_anomaly",
                "anomaly_threshold": 3.0,
                "min_samples_for_anomaly": 10,
                # Slow-execution ceiling raised above the spike so the
                # statistical detector is the only anomaly to fire.
                "slow_pattern_threshold": 10.0,
                "samples": [
                    {
                        "pattern": ANOMALY_PATTERN,
                        "execution_time": 0.08 if i % 2 == 0 else 0.12,
                    }
                    for i in range(20)
                ]
                + [{"pattern": ANOMALY_PATTERN, "execution_time": 5.0}],
            }
        ],
    },
]
