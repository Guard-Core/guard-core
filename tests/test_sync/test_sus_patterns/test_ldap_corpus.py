from typing import Any

import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.sync.handlers.suspatterns_handler import sus_patterns_handler
from guard_core.sync.utils import detect_penetration_attempt


@pytest.fixture(autouse=True)
def _force_enhanced_detection_singleton() -> None:
    sus_patterns_handler.configure(SyncSecurityConfig())


LDAP_PAREN_CONJUNCTION_STILL_FLAGGED = [
    pytest.param("(|(uid=*)(cn=*))", id="or_filter_wildcard_uid_cn"),
    pytest.param("(&(objectClass=user)(uid=*))", id="and_filter_wildcard_uid"),
    pytest.param("admin)(|(password=*", id="bare_or_paren_password_bypass"),
    pytest.param("(|(&", id="nested_filter_bypass_truncated"),
]

LDAP_PAREN_CONJUNCTION_WITHOUT_FOLLOWUP_NOT_FLAGGED = [
    pytest.param("(| end of message", id="or_paren_followed_by_prose"),
    pytest.param("(& end of message", id="and_paren_followed_by_prose"),
    pytest.param("logic gate (| means OR in this DSL", id="prose_mentions_or_paren"),
]

LDAP_WILDCARD_BREAKOUT_GAP_TOLERANT_FLAGGED = [
    pytest.param("*)(cn=admin", id="breakout_glued_cn_equals"),
    pytest.param("* ) ( cn=admin", id="breakout_every_gap_spaced_cn_equals"),
    pytest.param("*) (cn=admin", id="breakout_space_gap_cn_equals"),
    pytest.param("*)\t(cn=admin", id="breakout_tab_gap_cn_equals"),
    pytest.param("*)\n(cn=admin", id="breakout_newline_gap_cn_equals"),
    pytest.param("*)%20(cn=admin", id="breakout_percent20_gap_cn_equals"),
    pytest.param("*)%09(cn=admin", id="breakout_percent09_gap_cn_equals"),
    pytest.param("*)%0a(cn=admin", id="breakout_percent0a_gap_cn_equals"),
    pytest.param("* )( uid=*", id="breakout_leading_gap_wildcard_uid_equals_wildcard"),
    pytest.param("*)(&", id="breakout_glued_and_operator_no_attribute"),
    pytest.param("*) (&", id="breakout_space_gap_and_operator"),
    pytest.param("*)\t(&", id="breakout_tab_gap_and_operator"),
    pytest.param("*)\n(&", id="breakout_newline_gap_and_operator"),
    pytest.param("*)%20(&", id="breakout_percent20_gap_and_operator"),
    pytest.param("*)%09(&", id="breakout_percent09_gap_and_operator"),
    pytest.param("*)%0a(&", id="breakout_percent0a_gap_and_operator"),
]

LDAP_WILDCARD_BREAKOUT_CASE_VARIANT_FLAGGED = [
    pytest.param("*)(CN=admin", id="breakout_glued_uppercase_cn_equals"),
    pytest.param("*)(Cn=Admin", id="breakout_glued_mixedcase_cn_equals"),
]

LDAP_WILDCARD_BREAKOUT_EXTENSIBLE_MATCH_FLAGGED = [
    pytest.param("*)(cn:=admin", id="extensible_match_glued_bare_colon_equals"),
    pytest.param("*) (cn:=admin", id="extensible_match_space_gap_bare_colon_equals"),
    pytest.param(
        "*)%20(cn:=admin", id="extensible_match_percent20_gap_bare_colon_equals"
    ),
    pytest.param("*)(cn:dn:2.5.13.2:=admin", id="extensible_match_glued_dn_rule_oid"),
    pytest.param(
        "*) (cn:dn:2.5.13.2:=admin",
        id="extensible_match_space_gap_dn_rule_oid",
    ),
    pytest.param(
        "*)%20(cn:dn:2.5.13.2:=admin",
        id="extensible_match_percent20_gap_dn_rule_oid",
    ),
    pytest.param(
        "*)(|(cn:caseExactMatch:=admin",
        id="extensible_match_glued_boolean_operator_arm",
    ),
    pytest.param(
        "*) (|(cn:caseExactMatch:=admin",
        id="extensible_match_space_gap_boolean_operator_arm",
    ),
    pytest.param(
        "*)%20(|(cn:caseExactMatch:=admin",
        id="extensible_match_percent20_gap_boolean_operator_arm",
    ),
]

LDAP_PAREN_BREAKOUT_NO_WILDCARD_FLAGGED = [
    pytest.param("admin)(&)", id="no_wildcard_glued_boolean_operator_breakout"),
    pytest.param("admin) (&)", id="no_wildcard_space_gap_boolean_operator_breakout"),
    pytest.param(
        "admin)%20(&)", id="no_wildcard_percent20_gap_boolean_operator_breakout"
    ),
    pytest.param("admin)(cn=*)", id="no_wildcard_close_wildcard_attribute_tail"),
    pytest.param("admin)(|(uid=*))", id="no_wildcard_close_or_wildcard_clause_tail"),
    pytest.param(
        "admin)(objectClass=*)", id="no_wildcard_close_objectclass_wildcard_tail"
    ),
    pytest.param(
        "admin))(|(cn=x)(cn=y",
        id="double_close_then_or_conjunction_breakout",
    ),
]

LDAP_PAREN_BREAKOUT_INERT_BARE_ATTRIBUTE_NOT_FLAGGED = [
    pytest.param(
        "admin)(cn=x)",
        id="glued_bare_attribute_no_attack_token_matches_base_and_is_inert",
    ),
    pytest.param(
        "admin) (cn=x)",
        id="space_gap_bare_attribute_no_attack_token_matches_base_and_is_inert",
    ),
    pytest.param(
        "admin)%20(cn=x)",
        id="percent20_gap_bare_attribute_no_attack_token_matches_base_and_is_inert",
    ),
]

LDAP_PAREN_BREAKOUT_ATTACKER_CONTROLLED_WILDCARD_CLAUSE_FLAGGED = [
    pytest.param("(cn=x*)(cn=admin)", id="prefixed_wildcard_clause_then_cn_admin"),
    pytest.param(
        "(uid=abc*)(cn=admin)", id="prefixed_wildcard_clause_then_cn_admin_uid"
    ),
    pytest.param(
        "(sAMAccountName=admin*)(objectClass=user)",
        id="prefixed_wildcard_clause_samaccountname_then_objectclass",
    ),
    pytest.param(
        "(mail=a@b.com*)(isAdmin=TRUE)",
        id="prefixed_wildcard_clause_mail_then_is_admin",
    ),
]

LDAP_PAREN_BREAKOUT_FIELD_BOUNDARY_FLAGGED = [
    pytest.param(
        '{"note": "(hi", "user": "admin)(cn=*)"}',
        id="json_field_boundary_hides_unrelated_open_paren",
    ),
    pytest.param(
        "?note=(hi&user=admin)(cn=*)",
        id="query_string_ampersand_boundary_hides_unrelated_open_paren",
    ),
]

LDAP_PAREN_BREAKOUT_LOCAL_BALANCE_NOT_FLAGGED = [
    pytest.param("(a)(b=1)", id="balanced_single_letter_clause_then_attribute"),
    pytest.param("$(cmd)(x=1)", id="shell_substitution_then_attribute"),
    pytest.param("items: 5 (approx)(note=see)", id="prose_parenthetical_asides"),
    pytest.param("(admin)(cn=x)", id="balanced_value_then_attribute_breakout_shape"),
    pytest.param("?q=(admin)(cn=x)", id="query_string_balanced_value_then_attribute"),
]

LDAP_PAREN_BREAKOUT_TRUNCATED_PROSE_NOT_FLAGGED = [
    pytest.param(
        "request completed) (status=200", id="truncated_prose_status_code_aside"
    ),
    pytest.param("fi) (VAR=value)", id="truncated_prose_shell_fi_aside"),
    pytest.param("note) (dept=sales", id="truncated_prose_department_aside"),
    pytest.param("yeah that works) (mode=auto", id="truncated_prose_mode_auto_aside"),
]

LDAP_WILDCARD_BREAKOUT_COMPLETE_CLAUSE_NOT_FLAGGED = [
    pytest.param(
        "Our nightly sync uses filter: (objectClass=*)(department=Sales) "
        "and it worked fine.",
        id="complete_clause_objectclass_wildcard_then_department",
    ),
    pytest.param(
        "search_filter: (uid=*)(status=active)",
        id="complete_clause_uid_wildcard_then_status",
    ),
]

LDAP_WILDCARD_EQUALS_UNBOUNDED_NOISE_NOT_FLAGGED = [
    pytest.param("*" + ("x" * 200) + "=end", id="wildcard_then_long_word_run_equals"),
]

LDAP_WILDCARD_EQUALS_HYPHENATED_ATTR_NOT_A_FILTER_SHAPE_NOT_FLAGGED = [
    pytest.param("*given-name=admin", id="wildcard_glued_hyphenated_attr_equals"),
    pytest.param("*x-custom-attr=1", id="wildcard_glued_multi_hyphen_attr_equals"),
]

LDAP_WILDCARD_EQUALS_HYPHENATED_BENIGN_PROSE_NOT_FLAGGED = [
    pytest.param(
        "Default is *cache-ttl=300 seconds unless overridden",
        id="hyphenated_prose_trailing_star",
    ),
    pytest.param(
        "Pass *dry-run=true* to preview changes",
        id="hyphenated_prose_emphasis_wrapped",
    ),
    pytest.param(
        "- *log-level=debug* enables verbose output",
        id="hyphenated_prose_bullet_list_item",
    ),
    pytest.param(
        "OPTIONS\n  *dry-run=true   Preview changes",
        id="hyphenated_prose_options_help_block",
    ),
]

LDAP_WILDCARD_EQUALS_CRONTAB_SHAPES_NOT_FLAGGED = [
    pytest.param(
        "5 4 * * * root\nPATH=/usr/bin:/bin bash -c 'do_backup.sh'",
        id="crontab_backup_line",
    ),
    pytest.param(
        "0 2 * * 0 svc\nPATH=/usr/local/bin:/usr/bin bash -c 'weekly_cleanup.sh'",
        id="crontab_weekly_cleanup",
    ),
    pytest.param(
        "*/15 * * * * root\nMAILTO=admin@example.com bash -c 'health_check.sh'",
        id="crontab_step_health_check",
    ),
    pytest.param(
        "30 3 1 * * root\nHOME=/root bash -c 'monthly_report.sh'",
        id="crontab_monthly_report",
    ),
    pytest.param(
        "5 4 * * * root PATH=/usr/bin:/bin bash -c 'do_backup.sh'",
        id="crontab_already_single_line",
    ),
    pytest.param(
        "0 0 * * * root\nLOGNAME=root bash -c 'reboot_check.sh'",
        id="crontab_daily_reboot_check",
    ),
    pytest.param(
        "5 4 * * *\nPATH=/usr/bin:/bin bash -c 'do_backup.sh'",
        id="crontab_no_user_field_personal_crontab",
    ),
    pytest.param(
        "* * * * * MAILTO=admin@example.com bash -c 'do_backup.sh'",
        id="crontab_inline_mailto_one_liner",
    ),
    pytest.param(
        "# nightly backup job\n5 4 * * * root\nPATH=/usr/bin:/bin bash -c 'backup.sh'",
        id="crontab_comment_line",
    ),
    pytest.param(
        "5 4 * * * root\nPATH=/usr/bin:/bin\nMAILTO=admin@example.com\n"
        "bash -c 'backup.sh'",
        id="crontab_env_block",
    ),
    pytest.param(
        "*/5 9-17 * * 1-5\nPATH=/usr/bin bash -c 'workhours.sh'",
        id="crontab_step_range_list_combined",
    ),
    pytest.param(
        "@reboot\nPATH=/usr/bin bash -c 'startup.sh'",
        id="crontab_named_reboot",
    ),
    pytest.param(
        "5\t4\t*\t*\t*\troot\nPATH=/usr/bin:/bin bash -c 'backup.sh'",
        id="crontab_tab_separated",
    ),
    pytest.param(
        "schedule: |\n  5 4 * * *\n  PATH=/usr/bin bash -c 'backup.sh'",
        id="crontab_yaml_wrapped",
    ),
    pytest.param(
        '{"cron": "5 4 * * *\nPATH=/usr/bin bash -c backup.sh"}',
        id="crontab_json_wrapped",
    ),
]


@pytest.mark.parametrize("payload", LDAP_PAREN_CONJUNCTION_STILL_FLAGGED)
def test_ldap_paren_conjunction_still_flagged(payload: str) -> None:
    result = sus_patterns_handler.detect(
        content=payload, ip_address="203.0.113.9", context="request_body"
    )
    assert result["is_threat"] is True
    assert any(threat.get("category") == "ldap" for threat in result["threats"])


@pytest.mark.parametrize("payload", LDAP_PAREN_CONJUNCTION_WITHOUT_FOLLOWUP_NOT_FLAGGED)
def test_ldap_paren_conjunction_without_followup_not_flagged(
    payload: str,
) -> None:
    result = sus_patterns_handler.detect(
        content=payload, ip_address="203.0.113.9", context="request_body"
    )
    assert not any(threat.get("category") == "ldap" for threat in result["threats"])


@pytest.mark.parametrize("payload", LDAP_WILDCARD_BREAKOUT_GAP_TOLERANT_FLAGGED)
def test_ldap_wildcard_breakout_gap_tolerant_flagged(payload: str) -> None:
    result = sus_patterns_handler.detect(
        content=payload, ip_address="203.0.113.9", context="request_body"
    )
    assert result["is_threat"] is True
    assert any(threat.get("category") == "ldap" for threat in result["threats"])


@pytest.mark.parametrize("payload", LDAP_WILDCARD_BREAKOUT_CASE_VARIANT_FLAGGED)
def test_ldap_wildcard_breakout_case_variant_flagged(payload: str) -> None:
    result = sus_patterns_handler.detect(
        content=payload, ip_address="203.0.113.9", context="request_body"
    )
    assert result["is_threat"] is True
    assert any(threat.get("category") == "ldap" for threat in result["threats"])


@pytest.mark.parametrize("payload", LDAP_WILDCARD_BREAKOUT_EXTENSIBLE_MATCH_FLAGGED)
def test_ldap_wildcard_breakout_extensible_match_flagged(payload: str) -> None:
    result = sus_patterns_handler.detect(
        content=payload, ip_address="203.0.113.9", context="request_body"
    )
    assert result["is_threat"] is True
    assert any(threat.get("category") == "ldap" for threat in result["threats"])


@pytest.mark.parametrize("payload", LDAP_PAREN_BREAKOUT_NO_WILDCARD_FLAGGED)
def test_ldap_paren_breakout_no_wildcard_flagged(payload: str) -> None:
    result = sus_patterns_handler.detect(
        content=payload, ip_address="203.0.113.9", context="request_body"
    )
    assert result["is_threat"] is True
    assert any(threat.get("category") == "ldap" for threat in result["threats"])


@pytest.mark.parametrize(
    "payload", LDAP_PAREN_BREAKOUT_INERT_BARE_ATTRIBUTE_NOT_FLAGGED
)
def test_ldap_paren_breakout_inert_bare_attribute_not_flagged(
    payload: str,
) -> None:
    result = sus_patterns_handler.detect(
        content=payload, ip_address="198.51.100.4", context="request_body"
    )
    assert not any(threat.get("category") == "ldap" for threat in result["threats"])


@pytest.mark.parametrize(
    "payload", LDAP_PAREN_BREAKOUT_ATTACKER_CONTROLLED_WILDCARD_CLAUSE_FLAGGED
)
def test_ldap_paren_breakout_attacker_controlled_wildcard_clause_flagged(
    payload: str,
) -> None:
    result = sus_patterns_handler.detect(
        content=payload, ip_address="203.0.113.9", context="request_body"
    )
    assert result["is_threat"] is True
    assert any(threat.get("category") == "ldap" for threat in result["threats"])


@pytest.mark.parametrize("payload", LDAP_PAREN_BREAKOUT_FIELD_BOUNDARY_FLAGGED)
def test_ldap_paren_breakout_field_boundary_flagged(payload: str) -> None:
    result = sus_patterns_handler.detect(
        content=payload, ip_address="203.0.113.9", context="request_body"
    )
    assert result["is_threat"] is True
    assert any(threat.get("category") == "ldap" for threat in result["threats"])


@pytest.mark.parametrize("payload", LDAP_PAREN_BREAKOUT_LOCAL_BALANCE_NOT_FLAGGED)
def test_ldap_paren_breakout_local_balance_not_flagged(payload: str) -> None:
    result = sus_patterns_handler.detect(
        content=payload, ip_address="198.51.100.4", context="request_body"
    )
    assert not any(threat.get("category") == "ldap" for threat in result["threats"])


@pytest.mark.parametrize("payload", LDAP_PAREN_BREAKOUT_TRUNCATED_PROSE_NOT_FLAGGED)
def test_ldap_paren_breakout_truncated_prose_not_flagged(payload: str) -> None:
    result = sus_patterns_handler.detect(
        content=payload, ip_address="198.51.100.4", context="request_body"
    )
    assert not any(threat.get("category") == "ldap" for threat in result["threats"])


@pytest.mark.parametrize("payload", LDAP_WILDCARD_BREAKOUT_COMPLETE_CLAUSE_NOT_FLAGGED)
def test_ldap_wildcard_breakout_complete_clause_not_flagged(
    payload: str,
) -> None:
    result = sus_patterns_handler.detect(
        content=payload, ip_address="198.51.100.4", context="request_body"
    )
    assert not any(threat.get("category") == "ldap" for threat in result["threats"])


@pytest.mark.parametrize("payload", LDAP_WILDCARD_EQUALS_UNBOUNDED_NOISE_NOT_FLAGGED)
def test_ldap_wildcard_equals_unbounded_noise_not_flagged(
    payload: str,
) -> None:
    result = sus_patterns_handler.detect(
        content=payload, ip_address="203.0.113.9", context="request_body"
    )
    assert not any(threat.get("category") == "ldap" for threat in result["threats"])


@pytest.mark.parametrize(
    "payload", LDAP_WILDCARD_EQUALS_HYPHENATED_ATTR_NOT_A_FILTER_SHAPE_NOT_FLAGGED
)
def test_ldap_wildcard_equals_hyphenated_attr_not_a_filter_shape_not_flagged(
    payload: str,
) -> None:
    result = sus_patterns_handler.detect(
        content=payload, ip_address="203.0.113.9", context="request_body"
    )
    assert not any(threat.get("category") == "ldap" for threat in result["threats"])


@pytest.mark.parametrize(
    "payload", LDAP_WILDCARD_EQUALS_HYPHENATED_BENIGN_PROSE_NOT_FLAGGED
)
def test_ldap_wildcard_equals_hyphenated_benign_prose_not_flagged(
    payload: str,
) -> None:
    result = sus_patterns_handler.detect(
        content=payload, ip_address="203.0.113.9", context="request_body"
    )
    assert not any(threat.get("category") == "ldap" for threat in result["threats"])


@pytest.mark.parametrize("payload", LDAP_WILDCARD_EQUALS_CRONTAB_SHAPES_NOT_FLAGGED)
def test_ldap_wildcard_equals_crontab_shapes_not_flagged(payload: str) -> None:
    result = sus_patterns_handler.detect(
        content=payload, ip_address="203.0.113.9", context="request_body"
    )
    assert not any(threat.get("category") == "ldap" for threat in result["threats"])


LDAP_PAREN_BREAKOUT_SCAN_WINDOW_TRUNCATED_CLAUSE_NOT_FLAGGED = [
    pytest.param("(" + "x" * 38 + ")(cn=*)", id="filler_38_below_window_bound"),
    pytest.param("(" + "x" * 39 + ")(cn=*)", id="filler_39_below_window_bound"),
    pytest.param("(" + "x" * 40 + ")(cn=*)", id="filler_40_at_window_bound"),
    pytest.param("(" + "x" * 41 + ")(cn=*)", id="filler_41_past_window_bound"),
    pytest.param(
        "log_cleanup: (Cleanup completed after scanning all directories for "
        "old files older than thirty days per policy)(pattern=*.log)",
        id="natural_prose_parenthetical_past_window_bound",
    ),
]

LDAP_PAREN_BREAKOUT_COMPARATOR_FLAGGED = [
    pytest.param("admin)(cn~=x", id="approximate_match_comparator_breakout"),
    pytest.param("admin)(sn>=A", id="greater_or_equal_comparator_breakout"),
    pytest.param(
        "admin)(userPassword>=A", id="greater_or_equal_comparator_breakout_userpassword"
    ),
]

LDAP_WILDCARD_BREAKOUT_EXTENDED_ATTR_DESC_FLAGGED = [
    pytest.param(
        "*)(:caseExactMatch:=admin",
        id="wildcard_no_attr_extensible_match_caseexact",
    ),
    pytest.param(
        "*)(:1.2.840.113556.1.4.804:=admin",
        id="wildcard_no_attr_extensible_match_oid_rule",
    ),
    pytest.param(
        "*)(:dn:1.2.840.113556.1.4.804:=admin",
        id="wildcard_no_attr_dn_oid_rule",
    ),
    pytest.param(
        "*)(1.3.6.1.4.1.1466.0=admin",
        id="wildcard_numericoid_attr_equality",
    ),
    pytest.param(
        "*)(1.3.6.1.4.1.1466.0=*)",
        id="wildcard_numericoid_attr_wildcard_extraction",
    ),
    pytest.param(
        "*)(1.2.840.113556.1.4.804:=admin",
        id="wildcard_numericoid_attr_extensible_match",
    ),
    pytest.param(
        "*)(cn;lang-en:=admin",
        id="wildcard_attr_options_single_extensible_match",
    ),
    pytest.param(
        "*)(cn;lang-en;binary:=admin",
        id="wildcard_attr_multi_options_extensible_match",
    ),
]

LDAP_PAREN_BREAKOUT_COMPARATOR_EXTENDED_ATTR_DESC_FLAGGED = [
    pytest.param(
        "uid=foo)(1.2.840~=admin",
        id="numericoid_attr_approximate_match_comparator_breakout",
    ),
    pytest.param(
        "uid=foo)(:caseExactMatch~=admin",
        id="no_attr_extensible_match_approximate_comparator_breakout",
    ),
    pytest.param(
        "uid=foo)(cn;lang-en~=admin",
        id="attr_options_approximate_match_comparator_breakout",
    ),
]

LDAP_WILDCARD_BREAKOUT_QUERY_SURFACE_EXTENDED_ATTR_DESC_FLAGGED = [
    pytest.param(
        "q=*)(:caseExactMatch:=admin",
        id="query_surface_wildcard_no_attr_extensible_match",
    ),
    pytest.param(
        "q=*)(1.3.6.1.4.1.1466.0=*)",
        id="query_surface_wildcard_numericoid_attr_wildcard_extraction",
    ),
]

LDAP_PAREN_BREAKOUT_INERT_EXTENDED_BARE_ATTRIBUTE_NOT_FLAGGED = [
    pytest.param(
        "admin)(:caseExactMatch:=admin",
        id="inert_no_attr_bare_equality_only_adds_constraint_parity_with_admin_cn_x",
    ),
    pytest.param(
        "admin)(1.3.6.1.4.1.1466.0=admin",
        id="inert_numericoid_bare_equality_only_adds_constraint_parity_with_admin_cn_x",
    ),
    pytest.param(
        "admin)(cn;lang-en:=admin",
        id="inert_attr_options_bare_equality_only_adds_constraint_parity_with_admin_cn_x",
    ),
]

LDAP_RFC4515_HEX_ESCAPE_FLAGGED = [
    pytest.param(
        r"admin\29\28cn=\2a", id="rfc4515_hex_escaped_paren_breakout_wildcard"
    ),
    pytest.param(r"*\29\28cn=admin", id="rfc4515_hex_escaped_wildcard_chain_breakout"),
]


@pytest.mark.parametrize(
    "payload", LDAP_PAREN_BREAKOUT_SCAN_WINDOW_TRUNCATED_CLAUSE_NOT_FLAGGED
)
def test_ldap_paren_breakout_scan_window_truncated_clause_not_flagged(
    payload: str,
) -> None:
    result = sus_patterns_handler.detect(
        content=payload, ip_address="198.51.100.4", context="request_body"
    )
    assert not any(threat.get("category") == "ldap" for threat in result["threats"])


@pytest.mark.parametrize("payload", LDAP_PAREN_BREAKOUT_COMPARATOR_FLAGGED)
def test_ldap_paren_breakout_comparator_flagged(payload: str) -> None:
    result = sus_patterns_handler.detect(
        content=payload, ip_address="203.0.113.9", context="request_body"
    )
    assert result["is_threat"] is True
    assert any(threat.get("category") == "ldap" for threat in result["threats"])


@pytest.mark.parametrize("payload", LDAP_RFC4515_HEX_ESCAPE_FLAGGED)
def test_ldap_rfc4515_hex_escape_flagged(payload: str) -> None:
    result = sus_patterns_handler.detect(
        content=payload, ip_address="203.0.113.9", context="request_body"
    )
    assert result["is_threat"] is True
    assert any(threat.get("category") == "ldap" for threat in result["threats"])


@pytest.mark.parametrize("payload", LDAP_WILDCARD_BREAKOUT_EXTENDED_ATTR_DESC_FLAGGED)
def test_ldap_wildcard_breakout_extended_attr_desc_flagged(
    payload: str,
) -> None:
    result = sus_patterns_handler.detect(
        content=payload, ip_address="203.0.113.9", context="request_body"
    )
    assert result["is_threat"] is True
    assert any(threat.get("category") == "ldap" for threat in result["threats"])


@pytest.mark.parametrize(
    "payload", LDAP_PAREN_BREAKOUT_COMPARATOR_EXTENDED_ATTR_DESC_FLAGGED
)
def test_ldap_paren_breakout_comparator_extended_attr_desc_flagged(
    payload: str,
) -> None:
    result = sus_patterns_handler.detect(
        content=payload, ip_address="203.0.113.9", context="request_body"
    )
    assert result["is_threat"] is True
    assert any(threat.get("category") == "ldap" for threat in result["threats"])


@pytest.mark.parametrize(
    "payload", LDAP_WILDCARD_BREAKOUT_QUERY_SURFACE_EXTENDED_ATTR_DESC_FLAGGED
)
def test_ldap_wildcard_breakout_query_surface_extended_attr_desc_flagged(
    payload: str,
) -> None:
    result = sus_patterns_handler.detect(
        content=payload, ip_address="203.0.113.9", context="request_body"
    )
    assert result["is_threat"] is True
    assert any(threat.get("category") == "ldap" for threat in result["threats"])


@pytest.mark.parametrize(
    "payload", LDAP_PAREN_BREAKOUT_INERT_EXTENDED_BARE_ATTRIBUTE_NOT_FLAGGED
)
def test_ldap_paren_breakout_inert_extended_bare_attribute_not_flagged(
    payload: str,
) -> None:
    result = sus_patterns_handler.detect(
        content=payload, ip_address="198.51.100.4", context="request_body"
    )
    assert not any(threat.get("category") == "ldap" for threat in result["threats"])


_LDAP_OID_34 = "1" + ".2" * 33
_LDAP_OPT_17 = "cn" + ";opt" * 17
_LDAP_WIRE_MECHANISMS = ("raw_body", "query_param")

LDAP_CAP_REMOVAL_OID_BREAKOUT_WIRE_FLAGGED = [
    pytest.param(
        f"admin)({_LDAP_OID_34}~=admin",
        id="wire_34_component_oid_paren_breakout_approximate",
    ),
    pytest.param(
        f"*)({_LDAP_OID_34}:=admin",
        id="wire_34_component_oid_no_attr_extensible_match",
    ),
    pytest.param(
        f"*))(({_LDAP_OID_34}:=admin",
        id="wire_34_component_oid_wildcard_equals_extensible_match",
    ),
]

LDAP_CAP_REMOVAL_OPTION_BREAKOUT_WIRE_FLAGGED = [
    pytest.param(
        f"admin)({_LDAP_OPT_17}~=admin",
        id="wire_17_option_attr_approximate_match_breakout",
    ),
    pytest.param(
        f"*)({_LDAP_OPT_17}:=admin",
        id="wire_17_option_attr_extensible_match_wildcard_chain",
    ),
]


class _WireState:
    pass


class _WireReq:
    def __init__(self, body: bytes, mechanism: str) -> None:
        self.client_host = "203.0.113.9"
        self.url_path = "/x"
        self.method = "POST"
        self.state: Any = _WireState()
        self.query_params: dict[str, str] = {}
        self.headers: dict[str, str] = {"content-type": "text/plain"}
        self._body = body
        if mechanism == "query_param":
            self.query_params = {"v": body.decode("utf-8", errors="surrogateescape")}
            self._body = b""
        self.headers["content-length"] = str(len(self._body))

    url_scheme: str = "https"
    url_full: str = "https://t/"
    scope: dict[str, Any] = {}

    def url_replace_scheme(self, _scheme: str) -> str:
        return "https://t/"

    def body(self) -> bytes:
        return self._body


@pytest.mark.parametrize("mechanism", _LDAP_WIRE_MECHANISMS)
@pytest.mark.parametrize("payload", LDAP_CAP_REMOVAL_OID_BREAKOUT_WIRE_FLAGGED)
def test_ldap_cap_removal_oid_breakout_wire_flagged(
    payload: str, mechanism: str
) -> None:
    result = detect_penetration_attempt(
        _WireReq(payload.encode("utf-8"), mechanism), SyncSecurityConfig()
    )
    assert result.is_threat is True
    assert "ldap" in result.threat_categories


@pytest.mark.parametrize("mechanism", _LDAP_WIRE_MECHANISMS)
@pytest.mark.parametrize("payload", LDAP_CAP_REMOVAL_OPTION_BREAKOUT_WIRE_FLAGGED)
def test_ldap_cap_removal_option_breakout_wire_flagged(
    payload: str, mechanism: str
) -> None:
    result = detect_penetration_attempt(
        _WireReq(payload.encode("utf-8"), mechanism), SyncSecurityConfig()
    )
    assert result.is_threat is True
    assert "ldap" in result.threat_categories
