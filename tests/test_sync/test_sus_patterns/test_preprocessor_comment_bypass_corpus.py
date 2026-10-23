import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.sync.detection_engine.preprocessor import ContentPreprocessor
from guard_core.sync.handlers.suspatterns_handler import sus_patterns_handler

ATTACK_AFTER_SPECIAL_CONSTRUCT_PAYLOADS = [
    pytest.param(
        "id=1-- <script>alert(1)</script>",
        "<script>alert(1)</script>",
        id="dashdash_leads_into_script_tag",
    ),
    pytest.param(
        "id=1-- UNION SELECT password FROM users",
        "UNION SELECT",
        id="dashdash_leads_into_union_select",
    ),
    pytest.param(
        "note-- ; DROP TABLE users",
        "DROP TABLE users",
        id="dashdash_leads_into_drop_table",
    ),
    pytest.param(
        "id=1-- OR 'a'='a'",
        "OR 'a'='a'",
        id="dashdash_leads_into_or_tautology",
    ),
    pytest.param(
        "id=1-- SLEEP(5)",
        "SLEEP(5)",
        id="dashdash_leads_into_sleep",
    ),
    pytest.param(
        "page=1-- /etc/passwd",
        "/etc/passwd",
        id="dashdash_leads_into_etc_passwd",
    ),
    pytest.param(
        "note-- ; cat /etc/passwd -la",
        "cat /etc/passwd",
        id="dashdash_leads_into_cat_etc_passwd",
    ),
    pytest.param(
        "note-- ; $(whoami)",
        "$(whoami)",
        id="dashdash_leads_into_dollar_paren_whoami",
    ),
    pytest.param(
        "note-- {{ system('id') }}",
        "system('id')",
        id="dashdash_leads_into_ssti_curly",
    ),
    pytest.param(
        "note-- http://169.254.169.254/latest/meta-data",
        "169.254.169.254",
        id="dashdash_leads_into_ssrf_metadata_ip",
    ),
    pytest.param(
        "id=1# <script>alert(1)</script>",
        "<script>alert(1)</script>",
        id="hash_leads_into_script_tag",
    ),
    pytest.param(
        "id=1# UNION SELECT password FROM users",
        "UNION SELECT",
        id="hash_leads_into_union_select",
    ),
    pytest.param(
        "note# ; DROP TABLE users",
        "DROP TABLE users",
        id="hash_leads_into_drop_table",
    ),
    pytest.param(
        "note# ; whoami",
        "whoami",
        id="hash_leads_into_bare_whoami",
    ),
    pytest.param(
        'note# {"$where": "1"}',
        "$where",
        id="hash_leads_into_nosql_where",
    ),
    pytest.param(
        "id=1/* comment */<script>alert(1)</script>",
        "<script>alert(1)</script>",
        id="block_comment_leads_into_script_tag",
    ),
    pytest.param(
        "id=1/* comment */ UNION SELECT password FROM users",
        "UNION SELECT",
        id="block_comment_leads_into_union_select",
    ),
    pytest.param(
        "note/* comment */ ; DROP TABLE users",
        "DROP TABLE users",
        id="block_comment_leads_into_drop_table",
    ),
    pytest.param(
        "note/* comment */ ; whoami",
        "whoami",
        id="block_comment_leads_into_bare_whoami",
    ),
    pytest.param(
        "note/* comment */ {{ system('id') }}",
        "system('id')",
        id="block_comment_leads_into_ssti_curly",
    ),
    pytest.param(
        "/* leading */<script>alert(1)</script>",
        "<script>alert(1)</script>",
        id="leading_block_comment_before_script_tag",
    ),
    pytest.param(
        "id=1/*\nmultiline\ncomment\n*/<script>alert(1)</script>",
        "<script>alert(1)</script>",
        id="multiline_block_comment_before_script_tag",
    ),
    pytest.param(
        "id=1# note /* x */ <script>alert(1)</script>",
        "<script>alert(1)</script>",
        id="hash_then_block_comment_before_script_tag",
    ),
    pytest.param(
        "id=1-- note /* x */ UNION SELECT password FROM users",
        "UNION SELECT",
        id="dashdash_then_block_comment_before_union_select",
    ),
    pytest.param(
        "id=1/* comment */ SLEEP(5)",
        "SLEEP(5)",
        id="block_comment_leads_into_sleep",
    ),
    pytest.param(
        "id=1-- BENCHMARK(1000000,MD5(1))",
        "BENCHMARK(1000000",
        id="dashdash_leads_into_benchmark",
    ),
    pytest.param(
        "id=1-- LOAD_FILE(0x2f6574632f706173737764)",
        "LOAD_FILE(",
        id="dashdash_leads_into_load_file",
    ),
    pytest.param(
        "id=1/* comment */ ORDER BY 3--",
        "ORDER BY 3",
        id="block_comment_leads_into_order_by",
    ),
]

BENIGN_SPECIAL_CONSTRUCT_PAYLOADS = [
    pytest.param(
        "docker run --rm -it alpine sh",
        ("docker", "run", "alpine", "sh"),
        id="cli_flag_rm_survives",
    ),
    pytest.param(
        "git push --force origin main",
        ("git", "push", "origin", "main"),
        id="cli_flag_force_survives",
    ),
    pytest.param(
        "kubectl delete pod --force --grace-period=0",
        ("kubectl", "delete", "pod"),
        id="cli_multiple_flags_survive",
    ),
    pytest.param(
        "see http://example.com//path for the doc",
        ("http://example.com//path", "doc"),
        id="double_slash_url_survives",
    ),
    pytest.param(
        "a // not a comment b",
        ("not", "a", "comment", "b"),
        id="double_slash_prose_survives",
    ),
    pytest.param(
        "visit http://example.com/page#section for details",
        ("section", "details"),
        id="hash_fragment_survives",
    ),
    pytest.param(
        "trending #python topic today",
        ("python", "topic", "today"),
        id="hash_tag_survives",
    ),
    pytest.param(
        "the file has a /* TODO */ marker inside it",
        ("TODO", "marker", "inside"),
        id="block_comment_prose_survives",
    ),
    pytest.param(
        "int x = 1; /* increment */ x++;",
        ("increment", "x++"),
        id="block_comment_code_snippet_survives",
    ),
]


@pytest.fixture
def preprocessor() -> ContentPreprocessor:
    return ContentPreprocessor()


@pytest.mark.parametrize("payload, tell", ATTACK_AFTER_SPECIAL_CONSTRUCT_PAYLOADS)
def test_attack_after_comment_marker_survives_preprocessing(
    preprocessor: ContentPreprocessor, payload: str, tell: str
) -> None:
    result = preprocessor.preprocess(payload)
    assert tell in result


@pytest.mark.parametrize("payload, tell", ATTACK_AFTER_SPECIAL_CONSTRUCT_PAYLOADS)
def test_attack_after_comment_marker_is_flagged_in_enhanced_mode(
    payload: str, tell: str
) -> None:
    sus_patterns_handler.configure(SyncSecurityConfig())
    result = sus_patterns_handler.detect(
        content=payload, ip_address="203.0.113.9", context="unknown"
    )
    assert result["detection_method"] != "legacy"
    assert result["is_threat"] is True


def test_enhanced_mode_is_genuinely_active_for_corpus_run() -> None:
    sus_patterns_handler.configure(SyncSecurityConfig())
    result = sus_patterns_handler.detect(
        content="id=1-- <script>alert(1)</script>",
        ip_address="203.0.113.9",
        context="unknown",
    )
    assert result["detection_method"] == "enhanced"


@pytest.mark.parametrize("payload, must_contain", BENIGN_SPECIAL_CONSTRUCT_PAYLOADS)
def test_benign_special_construct_usage_is_not_mangled(
    preprocessor: ContentPreprocessor,
    payload: str,
    must_contain: tuple[str, ...],
) -> None:
    result = preprocessor.preprocess(payload)
    lowered = result.lower()
    for word in must_contain:
        assert word.lower() in lowered
