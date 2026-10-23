import json
import logging
from urllib.parse import quote

import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.sync.detection_result import DetectionResult
from guard_core.sync.handlers.suspatterns_handler import sus_patterns_handler
from guard_core.sync.utils import detect_penetration_attempt
from tests.test_sync.conftest import SyncMockGuardRequest

ATTACK = "1' UNION SELECT password FROM users--"
_JUNK = {f"k{i}": "v" for i in range(300)}
_BOUNDARY = "guardboundary"


@pytest.fixture(autouse=True)
def _force_enhanced_detection_singleton() -> None:
    sus_patterns_handler.configure(SyncSecurityConfig())


def _query(
    params: dict[str, str], headers: dict[str, str] | None = None
) -> SyncMockGuardRequest:
    return SyncMockGuardRequest(path="/api", query_params=params, headers=headers)


def _post(
    body: bytes,
    content_type: str,
    path: str = "/api",
    query_params: dict[str, str] | None = None,
    headers: dict[str, str] | None = None,
) -> SyncMockGuardRequest:
    return SyncMockGuardRequest(
        path=path,
        method="POST",
        query_params=query_params,
        headers={
            **(headers or {}),
            "content-type": content_type,
            "content-length": str(len(body)),
        },
        body_content=body,
    )


def _threat(
    request: SyncMockGuardRequest, config: SyncSecurityConfig | None = None
) -> DetectionResult:
    return detect_penetration_attempt(request, config or SyncSecurityConfig())


def test_attack_in_the_last_of_300_junk_query_params_is_flagged() -> None:
    result = _threat(_query(dict(_JUNK, zz=ATTACK)))
    assert result.is_threat is True
    assert result.trigger_info.startswith("Remaining query params")


def test_attack_in_the_first_query_value_after_the_value_cap_is_flagged() -> None:
    config = SyncSecurityConfig(detection_max_scan_values=20)
    params = {f"p{i}": "v" for i in range(10)}
    params["first_after_cut"] = ATTACK
    params.update({f"q{i}": "v" for i in range(50)})
    assert (_threat(_query(params), config)).is_threat is True


def test_attack_in_the_first_value_after_the_char_cap_is_flagged() -> None:
    config = SyncSecurityConfig(detection_max_scan_chars=1024)
    params = {"filler": "a" * 2000, "after_cut": ATTACK}
    assert (_threat(_query(params), config)).is_threat is True


def test_attack_in_a_value_that_crosses_the_char_cap_is_flagged() -> None:
    config = SyncSecurityConfig(detection_max_scan_chars=1024)
    params = {"filler": "a" * 1000, "crosses": ("a" * 100) + " " + ATTACK}
    assert (_threat(_query(params), config)).is_threat is True


def test_percent_encoded_attack_after_the_cut_is_flagged() -> None:
    value = quote(ATTACK, safe="")
    assert (_threat(_query(dict(_JUNK, zz=value)))).is_threat is True


def test_double_encoded_attack_after_the_cut_is_flagged() -> None:
    value = quote(quote(ATTACK, safe=""), safe="")
    assert (_threat(_query(dict(_JUNK, zz=value)))).is_threat is True


def test_repeated_query_attack_ordered_last_by_the_engine_is_flagged() -> None:
    junk = "&".join(f"k{i}=v" for i in range(300))
    path = f"/api?q={quote(ATTACK)}&q=hello&{junk}"
    request = SyncMockGuardRequest(path=path, query_params={"q": "hello", **_JUNK})
    assert (_threat(request)).is_threat is True


def test_traversal_in_the_url_path_is_flagged_after_300_junk_params() -> None:
    request = SyncMockGuardRequest(
        path="/files/../../../../etc/passwd", query_params=dict(_JUNK)
    )
    assert (_threat(request)).is_threat is True


def test_header_attack_is_flagged_after_300_junk_query_params() -> None:
    request = _query(dict(_JUNK), headers={"x-note": ATTACK})
    result = _threat(request)
    assert result.is_threat is True
    assert result.trigger_info.startswith("Remaining headers")


def test_json_body_attack_is_flagged_after_300_junk_query_params() -> None:
    body = json.dumps({"q": ATTACK}).encode()
    request = _post(body, "application/json", query_params=dict(_JUNK))
    result = _threat(request)
    assert result.is_threat is True
    assert result.trigger_info.startswith("Remaining request body")


def test_text_body_attack_is_flagged_after_300_junk_query_params() -> None:
    request = _post(ATTACK.encode(), "text/plain", query_params=dict(_JUNK))
    assert (_threat(request)).is_threat is True


def test_attack_in_the_last_of_600_json_fields_is_flagged() -> None:
    body = json.dumps({**{f"f{i}": "v" for i in range(600)}, "last": ATTACK}).encode()
    assert (_threat(_post(body, "application/json"))).is_threat is True


def test_attack_in_the_last_json_record_after_the_value_cap_is_flagged() -> None:
    records = [{f"f{j}": "pending" for j in range(5)} for _ in range(100)]
    records[-1]["f4"] = ATTACK
    body = json.dumps({"items": records}).encode()
    assert (_threat(_post(body, "application/json"))).is_threat is True


def test_unicode_escaped_json_attack_after_the_cut_is_flagged() -> None:
    escaped = "".join(f"\\u{ord(char):04x}" for char in ATTACK)
    junk = ", ".join(f'"f{i}": "v"' for i in range(600))
    body = f'{{{junk}, "last": "{escaped}"}}'.encode()
    assert (_threat(_post(body, "application/json"))).is_threat is True


def test_json_backslash_traversal_after_the_cut_is_flagged() -> None:
    junk = {f"f{i}": "v" for i in range(600)}
    body = json.dumps({**junk, "path": "..\\..\\..\\windows\\win.ini"}).encode()
    assert (_threat(_post(body, "application/json"))).is_threat is True


def test_json_attack_with_double_quotes_after_the_cut_is_flagged() -> None:
    junk = {f"f{i}": "v" for i in range(600)}
    body = json.dumps({**junk, "q": '\' OR "x"="x'}).encode()
    assert (_threat(_post(body, "application/json"))).is_threat is True


def test_json_key_attack_after_the_cut_is_flagged() -> None:
    junk = {f"f{i}": "v" for i in range(600)}
    body = json.dumps({**junk, ATTACK: "v"}).encode()
    assert (_threat(_post(body, "application/json"))).is_threat is True


def test_json_mongo_operator_key_after_the_cut_is_flagged() -> None:
    junk = {f"f{i}": "v" for i in range(600)}
    body = json.dumps({**junk, "user": {"$ne": None}}).encode()
    assert (_threat(_post(body, "application/json"))).is_threat is True


def test_json_attack_below_the_depth_cap_after_the_cut_is_flagged() -> None:
    config = SyncSecurityConfig(detection_max_json_depth=2)
    junk = {f"f{i}": "v" for i in range(600)}
    body = json.dumps({**junk, "deep": {"deeper": {"q": ATTACK}}}).encode()
    assert (_threat(_post(body, "application/json"), config)).is_threat is True


def test_form_attack_after_the_cut_is_flagged() -> None:
    fields = "&".join(f"f{i}=v" for i in range(600))
    body = f"{fields}&last={quote(ATTACK)}".encode()
    request = _post(body, "application/x-www-form-urlencoded")
    result = _threat(request)
    assert result.is_threat is True
    assert result.trigger_info.startswith("Remaining form fields")


def _multipart(fields: list[tuple[str, str]]) -> bytes:
    parts = "".join(
        f"--{_BOUNDARY}\r\n"
        f'Content-Disposition: form-data; name="{name}"\r\n\r\n{value}\r\n'
        for name, value in fields
    )
    return f"{parts}--{_BOUNDARY}--\r\n".encode()


def test_multipart_attack_after_the_cut_is_flagged() -> None:
    fields = [(f"f{i}", "v") for i in range(400)] + [("last", ATTACK)]
    content_type = f"multipart/form-data; boundary={_BOUNDARY}"
    result = _threat(_post(_multipart(fields), content_type))
    assert result.is_threat is True
    assert result.trigger_info.startswith("Remaining multipart parts")


def test_benign_300_junk_query_params_are_clean() -> None:
    assert (_threat(_query(dict(_JUNK)))).is_threat is False


def test_benign_query_variant_set_after_the_cut_is_clean() -> None:
    variants = {
        "limit": "5",
        "filter": "foo|bar",
        "filterout": "广告.*推广",
        "filter_title": "(?i)select.*from",
        "mode": "fulltext",
        "brief": "100",
        "key": "abc123",
        "code": "0123456789abcdef0123456789abcdef",
    }
    assert (_threat(_query({**_JUNK, **variants}))).is_threat is False


def test_benign_cross_value_words_after_the_cut_are_clean() -> None:
    params = {
        **_JUNK,
        "a": "select",
        "b": "from",
        "c": "union",
        "d": "select",
        "e": "'",
        "f": "or",
        "g": "1",
        "h": "=",
        "i": "1",
    }
    assert (_threat(_query(params))).is_threat is False


def test_benign_apostrophe_prose_after_the_cut_is_clean() -> None:
    prose = {
        "p1": "O'Brien",
        "p2": "don't or won't",
        "p3": "it's 'x' = 'y' in the spec",
        "p4": "rock 'n' roll or jazz",
    }
    assert (_threat(_query({**_JUNK, **prose}))).is_threat is False


def test_benign_header_block_after_the_cut_is_clean() -> None:
    headers = {
        "host": "app.example.com",
        "user-agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit",
        "accept": "application/json, text/plain, */*",
        "accept-language": "en-US,en;q=0.9,it;q=0.8",
        "referer": "https://app.example.com/orders?status=open",
        "cookie": "session=abc; theme=dark; lang=en",
    }
    assert (_threat(_query(dict(_JUNK), headers=headers))).is_threat is False


def test_benign_json_body_of_600_fields_is_clean() -> None:
    records = [{f"f{j}": "pending order" for j in range(5)} for _ in range(120)]
    body = json.dumps({"items": records}).encode()
    assert (_threat(_post(body, "application/json"))).is_threat is False


def test_benign_text_body_after_a_spent_budget_is_clean() -> None:
    body = b"The quick brown fox jumps over the lazy dog. " * 50
    request = _post(body, "text/plain", query_params=dict(_JUNK))
    assert (_threat(request)).is_threat is False


def test_a_param_excluded_from_a_category_stays_excluded_after_the_cut() -> None:
    config = SyncSecurityConfig(excluded_detection_params={"note": ["sqli"]})
    params = {**_JUNK, "note": ATTACK}
    assert (_threat(_query(params), config)).is_threat is False


def test_an_excluded_header_keeps_its_category_exclusion_after_the_cut() -> None:
    headers = {"host": "localhost:8000", "referer": "http://localhost:8000/orders"}
    assert (_threat(_query({}, headers=headers))).is_threat is False
    assert (_threat(_query(dict(_JUNK), headers=headers))).is_threat is False


def test_a_public_host_keeps_the_referer_ssrf_flag_after_the_cut() -> None:
    headers = {
        "host": "app.example.com",
        "referer": "http://169.254.169.254/latest/meta-data/",
    }
    assert (_threat(_query({}, headers=headers))).is_threat is True
    assert (_threat(_query(dict(_JUNK), headers=headers))).is_threat is True


def test_the_walk_hit_wins_over_the_remainder() -> None:
    params = {"first": ATTACK, **_JUNK, "last": ATTACK}
    result = _threat(_query(params))
    assert result.is_threat is True
    assert "Remaining" not in result.trigger_info


def test_the_budget_warning_is_logged_once(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.INFO, logger="guard_core"):
        _threat(_query(dict(_JUNK)))
    assert caplog.text.count("detection_max_scan_values (512) reached") == 1
    assert "Remaining query params skipped past the scan budget" in caplog.text


def test_a_sensitive_value_after_the_cut_is_never_logged(
    caplog: pytest.LogCaptureFixture,
) -> None:
    secret = "s3cr3tvalue"
    params = {**_JUNK, "password": secret, "zz": ATTACK}
    with caplog.at_level(logging.INFO, logger="guard_core"):
        result = _threat(_query(params))
    assert result.is_threat is True
    assert secret not in caplog.text
    assert secret not in result.trigger_info


def test_a_sensitive_header_after_the_cut_is_never_logged(
    caplog: pytest.LogCaptureFixture,
) -> None:
    secret = "Bearer s3cr3ttokenvalue"
    headers = {"authorization": secret, "x-note": ATTACK}
    with caplog.at_level(logging.INFO, logger="guard_core"):
        result = _threat(_query(dict(_JUNK), headers=headers))
    assert result.is_threat is True
    assert "s3cr3ttokenvalue" not in caplog.text


def test_a_sensitive_json_leaf_after_the_cut_is_never_logged(
    caplog: pytest.LogCaptureFixture,
) -> None:
    secret = "hunter2hunter2"
    junk = {f"f{i}": "v" for i in range(600)}
    body = json.dumps({**junk, "password": secret, "q": ATTACK}).encode()
    with caplog.at_level(logging.INFO, logger="guard_core"):
        result = _threat(_post(body, "application/json"))
    assert result.is_threat is True
    assert secret not in caplog.text


def test_embedded_json_values_past_the_cut_are_not_rescanned_as_a_block() -> None:
    embedded = json.dumps({f"k{i}": "v" for i in range(40)})
    params = {f"p{i}": embedded for i in range(30)}
    assert (_threat(_query(params))).is_threat is False


def test_the_remainder_preview_stops_once_it_has_enough_text() -> None:
    from guard_core.sync._utils.scan_remainder import _remainder_preview, _Skipped

    pieces = [_Skipped("x" * 600, False, ("x" * 600,)) for _ in range(1000)]
    shown = _remainder_preview(pieces, "&", lambda piece: None).resolve()
    assert shown is not None
    assert 1200 <= len(shown) <= 1300


def test_a_relative_path_value_after_the_cut_is_not_a_traversal() -> None:
    params = {**_JUNK, "next": "../relative", "also": "..\\other"}
    assert (_threat(_query(params))).is_threat is False


def test_a_value_with_ampersand_and_percent_after_the_cut_is_clean() -> None:
    params = {**_JUNK, "a": "fish & chips 100%", "b": "x=1&y=2"}
    assert (_threat(_query(params))).is_threat is False


def test_a_unit_longer_than_the_unit_pass_limit_is_covered_by_the_block() -> None:
    params = {**_JUNK, "long": "a " * 700, "zz": ATTACK}
    result = _threat(_query(params))
    assert result.is_threat is True


def test_a_whole_base64_value_after_the_cut_is_decoded_like_in_the_walk() -> None:
    encoded = "U0VMRUNUIHBhc3N3b3JkIEZST00gdXNlcnMgV0hFUkUgaWQ9MQ=="
    assert (_threat(_query({**_JUNK, "b": encoded}))).is_threat is True


def test_the_unit_pass_stops_at_its_scan_limit() -> None:
    params = {f"p{i}": f"value%41{i}" for i in range(700)}
    result = _threat(_query(params))
    assert result.is_threat is False
