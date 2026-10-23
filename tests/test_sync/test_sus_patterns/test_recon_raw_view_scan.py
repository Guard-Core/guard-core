import json
from collections.abc import Iterator

import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.sync.handlers.suspatterns_handler import sus_patterns_handler
from guard_core.sync.utils import detect_penetration_attempt
from tests.test_sync.conftest import SyncMockGuardRequest

_CONFIG = SyncSecurityConfig()


@pytest.fixture(autouse=True)
def _force_configured_detection_singleton() -> Iterator[None]:
    # The bare-word recon tests pin the legacy unconfigured singleton; these
    # tests exercise the production path, where the preprocessor folds LDAP
    # hex escapes ("\de" -> "Þ") before the pattern tables run and only the
    # signal-preserving raw view still carries the backslashes through.
    sus_patterns_handler.configure(SyncSecurityConfig())
    yield


# Separator-prefixed probes the processed views mangle or gate away: the LDAP
# hex decoder folds "\de" into "Þ", so "\default" arrives as "Þfault" and only
# the raw view still sees the original value.
_BACKSLASH_PROBES = ["\\default", "\\report.asp", "\\README.md"]
_BARE_WORDS = ["default", "SAP", "actuator", "README.md"]


def _body_headers(body: bytes, content_type: str) -> dict[str, str]:
    # The configured pipeline reads the body through the content-length path;
    # without the header the capped body prefix read sees nothing.
    return {
        "content-type": content_type,
        "content-length": str(len(body)),
    }


def _requests(value: str) -> list[SyncMockGuardRequest]:
    json_body = json.dumps({"system": value}).encode()
    form_body = f"system={value}".encode()
    return [
        SyncMockGuardRequest(path="/items", query_params={"system": value}),
        SyncMockGuardRequest(
            path="/items",
            method="POST",
            headers=_body_headers(json_body, "application/json"),
            body_content=json_body,
        ),
        SyncMockGuardRequest(
            path="/items",
            method="POST",
            headers=_body_headers(form_body, "application/x-www-form-urlencoded"),
            body_content=form_body,
        ),
        SyncMockGuardRequest(
            path="/items", query_params={"v": json.dumps({"system": value})}
        ),
    ]


def _embedded_json_body_requests(payload: str) -> list[SyncMockGuardRequest]:
    encoded = payload.encode()
    return [
        SyncMockGuardRequest(path="/items", query_params={"v": payload}),
        SyncMockGuardRequest(
            path="/items",
            method="POST",
            headers=_body_headers(encoded, "application/json"),
            body_content=encoded,
        ),
    ]


def _threat_categories(request: SyncMockGuardRequest) -> list[str]:
    result = detect_penetration_attempt(request, _CONFIG)
    return list(result.threat_categories) if result.is_threat else []


@pytest.mark.parametrize("value", _BACKSLASH_PROBES)
def test_backslash_probe_value_in_query_or_body_is_recon(value: str) -> None:
    for request in _requests(value):
        assert "recon" in _threat_categories(request)


@pytest.mark.parametrize("value", _BARE_WORDS)
def test_bare_word_value_stays_innocent_on_the_raw_view(value: str) -> None:
    for request in _requests(value):
        assert _threat_categories(request) == []


@pytest.mark.parametrize(
    ("payload", "expected"),
    [
        (json.dumps({"url": "\\default"}), "recon"),
        (json.dumps({"url": "default"}), None),
    ],
)
def test_embedded_json_leaf_follows_the_probe_gate(
    payload: str, expected: str | None
) -> None:
    for request in _embedded_json_body_requests(payload):
        categories = _threat_categories(request)
        if expected is None:
            assert categories == []
        else:
            assert expected in categories


def test_backslash_default_as_the_url_path_value_is_recon() -> None:
    # The #116 reference semantics: a backslash-prefixed probe is recon as a
    # URL path value; the raw view must not lose it to the hex decoder.
    result = sus_patterns_handler.detect("\\default", "1.2.3.4", "url_path")
    assert result["is_threat"] is True
    assert any(t.get("category") == "recon" for t in result["threats"])


def test_slash_backslash_url_path_stays_clean_on_both_views() -> None:
    # "/\default" is not a probe shape on any view: the leading slash already
    # satisfies the path prefix, so the row cannot rematch on "\default".
    result = sus_patterns_handler.detect("/\\default", "1.2.3.4", "url_path")
    assert result["is_threat"] is False
    assert result["threats"] == []


def test_hex_decoded_separator_probe_still_detects_once() -> None:
    # "\2fdefault" decodes to "/default" on the processed views; the raw view
    # does not match it, and the decoded sighting stays a single recon hit.
    result = sus_patterns_handler.detect("\\2fdefault", "1.2.3.4", "query_param")
    recon_threats = [t for t in result["threats"] if t.get("category") == "recon"]
    assert len(recon_threats) == 1
    assert recon_threats[0]["match"] == "/default"


def test_row_matching_both_views_is_counted_once() -> None:
    # "\report.asp" survives preprocessing intact: the processed views and the
    # raw view both match it, and the raw-view merge must not double-count it.
    result = sus_patterns_handler.detect("\\report.asp", "1.2.3.4", "query_param")
    recon_threats = [t for t in result["threats"] if t.get("category") == "recon"]
    assert len(recon_threats) == 1
    assert recon_threats[0]["match"] == "\\report.asp"
    assert result["is_threat"] is True


@pytest.mark.parametrize("value", ["/default.asp", "\\default.asp"])
def test_two_row_probe_keeps_the_reference_multiset(value: str) -> None:
    # Both separator forms hit the default-page row and the extension row,
    # exactly the threat multiset the legacy reference path produces.
    result = sus_patterns_handler.detect(value, "1.2.3.4", "query_param")
    recon_threats = [t for t in result["threats"] if t.get("category") == "recon"]
    assert len(recon_threats) == 2
    assert {t["match"] for t in recon_threats} == {value}


def test_hex_folded_run_stays_clean() -> None:
    # "\de\ad\be\ef" folds to non-ASCII text on the processed views and is not
    # a probe on the raw view either; folding must not create a recon hit.
    result = sus_patterns_handler.detect("\\de\\ad\\be\\ef", "1.2.3.4", "query_param")
    assert result["is_threat"] is False
    assert result["threats"] == []
