import json
import logging
from typing import Any

import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.sync.handlers import ipban_handler
from tests.test_sync.test_core.conftest import build_route_pipeline, send_request

BOT_IP = "203.0.113.7"
FORM = {"content-type": "application/x-www-form-urlencoded"}
JSON = {"content-type": "application/json"}
MULTIPART = {"content-type": "multipart/form-data; boundary=B"}


def _multipart(name: str, value: str, extra: str = "") -> bytes:
    return (
        f'--B\r\nContent-Disposition: form-data; name="{name}"{extra}\r\n\r\n'
        f"{value}\r\n--B--\r\n"
    ).encode()


def _config(**overrides: Any) -> SyncSecurityConfig:
    settings: dict[str, Any] = {
        "enable_redis": False,
        "enable_penetration_detection": False,
        "enable_rate_limiting": False,
    }
    settings.update(overrides)
    return SyncSecurityConfig(**settings)


def _hit(
    method: str,
    headers: dict[str, str],
    body: bytes,
    path: str = "/x",
    config: SyncSecurityConfig | None = None,
    ip: str = BOT_IP,
) -> Any:
    pipeline, _, route_id = build_route_pipeline(
        config or _config(), lambda d: d.honeypot_detection(["hp"])
    )
    headers = {**headers, "content-length": str(len(body))}
    return send_request(
        pipeline, route_id, ip=ip, path=path, method=method, headers=headers, body=body
    )


TRAPPED = [
    pytest.param("POST", FORM, b"hp=bot&a=1", "/x", id="control-form"),
    pytest.param("POST", JSON, b'{"hp":"bot"}', "/x", id="control-json"),
    pytest.param("DELETE", FORM, b"hp=bot", "/x", id="delete-form-body"),
    pytest.param("PUT", JSON, b'{"hp":"bot"}', "/x", id="put-json"),
    pytest.param("GET", {}, b"", "/x?hp=bot", id="get-query-string"),
    pytest.param("POST", FORM, b"a=1", "/x?a=1&hp=bot", id="post-query-string"),
    pytest.param("DELETE", {}, b"", "/x?HP=bot", id="query-string-field-case"),
    pytest.param("POST", MULTIPART, _multipart("hp", "bot"), "/x", id="multipart"),
    pytest.param(
        "POST",
        {"content-type": 'Multipart/Form-Data; boundary="B"'},
        _multipart("hp", "bot"),
        "/x",
        id="multipart-media-type-case",
    ),
    pytest.param(
        "POST", MULTIPART, _multipart("Hp", "bot"), "/x", id="multipart-field-case"
    ),
    pytest.param(
        "POST",
        MULTIPART,
        _multipart("hp", "bot", '; filename="a.txt"'),
        "/x",
        id="multipart-trap-as-file",
    ),
    pytest.param("POST", FORM, b"Hp=bot", "/x", id="form-field-case"),
    pytest.param("POST", JSON, b'{"HP":"bot"}', "/x", id="json-field-case"),
    pytest.param(
        "POST",
        {"content-type": "Application/JSON"},
        b'{"hp":"bot"}',
        "/x",
        id="json-media-type-case",
    ),
    pytest.param(
        "POST",
        {"content-type": "APPLICATION/X-WWW-FORM-URLENCODED"},
        b"hp=bot",
        "/x",
        id="form-media-type-case",
    ),
    pytest.param(
        "POST",
        {"content-type": " application/json ; charset=utf-8"},
        b'{"hp":"bot"}',
        "/x",
        id="json-media-type-parameters-and-spaces",
    ),
    pytest.param("POST", JSON, b'[{"hp":"bot"}]', "/x", id="json-array-of-objects"),
    pytest.param("POST", JSON, b'{"user":{"hp":"bot"}}', "/x", id="json-nested-object"),
    pytest.param(
        "POST",
        JSON,
        b'{"a":[1,[{"deep":{"hp":"bot"}}]]}',
        "/x",
        id="json-deeply-nested",
    ),
    pytest.param(
        "POST", JSON, b'{"hp":"bot","hp":""}', "/x", id="json-duplicate-key-last-empty"
    ),
    pytest.param("POST", JSON, b'{"hp":0}', "/x", id="json-zero"),
    pytest.param("POST", JSON, b'{"hp":false}', "/x", id="json-false"),
    pytest.param("POST", JSON, b'{"hp":[]}', "/x", id="json-empty-array"),
    pytest.param("POST", JSON, b'{"hp":{"a":1}}', "/x", id="json-object-value"),
    pytest.param("POST", JSON, b'{"hp":["bot"]}', "/x", id="json-array-value"),
    pytest.param(
        "POST",
        {"content-type": "application/json; charset=utf-16"},
        '{"hp":"bot"}'.encode("utf-16"),
        "/x",
        id="json-utf-16",
    ),
    pytest.param("POST", JSON, '{"hp":"bot"}'.encode("utf-32"), "/x", id="json-utf-32"),
    pytest.param("POST", JSON, b'\xef\xbb\xbf{"hp":"bot"}', "/x", id="json-utf-8-bom"),
    pytest.param("POST", FORM, b"hp=&hp=bot", "/x", id="form-repeated-blank-first"),
    pytest.param("POST", FORM, b"hp=bot&hp=", "/x", id="form-repeated-blank-last"),
    pytest.param("POST", FORM, b"hp=%20bot", "/x", id="form-padded-value"),
]


@pytest.mark.parametrize(("method", "headers", "body", "path"), TRAPPED)
def test_filled_trap_is_caught_and_bans_the_client(
    method: str, headers: dict[str, str], body: bytes, path: str
) -> None:
    response = _hit(method, headers, body, path)

    assert response is not None
    assert response.status_code == 403
    assert ipban_handler.ip_ban_manager.is_ip_banned(BOT_IP)


CLEAN = [
    pytest.param("POST", FORM, b"hp=&a=1", "/x", id="form-empty-value"),
    pytest.param("POST", FORM, b"hp=%20%20", "/x", id="form-whitespace-value"),
    pytest.param("POST", FORM, b"a=1", "/x", id="form-absent"),
    pytest.param("POST", JSON, b'{"hp":null}', "/x", id="json-null"),
    pytest.param("POST", JSON, b'{"hp":""}', "/x", id="json-empty-string"),
    pytest.param("POST", JSON, b'{"hp":"   "}', "/x", id="json-whitespace"),
    pytest.param(
        "POST", JSON, b'{"hp":"","hp":null}', "/x", id="json-all-duplicates-empty"
    ),
    pytest.param(
        "POST", JSON, b'{"a":{"hp":""},"b":[{"hp":null}]}', "/x", id="json-nested-empty"
    ),
    pytest.param("POST", JSON, b'{"hpx":"v","a":"hp"}', "/x", id="json-other-fields"),
    pytest.param("POST", JSON, b"not json", "/x", id="json-unparsable"),
    pytest.param("POST", JSON, b"123", "/x", id="json-scalar"),
    pytest.param("POST", MULTIPART, _multipart("hp", ""), "/x", id="multipart-empty"),
    pytest.param(
        "POST",
        {"content-type": "multipart/form-data"},
        b"hp=bot",
        "/x",
        id="multipart-without-boundary",
    ),
    pytest.param(
        "POST",
        MULTIPART,
        b"--B\r\nContent-Type: text/plain\r\n\r\nbot\r\n--B--\r\n",
        "/x",
        id="multipart-part-without-a-name",
    ),
    pytest.param(
        "POST", MULTIPART, _multipart("other", "bot"), "/x", id="multipart-other"
    ),
    pytest.param(
        "POST", {"content-type": "text/plain"}, b"hp=bot", "/x", id="text-plain"
    ),
    pytest.param("GET", {}, b"", "/x", id="get-plain"),
    pytest.param("GET", {}, b"", "/x?hp=", id="get-empty-query-value"),
    pytest.param("GET", {}, b"", "/x?a=1", id="get-other-query"),
]


@pytest.mark.parametrize(("method", "headers", "body", "path"), CLEAN)
def test_unfilled_trap_passes_without_counting(
    method: str, headers: dict[str, str], body: bytes, path: str
) -> None:
    pipeline, middleware, route_id = build_route_pipeline(
        _config(), lambda d: d.honeypot_detection(["hp"])
    )
    full_headers = {**headers, "content-length": str(len(body))}

    response = send_request(
        pipeline,
        route_id,
        ip=BOT_IP,
        path=path,
        method=method,
        headers=full_headers,
        body=body,
    )

    assert response is None
    assert middleware.suspicious_request_counts == {}


def test_every_configured_trap_name_matches_case_insensitively() -> None:
    pipeline, _, route_id = build_route_pipeline(
        _config(), lambda d: d.honeypot_detection(["Website", "URL"])
    )

    for body in (b"website=x", b"WEBSITE=x", b"url=x"):
        response = send_request(
            pipeline,
            route_id,
            ip=BOT_IP,
            method="POST",
            headers={**FORM, "content-length": str(len(body))},
            body=body,
        )
        assert response is not None
        assert response.status_code == 403
        ipban_handler.ip_ban_manager.unban_ip(BOT_IP)


def test_json_with_the_trap_before_trailing_garbage_is_still_caught() -> None:
    response = _hit("POST", JSON, b'{"hp":"bot"} trailing')

    assert response is not None
    assert response.status_code == 403


def test_invalid_utf8_around_a_filled_trap_is_still_caught() -> None:
    response = _hit("POST", JSON, b'{"hp":"bait\xff"}')

    assert response is not None
    assert response.status_code == 403


def test_nesting_too_deep_to_parse_is_warned_not_silently_skipped(
    caplog: pytest.LogCaptureFixture,
) -> None:
    body = b"[" * 50_000 + b'{"hp":"bot"}' + b"]" * 50_000

    with caplog.at_level(logging.WARNING):
        response = _hit("POST", JSON, body, config=_config())

    assert response is None
    assert any("nested too deeply" in r.getMessage() for r in caplog.records)


def test_a_trap_filled_before_the_too_deep_part_is_still_caught() -> None:
    body = b'[{"hp":"bot"},' + b"[" * 50_000 + b"]" * 50_000 + b"]"

    response = _hit("POST", JSON, body, config=_config())

    assert response is not None
    assert response.status_code == 403


def test_nesting_at_the_same_depth_on_every_interpreter_is_parsed() -> None:
    body = b"[" * 400 + b'{"hp":"bot"}' + b"]" * 400

    response = _hit("POST", JSON, body, config=_config())

    assert response is not None
    assert response.status_code == 403


def _warnings(caplog: pytest.LogCaptureFixture) -> list[str]:
    return [
        r.getMessage()
        for r in caplog.records
        if r.levelno == logging.WARNING and "honeypot_detection" in r.getMessage()
    ]


def test_body_over_the_inspection_cap_is_warned_and_not_inspected(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = _config(detection_max_body_inspect_bytes=1024)
    body = json.dumps({"pad": "a" * 4096, "hp": "bot"}).encode()

    with caplog.at_level(logging.WARNING):
        response = _hit("POST", JSON, body, config=config)

    assert response is None
    warnings_logged = _warnings(caplog)
    assert len(warnings_logged) == 1
    assert "detection_max_body_inspect_bytes (1024)" in warnings_logged[0]
    assert BOT_IP not in " ".join(warnings_logged)


def test_body_within_the_cap_is_inspected_without_a_warning(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = _config(detection_max_body_inspect_bytes=1024)

    with caplog.at_level(logging.WARNING):
        response = _hit("POST", JSON, b'{"hp":"bot"}', config=config)

    assert response is not None
    assert _warnings(caplog) == []


def test_bodyless_get_never_warns(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.WARNING):
        _hit("GET", {}, b"")

    assert _warnings(caplog) == []
