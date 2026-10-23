import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.sync._utils.penetration_detection import detect_penetration_attempt
from tests.test_sync.conftest import SyncMockGuardRequest

_CONFIG = SyncSecurityConfig()


def _header_request(value: str) -> SyncMockGuardRequest:
    return SyncMockGuardRequest(headers={"X-Custom": value})


def _path_request(path: str) -> SyncMockGuardRequest:
    return SyncMockGuardRequest(path=path)


def _query_request(value: str) -> SyncMockGuardRequest:
    return SyncMockGuardRequest(query_params={"q": value})


_NEWLY_ENABLED_PAIR_MALICIOUS_REQUESTS = [
    pytest.param(
        "code_injection",
        _header_request('System.Diagnostics.Process.Start("cmd.exe","/c whoami")'),
        id="code_injection_header",
    ),
    pytest.param("ldap", _header_request("(|(uid=*)(cn=*))"), id="ldap_header"),
    pytest.param("nosql", _header_request('{"$gt":""}'), id="nosql_header"),
    pytest.param(
        "proto_pollution",
        _header_request('{"__proto__":{"isAdmin":true}}'),
        id="proto_pollution_header",
    ),
    pytest.param(
        "template",
        _header_request("{{ config.__class__.__init__.__globals__.os.system }}"),
        id="template_header",
    ),
    pytest.param(
        "dir_traversal",
        _header_request("../../../../etc/passwd"),
        id="dir_traversal_header",
    ),
    pytest.param(
        "file_inclusion",
        _header_request("php://filter/convert.base64-encode/resource=index.php"),
        id="file_inclusion_header",
    ),
    pytest.param(
        "path_traversal",
        _header_request("%2e%2e/%2e%2e/etc/passwd"),
        id="path_traversal_header",
    ),
    pytest.param(
        "deserialization",
        _path_request('/O:8:"stdClass":1:{s:4:"prop";s:9:"pwnedval1";}'),
        id="deserialization_url_path",
    ),
    pytest.param(
        "xml",
        _path_request('/<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'),
        id="xml_url_path",
    ),
    pytest.param(
        "http_split",
        _path_request("/search=x\r\nLocation: http://evil.example"),
        id="http_split_url_path",
    ),
    pytest.param(
        "code_injection",
        _path_request('/System.Diagnostics.Process.Start("cmd.exe","/c whoami")'),
        id="code_injection_url_path",
    ),
    pytest.param("ldap", _path_request("/(|(uid=*)(cn=*))"), id="ldap_url_path"),
    pytest.param("nosql", _path_request('/{"$gt":""}'), id="nosql_url_path"),
    pytest.param(
        "proto_pollution",
        _path_request('/{"__proto__":{"isAdmin":true}}'),
        id="proto_pollution_url_path",
    ),
    pytest.param(
        "cms_probing", _query_request("/wp-admin/"), id="cms_probing_query_param"
    ),
    pytest.param("recon", _query_request("/actuator/health"), id="recon_query_param"),
    pytest.param(
        "sensitive_file",
        _query_request("/.env"),
        id="sensitive_file_query_param",
    ),
    pytest.param(
        "file_upload",
        _query_request('filename="shell.php"'),
        id="file_upload_query_param",
    ),
]


@pytest.mark.parametrize(
    "category, request_obj", _NEWLY_ENABLED_PAIR_MALICIOUS_REQUESTS
)
def test_newly_enabled_pair_detects_attack_on_the_wire(
    category: str, request_obj: SyncMockGuardRequest
) -> None:
    result = detect_penetration_attempt(request_obj, _CONFIG)
    assert result.is_threat is True
    assert category in result.threat_categories


_NEWLY_ENABLED_PAIR_BENIGN_REQUESTS = [
    pytest.param(
        "code_injection",
        _header_request("The deployment runbook explains how the service starts up."),
        id="code_injection_header",
    ),
    pytest.param(
        "ldap",
        _header_request("cn=john.doe,ou=users,dc=example,dc=com"),
        id="ldap_header",
    ),
    pytest.param(
        "nosql", _header_request('{"name": "Alice", "age": 30}'), id="nosql_header"
    ),
    pytest.param(
        "proto_pollution",
        _header_request('{"user": {"name": "Alice"}}'),
        id="proto_pollution_header",
    ),
    pytest.param(
        "template",
        _header_request("The report covers Q3 revenue and headcount."),
        id="template_header",
    ),
    pytest.param(
        "dir_traversal",
        _header_request("reports/2024/summary.pdf"),
        id="dir_traversal_header",
    ),
    pytest.param(
        "file_inclusion",
        _header_request("the user manual is at /docs/manual.pdf"),
        id="file_inclusion_header",
    ),
    pytest.param(
        "path_traversal", _header_request("images/logo.png"), id="path_traversal_header"
    ),
    pytest.param(
        "deserialization",
        _path_request("/users/alice/profile"),
        id="deserialization_url_path",
    ),
    pytest.param("xml", _path_request("/catalog/items"), id="xml_url_path"),
    pytest.param(
        "http_split", _path_request("/search/results"), id="http_split_url_path"
    ),
    pytest.param(
        "code_injection", _path_request("/status/health"), id="code_injection_url_path"
    ),
    pytest.param("ldap", _path_request("/users/alice"), id="ldap_url_path"),
    pytest.param("nosql", _path_request("/products/42"), id="nosql_url_path"),
    pytest.param(
        "proto_pollution",
        _path_request("/settings/theme"),
        id="proto_pollution_url_path",
    ),
    pytest.param(
        "cms_probing", _query_request("welcome-post"), id="cms_probing_query_param"
    ),
    pytest.param("recon", _query_request("dashboard"), id="recon_query_param"),
    pytest.param(
        "sensitive_file", _query_request("report.pdf"), id="sensitive_file_query_param"
    ),
    pytest.param(
        "file_upload", _query_request("photo.jpg"), id="file_upload_query_param"
    ),
]


@pytest.mark.parametrize("category, request_obj", _NEWLY_ENABLED_PAIR_BENIGN_REQUESTS)
def test_newly_enabled_pair_benign_control_stays_clean(
    category: str, request_obj: SyncMockGuardRequest
) -> None:
    result = detect_penetration_attempt(request_obj, _CONFIG)
    assert category not in result.threat_categories
