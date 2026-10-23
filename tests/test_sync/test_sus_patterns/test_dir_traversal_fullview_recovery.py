import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.sync.handlers.suspatterns_handler import sus_patterns_handler
from guard_core.sync.utils import detect_penetration_attempt
from tests.test_sync.conftest import SyncMockGuardRequest

_CONFIG = SyncSecurityConfig()


@pytest.fixture(autouse=True)
def _force_enhanced_detection_singleton() -> None:
    sus_patterns_handler.configure(SyncSecurityConfig())


def _text_body_request(body: str) -> SyncMockGuardRequest:
    encoded = body.encode()
    headers = {
        "content-length": str(len(encoded)),
        "content-type": "text/plain",
    }
    return SyncMockGuardRequest(body_content=encoded, headers=headers)


def _assert_body_fires_dir_traversal(body: str) -> None:
    request = _text_body_request(body)
    result = detect_penetration_attempt(request, _CONFIG)
    assert result.is_threat is True
    assert result.threat_categories == ["dir_traversal"]


def _assert_body_does_not_fire(body: str) -> None:
    request = _text_body_request(body)
    result = detect_penetration_attempt(request, _CONFIG)
    assert result.is_threat is False


def test_etc_passwd_url_encoded_body_fires_dir_traversal() -> None:
    _assert_body_fires_dir_traversal("%2fetc%2fpasswd")


def test_windows_ini_url_encoded_body_fires_dir_traversal() -> None:
    _assert_body_fires_dir_traversal("%2fboot.ini")


def test_proc_environ_url_encoded_body_fires_dir_traversal() -> None:
    _assert_body_fires_dir_traversal("%2fproc%2fself%2fenviron")


def test_var_log_url_encoded_body_fires_dir_traversal() -> None:
    _assert_body_fires_dir_traversal("%2fvar%2flog%2fauth.log")


def test_etc_passwd_single_line_body_still_fires() -> None:
    _assert_body_fires_dir_traversal("/etc/passwd")


def test_etc_passwd_inline_single_line_body_still_fires() -> None:
    _assert_body_fires_dir_traversal("foo=bar /etc/passwd")


def test_windows_ini_single_line_body_still_fires() -> None:
    _assert_body_fires_dir_traversal("boot.ini")


def test_proc_environ_single_line_body_still_fires() -> None:
    _assert_body_fires_dir_traversal("proc/self/environ")


def test_var_log_single_line_body_still_fires() -> None:
    _assert_body_fires_dir_traversal("var/log/auth.log")


def test_etc_passwd_multiline_body_not_detected() -> None:
    _assert_body_does_not_fire("foo=bar\n/etc/passwd")


def test_windows_ini_multiline_body_not_detected() -> None:
    _assert_body_does_not_fire("foo=bar\nboot.ini")


def test_proc_environ_multiline_body_not_detected() -> None:
    _assert_body_does_not_fire("foo=bar\nproc/self/environ")


def test_var_log_multiline_body_not_detected() -> None:
    _assert_body_does_not_fire("foo=bar\nvar/log/auth.log")


def test_etc_passwd_incident_note_prose_not_detected() -> None:
    _assert_body_does_not_fire(
        "Incident note: server rebooted at 03:00.\n"
        "Verified /etc/passwd had no unauthorized accounts"
    )


def test_windows_ini_setup_log_prose_not_detected() -> None:
    _assert_body_does_not_fire(
        "Setup log step 3 complete.\nRead boot.ini to confirm boot loader options"
    )


def test_proc_environ_debug_trace_prose_not_detected() -> None:
    _assert_body_does_not_fire(
        "Debug trace captured connection handshake.\n"
        "Inspecting proc/self/environ for env var leakage check"
    )


def test_var_log_ops_report_prose_not_detected() -> None:
    _assert_body_does_not_fire(
        "Ops report for nightly maintenance window.\n"
        "Reviewed var/log/auth.log for ssh failures"
    )


def test_benign_body_not_detected() -> None:
    _assert_body_does_not_fire("hello world")


def test_etc_passwd_form_urlencoded_trailing_field_fires() -> None:
    _assert_body_fires_dir_traversal("p=/etc/passwd&bar=1")


def test_etc_passwd_path_info_matrix_trailing_fires() -> None:
    _assert_body_fires_dir_traversal("/etc/passwd;x=1")


def test_etc_passwd_json_trailing_field_fires() -> None:
    _assert_body_fires_dir_traversal('{"p":"/etc/passwd&bar=1"}')


def test_etc_passwd_xml_trailing_sibling_fires() -> None:
    _assert_body_fires_dir_traversal("<doc><p>/etc/passwd</p><x>1</x></doc>")


def test_etc_passwd_url_encoded_trailing_field_fires() -> None:
    _assert_body_fires_dir_traversal("%2fetc%2fpasswd&bar=1")


def test_proc_environ_form_urlencoded_trailing_field_fires() -> None:
    _assert_body_fires_dir_traversal("p=/proc/self/environ&x=1")


def test_windows_ini_form_urlencoded_trailing_field_fires() -> None:
    _assert_body_fires_dir_traversal("p=boot.ini&x=1")


def test_var_log_form_urlencoded_trailing_field_fires() -> None:
    _assert_body_fires_dir_traversal("p=var/log/auth.log&x=1")


def test_etc_passwd_prose_with_trailing_words_not_detected() -> None:
    _assert_body_does_not_fire("the file was /etc/passwd and more")


def test_enhanced_mode_is_active_for_dir_traversal_bodies() -> None:
    result = sus_patterns_handler.detect(
        content="%2fetc%2fpasswd",
        ip_address="203.0.113.9",
        context="request_body",
    )
    assert result["detection_method"] == "enhanced"
    assert result["is_threat"] is True
