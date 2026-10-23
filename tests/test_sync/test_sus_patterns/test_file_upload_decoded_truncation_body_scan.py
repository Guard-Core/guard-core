from collections.abc import Generator

import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.sync.handlers.suspatterns_handler import (
    _FILE_UPLOAD_DECODED_TRUNCATION_RE,
    _FILE_UPLOAD_TRUNCATION_RE,
    DETECTION_RAW_VIEW_PATTERN_SOURCES,
    DETECTION_URL_DECODED_VIEW_PATTERN_SOURCES,
    SusPatternsManager,
    sus_patterns_handler,
)
from guard_core.sync.utils import detect_penetration_attempt
from tests.test_sync.conftest import SyncMockGuardRequest


@pytest.fixture(autouse=True)
def _force_enhanced_detection_singleton() -> None:
    sus_patterns_handler.configure(SyncSecurityConfig())


@pytest.fixture
def manager() -> Generator[SusPatternsManager, None, None]:
    original_instance = SusPatternsManager._instance
    original_config = SusPatternsManager._config
    SusPatternsManager._instance = None
    SusPatternsManager._config = None
    new_instance = SusPatternsManager(SyncSecurityConfig())
    yield new_instance
    SusPatternsManager._instance = original_instance
    SusPatternsManager._config = original_config


def _body_request(body: str) -> SyncMockGuardRequest:
    encoded = body.encode()
    return SyncMockGuardRequest(
        path="/upload",
        method="POST",
        headers={"content-length": str(len(encoded))},
        body_content=encoded,
    )


def _body_categories(body: str) -> list[str]:
    result = detect_penetration_attempt(_body_request(body), SyncSecurityConfig())
    return list(result.threat_categories)


def _body_is_threat(body: str) -> bool:
    result = detect_penetration_attempt(_body_request(body), SyncSecurityConfig())
    return bool(result.is_threat)


def _manager_truncation_threats(manager: SusPatternsManager, body: str) -> list[dict]:
    result = manager.detect(body, "203.0.113.9", context="request_body")
    return [
        threat
        for threat in result["threats"]
        if threat["type"] == "regex" and threat["pattern"] == _FILE_UPLOAD_TRUNCATION_RE
    ]


def _manager_decoded_truncation_threats(
    manager: SusPatternsManager, body: str
) -> list[dict]:
    result = manager.detect(body, "203.0.113.9", context="request_body")
    return [
        threat
        for threat in result["threats"]
        if threat["type"] == "regex"
        and threat["pattern"] == _FILE_UPLOAD_DECODED_TRUNCATION_RE
    ]


NUL_TRUNCATION_EVASION_BODIES = [
    pytest.param('filename="shell.php%00.txt"', id="percent_encoded_nul"),
    pytest.param('filename="shell.php\\x00.txt"', id="escaped_hex_nul_text"),
    pytest.param('filename="shell.php\\u0000.txt"', id="escaped_unicode_nul_text"),
    pytest.param('filename="shell.php\x00.txt"', id="raw_nul_byte"),
]


@pytest.mark.parametrize("body", NUL_TRUNCATION_EVASION_BODIES)
def test_nul_truncation_evasion_in_body_fires_file_upload(
    body: str,
) -> None:
    original_instance = SusPatternsManager._instance
    original_config = SusPatternsManager._config
    SusPatternsManager._instance = None
    SusPatternsManager._config = None
    SusPatternsManager(SyncSecurityConfig())
    try:
        categories = _body_categories(body)
        assert "file_upload" in categories
        assert _body_is_threat(body) is True
    finally:
        SusPatternsManager._instance = original_instance
        SusPatternsManager._config = original_config


@pytest.mark.parametrize("body", NUL_TRUNCATION_EVASION_BODIES)
def test_nul_truncation_evasion_fires_in_enhanced_mode_via_raw_view(
    manager: SusPatternsManager, body: str
) -> None:
    result = manager.detect(body, "203.0.113.9", context="request_body")
    assert result["detection_method"] == "enhanced"
    threats = _manager_truncation_threats(manager, body)
    assert threats
    assert threats[0]["category"] == "file_upload"


def test_bare_dangerous_extension_in_body_still_fires() -> None:
    original_instance = SusPatternsManager._instance
    original_config = SusPatternsManager._config
    SusPatternsManager._instance = None
    SusPatternsManager._config = None
    SusPatternsManager(SyncSecurityConfig())
    try:
        categories = _body_categories('filename="shell.php"')
        assert "file_upload" in categories
    finally:
        SusPatternsManager._instance = original_instance
        SusPatternsManager._config = original_config


def test_trailing_dot_truncation_in_body_still_fires() -> None:
    original_instance = SusPatternsManager._instance
    original_config = SusPatternsManager._config
    SusPatternsManager._instance = None
    SusPatternsManager._config = None
    SusPatternsManager(SyncSecurityConfig())
    try:
        categories = _body_categories('filename="shell.php."')
        assert "file_upload" in categories
    finally:
        SusPatternsManager._instance = original_instance
        SusPatternsManager._config = original_config


def test_double_extension_in_body_still_fires() -> None:
    original_instance = SusPatternsManager._instance
    original_config = SusPatternsManager._config
    SusPatternsManager._instance = None
    SusPatternsManager._config = None
    SusPatternsManager(SyncSecurityConfig())
    try:
        categories = _body_categories('filename="shell.php.jpg"')
        assert "file_upload" in categories
    finally:
        SusPatternsManager._instance = original_instance
        SusPatternsManager._config = original_config


def test_benign_php_txt_filename_in_body_not_flagged(
    manager: SusPatternsManager,
) -> None:
    assert _body_is_threat('filename="shell.php.txt"') is False
    result = manager.detect(
        'filename="shell.php.txt"', "203.0.113.9", context="request_body"
    )
    assert result["is_threat"] is False


def test_benign_photo_filename_in_body_not_flagged(
    manager: SusPatternsManager,
) -> None:
    assert _body_is_threat('filename="vacation.jpg"') is False


SPACE_IN_FILENAME_BODIES = [
    pytest.param('filename="notes.php .txt"', id="notes_php_space_txt"),
    pytest.param('filename="my report.php .txt"', id="my_report_php_space_txt"),
]


@pytest.mark.parametrize("body", SPACE_IN_FILENAME_BODIES)
def test_space_in_filename_is_not_a_truncation_vector(
    body: str,
) -> None:
    original_instance = SusPatternsManager._instance
    original_config = SusPatternsManager._config
    SusPatternsManager._instance = None
    SusPatternsManager._config = None
    SusPatternsManager(SyncSecurityConfig())
    try:
        assert _body_is_threat(body) is False
        categories = _body_categories(body)
        assert "file_upload" not in categories
    finally:
        SusPatternsManager._instance = original_instance
        SusPatternsManager._config = original_config


def test_space_bridge_is_not_a_double_extension_vector() -> None:
    original_instance = SusPatternsManager._instance
    original_config = SusPatternsManager._config
    SusPatternsManager._instance = None
    SusPatternsManager._config = None
    SusPatternsManager(SyncSecurityConfig())
    try:
        assert _body_is_threat('filename="vacation photo.php .jpg"') is False
        categories = _body_categories('filename="vacation photo.php .jpg"')
        assert "file_upload" not in categories
    finally:
        SusPatternsManager._instance = original_instance
        SusPatternsManager._config = original_config


CONTROL_CHAR_BRIDGE_DOUBLE_EXTENSION_BODIES = [
    pytest.param('filename="shell.php\n.jpg"', id="newline_bridge"),
    pytest.param('filename="shell.php\r.jpg"', id="carriage_return_bridge"),
    pytest.param('filename="shell.php\t.jpg"', id="tab_bridge"),
]


@pytest.mark.parametrize("body", CONTROL_CHAR_BRIDGE_DOUBLE_EXTENSION_BODIES)
def test_control_char_bridge_is_a_double_extension_vector(body: str) -> None:
    original_instance = SusPatternsManager._instance
    original_config = SusPatternsManager._config
    SusPatternsManager._instance = None
    SusPatternsManager._config = None
    SusPatternsManager(SyncSecurityConfig())
    try:
        assert _body_is_threat(body) is True
        categories = _body_categories(body)
        assert "file_upload" in categories
    finally:
        SusPatternsManager._instance = original_instance
        SusPatternsManager._config = original_config


SEMICOLON_TRUNCATION_BODIES = [
    pytest.param('filename="shell.php;x=1"', id="php_semicolon_path_info"),
    pytest.param('filename="shell.asp;.jpg"', id="asp_semicolon_path_info"),
]


@pytest.mark.parametrize("body", SEMICOLON_TRUNCATION_BODIES)
def test_semicolon_truncation_vector_still_fires(
    body: str,
) -> None:
    original_instance = SusPatternsManager._instance
    original_config = SusPatternsManager._config
    SusPatternsManager._instance = None
    SusPatternsManager._config = None
    SusPatternsManager(SyncSecurityConfig())
    try:
        categories = _body_categories(body)
        assert "file_upload" in categories
        assert _body_is_threat(body) is True
    finally:
        SusPatternsManager._instance = original_instance
        SusPatternsManager._config = original_config


def test_double_encoded_nul_truncation_fires_in_url_decoded_view() -> None:
    original_instance = SusPatternsManager._instance
    original_config = SusPatternsManager._config
    SusPatternsManager._instance = None
    SusPatternsManager._config = None
    SusPatternsManager(SyncSecurityConfig())
    try:
        body = 'filename="shell.php%2500.txt"'
        assert _body_is_threat(body) is True
        categories = _body_categories(body)
        assert "file_upload" in categories
    finally:
        SusPatternsManager._instance = original_instance
        SusPatternsManager._config = original_config


def test_decoded_truncation_pattern_registered_in_url_decoded_view_only(
    manager: SusPatternsManager,
) -> None:
    assert (
        _FILE_UPLOAD_DECODED_TRUNCATION_RE in DETECTION_URL_DECODED_VIEW_PATTERN_SOURCES
    )
    assert _FILE_UPLOAD_DECODED_TRUNCATION_RE not in DETECTION_RAW_VIEW_PATTERN_SOURCES
    body = 'filename="shell.php%2500.txt"'
    threats = _manager_decoded_truncation_threats(manager, body)
    assert threats
    assert threats[0]["category"] == "file_upload"
    assert threats[0]["pattern"] == _FILE_UPLOAD_DECODED_TRUNCATION_RE


BENIGN_DECODED_TRUNCATION_FP_BODIES = [
    pytest.param('filename="vacation.jpg"', id="benign_jpg"),
    pytest.param('filename="shell.php.txt"', id="benign_php_txt"),
    pytest.param('filename="notes.php .txt"', id="benign_php_space_txt"),
    pytest.param('filename="report;final.pdf"', id="benign_semicolon_pdf"),
    pytest.param('filename="invoice;final.pdf"', id="benign_invoice_semicolon_pdf"),
    pytest.param('filename="notes.php .jpg"', id="benign_php_space_jpg"),
]


@pytest.mark.parametrize("body", BENIGN_DECODED_TRUNCATION_FP_BODIES)
def test_benign_filenames_do_not_fire_decoded_truncation_pattern(
    manager: SusPatternsManager, body: str
) -> None:
    threats = _manager_decoded_truncation_threats(manager, body)
    assert not threats


def test_benign_base64_blob_in_filename_does_not_fire_decoded_truncation_pattern(
    manager: SusPatternsManager,
) -> None:
    blob = "aBcDeFgHiJkLmN" * 50
    body = f'filename="{blob}"'
    threats = _manager_decoded_truncation_threats(manager, body)
    assert not threats


BENIGN_DECODED_BASE64_FP_BODIES = [
    pytest.param(
        'filename="cmVwb3J0O2ZpbmFsLnBkZg=="',
        id="benign_base64_report_semicolon_pdf",
    ),
    pytest.param(
        'filename="dmFjYXRpb24uanBn"',
        id="benign_base64_vacation_jpg",
    ),
]


@pytest.mark.parametrize("body", BENIGN_DECODED_BASE64_FP_BODIES)
def test_benign_base64_decoded_blobs_do_not_fire_decoded_truncation_pattern(
    manager: SusPatternsManager, body: str
) -> None:
    threats = _manager_decoded_truncation_threats(manager, body)
    assert not threats


DOUBLE_ENCODED_NUL_BODIES = [
    pytest.param('filename="shell.php%2500.txt"', id="double_encoded_percent_nul"),
    pytest.param('filename="shell.asp%2500.jpg"', id="double_encoded_asp_nul"),
]


@pytest.mark.parametrize("body", DOUBLE_ENCODED_NUL_BODIES)
def test_double_encoded_nul_fires_file_upload_in_url_decoded_view(
    body: str,
) -> None:
    original_instance = SusPatternsManager._instance
    original_config = SusPatternsManager._config
    SusPatternsManager._instance = None
    SusPatternsManager._config = None
    SusPatternsManager(SyncSecurityConfig())
    try:
        categories = _body_categories(body)
        assert "file_upload" in categories
        assert _body_is_threat(body) is True
    finally:
        SusPatternsManager._instance = original_instance
        SusPatternsManager._config = original_config


DOUBLE_ENCODED_SEMICOLON_BODIES = [
    pytest.param(
        'filename="shell.asp%253B.jpg"',
        id="asp_double_encoded_semicolon_path_info",
    ),
    pytest.param(
        'filename="shell.php%253Bx=1"',
        id="php_double_encoded_semicolon_path_info",
    ),
]


@pytest.mark.parametrize("body", DOUBLE_ENCODED_SEMICOLON_BODIES)
def test_double_encoded_semicolon_fires_file_upload_in_url_decoded_view(
    body: str,
) -> None:
    original_instance = SusPatternsManager._instance
    original_config = SusPatternsManager._config
    SusPatternsManager._instance = None
    SusPatternsManager._config = None
    SusPatternsManager(SyncSecurityConfig())
    try:
        assert _body_is_threat(body) is True
        categories = _body_categories(body)
        assert "file_upload" in categories
    finally:
        SusPatternsManager._instance = original_instance
        SusPatternsManager._config = original_config


SINGLE_ENCODED_SEMICOLON_BODIES = [
    pytest.param(
        'filename="shell.asp%3B.jpg"',
        id="asp_single_encoded_semicolon_path_info",
    ),
]


@pytest.mark.parametrize("body", SINGLE_ENCODED_SEMICOLON_BODIES)
def test_single_encoded_semicolon_fires_file_upload_in_url_decoded_view(
    body: str,
) -> None:
    original_instance = SusPatternsManager._instance
    original_config = SusPatternsManager._config
    SusPatternsManager._instance = None
    SusPatternsManager._config = None
    SusPatternsManager(SyncSecurityConfig())
    try:
        assert _body_is_threat(body) is True
        categories = _body_categories(body)
        assert "file_upload" in categories
    finally:
        SusPatternsManager._instance = original_instance
        SusPatternsManager._config = original_config


ENCODED_TRAILING_DOT_BODIES = [
    pytest.param(
        'filename="shell.php%252E"',
        id="php_double_encoded_trailing_dot",
    ),
    pytest.param(
        'filename="shell.php%2E"',
        id="php_single_encoded_trailing_dot",
    ),
]


@pytest.mark.parametrize("body", ENCODED_TRAILING_DOT_BODIES)
def test_encoded_trailing_dot_fires_file_upload_in_url_decoded_view(
    body: str,
) -> None:
    original_instance = SusPatternsManager._instance
    original_config = SusPatternsManager._config
    SusPatternsManager._instance = None
    SusPatternsManager._config = None
    SusPatternsManager(SyncSecurityConfig())
    try:
        assert _body_is_threat(body) is True
        categories = _body_categories(body)
        assert "file_upload" in categories
    finally:
        SusPatternsManager._instance = original_instance
        SusPatternsManager._config = original_config


def test_decoded_truncation_manager_detects_semicolon_and_dot_bodies(
    manager: SusPatternsManager,
) -> None:
    assert (
        _FILE_UPLOAD_DECODED_TRUNCATION_RE in DETECTION_URL_DECODED_VIEW_PATTERN_SOURCES
    )
    assert _FILE_UPLOAD_DECODED_TRUNCATION_RE not in DETECTION_RAW_VIEW_PATTERN_SOURCES
    semicolon_body = 'filename="shell.asp%253B.jpg"'
    semicolon_result = manager.detect(
        semicolon_body, "203.0.113.9", context="request_body"
    )
    semicolon_threats = [
        threat
        for threat in semicolon_result["threats"]
        if threat["type"] == "regex"
        and threat["pattern"] == _FILE_UPLOAD_DECODED_TRUNCATION_RE
    ]
    assert semicolon_threats
    assert semicolon_threats[0]["category"] == "file_upload"
    assert semicolon_threats[0]["pattern"] == _FILE_UPLOAD_DECODED_TRUNCATION_RE
    dot_body = 'filename="shell.php%252E"'
    dot_result = manager.detect(dot_body, "203.0.113.9", context="request_body")
    dot_threats = [
        threat
        for threat in dot_result["threats"]
        if threat["type"] == "regex"
        and threat["pattern"] == _FILE_UPLOAD_DECODED_TRUNCATION_RE
    ]
    assert dot_threats
    assert dot_threats[0]["category"] == "file_upload"
    assert dot_threats[0]["pattern"] == _FILE_UPLOAD_DECODED_TRUNCATION_RE
