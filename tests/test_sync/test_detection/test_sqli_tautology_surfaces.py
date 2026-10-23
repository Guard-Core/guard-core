from urllib.parse import quote

import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.sync.handlers.suspatterns_handler import sus_patterns_handler
from guard_core.sync.utils import detect_penetration_attempt
from tests.test_sync.conftest import SyncMockGuardRequest

_CONFIG = SyncSecurityConfig()
_TAUTOLOGY = "' OR 1=1--"


@pytest.fixture(autouse=True)
def _force_enhanced_detection_singleton() -> None:
    sus_patterns_handler.configure(SyncSecurityConfig())


def _header_request(name: str, value: str) -> SyncMockGuardRequest:
    return SyncMockGuardRequest(headers={name: value})


def _path_request(path: str) -> SyncMockGuardRequest:
    return SyncMockGuardRequest(path=path)


_TAUTOLOGY_DETECTED_REQUESTS = [
    pytest.param(_header_request("X-Session", _TAUTOLOGY), id="header_bare"),
    pytest.param(
        _header_request("X-Session", "1" + _TAUTOLOGY), id="header_leading_digit"
    ),
    pytest.param(
        _header_request("X-Session", f"password=x {_TAUTOLOGY}"),
        id="header_after_assignment_pair",
    ),
    pytest.param(
        _header_request("Cookie", f"a=1; {_TAUTOLOGY}"), id="cookie_header_value"
    ),
    pytest.param(_path_request(f"/{_TAUTOLOGY}"), id="url_path_segment_bare"),
    pytest.param(
        _path_request("/" + quote(_TAUTOLOGY)), id="url_path_segment_percent_encoded"
    ),
]


@pytest.mark.parametrize("request_obj", _TAUTOLOGY_DETECTED_REQUESTS)
def test_sqli_tautology_detected_outside_body_and_query(
    request_obj: SyncMockGuardRequest,
) -> None:
    result = detect_penetration_attempt(request_obj, _CONFIG)
    assert result.is_threat is True
    assert "sqli" in result.threat_categories


_BENIGN_HEADER_REQUESTS_NOT_DETECTED = [
    pytest.param(
        _header_request(
            "User-Agent",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        ),
        id="ordinary_user_agent",
    ),
    pytest.param(
        _header_request(
            "Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
        ),
        id="ordinary_accept_header",
    ),
    pytest.param(
        _header_request("Cookie", "a=a; session=abc123"),
        id="cookie_repeated_value_no_boolean_keyword",
    ),
    pytest.param(
        _path_request("/resource;a=a"), id="url_path_matrix_param_repeated_value"
    ),
]


@pytest.mark.parametrize("request_obj", _BENIGN_HEADER_REQUESTS_NOT_DETECTED)
def test_ordinary_header_and_path_values_stay_clean(
    request_obj: SyncMockGuardRequest,
) -> None:
    result = detect_penetration_attempt(request_obj, _CONFIG)
    assert result.is_threat is False
