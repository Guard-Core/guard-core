import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.sync.handlers.suspatterns_handler import SusPatternsManager


def _manager() -> SusPatternsManager:
    original_instance = SusPatternsManager._instance
    original_config = SusPatternsManager._config
    SusPatternsManager._instance = None
    SusPatternsManager._config = None
    manager = SusPatternsManager(SyncSecurityConfig())
    SusPatternsManager._instance = original_instance
    SusPatternsManager._config = original_config
    return manager


@pytest.mark.parametrize(
    "payload,category",
    [
        (
            "Note: the scanner hit /wp-admin/install.php on our staging host.",
            "cms_probing",
        ),
        (
            "We detected an attacker trying to access /.git/config on the "
            "public endpoint.",
            "sensitive_file",
        ),
        (
            "The honeypot recorded a request to /etc/passwd from an unknown scanner.",
            "dir_traversal",
        ),
    ],
)
def test_attack_report_prose_with_probe_path_is_detected(
    payload: str, category: str
) -> None:
    manager = _manager()
    result = manager.detect(
        content=payload, ip_address="203.0.113.9", context="request_body"
    )
    assert result["is_threat"] is True
    assert any(threat.get("category") == category for threat in result["threats"])


@pytest.mark.parametrize(
    "payload",
    [
        "The changelog mentions removing /wp-admin/install.php from the demo site.",
        "Please confirm /.git/config was purged from the old snapshot.",
        "The runbook says to check /etc/passwd for stale local accounts.",
    ],
)
def test_ordinary_prose_mentioning_the_same_path_stays_benign(
    payload: str,
) -> None:
    manager = _manager()
    result = manager.detect(
        content=payload, ip_address="198.51.100.4", context="request_body"
    )
    assert result["is_threat"] is False
