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
    "payload",
    [
        "url=https://example.com/install.sh",
        "url=https://legacy.example.com/cgi-bin/search.cgi",
    ],
)
def test_benign_installer_and_cgi_links_stay_clear(payload: str) -> None:
    manager = _manager()
    result = manager.detect(
        content=payload, ip_address="198.51.100.4", context="request_body"
    )
    assert result["is_threat"] is False


def test_txt_extension_rfi_payload_is_still_detected() -> None:
    manager = _manager()
    payload = "?file=https://evil.example/backdoor.txt"
    result = manager.detect(
        content=payload, ip_address="203.0.113.9", context="request_body"
    )
    assert result["is_threat"] is True
    assert any(
        threat.get("category") == "file_inclusion" for threat in result["threats"]
    )
