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


def test_dangerous_filename_mentioned_mid_sentence_stays_benign() -> None:
    manager = _manager()
    payload = (
        "Ticket #4821: please confirm the attachment filename = "
        '"invoice.php" was renamed correctly before closing.'
    )
    result = manager.detect(
        content=payload, ip_address="198.51.100.4", context="request_body"
    )
    assert result["is_threat"] is False


@pytest.mark.parametrize(
    "payload",
    [
        'filename="shell.php"',
        '; filename="shell.php"',
        'Content-Disposition: form-data; name="file"; filename="shell.php"',
    ],
)
def test_real_content_disposition_filename_is_still_detected(
    payload: str,
) -> None:
    manager = _manager()
    result = manager.detect(
        content=payload, ip_address="203.0.113.9", context="request_body"
    )
    assert result["is_threat"] is True
    assert any(threat.get("category") == "file_upload" for threat in result["threats"])
