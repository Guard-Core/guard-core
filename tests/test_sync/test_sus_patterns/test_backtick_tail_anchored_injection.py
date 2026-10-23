from guard_core.models import SyncSecurityConfig
from guard_core.sync.handlers.suspatterns_handler import SusPatternsManager

_FILLER = (
    "The quarterly report summarizes engagement metrics across every region "
    "and highlights the onboarding funnel improvements shipped last sprint. "
) * 90


def _manager() -> SusPatternsManager:
    original_instance = SusPatternsManager._instance
    original_config = SusPatternsManager._config
    SusPatternsManager._instance = None
    SusPatternsManager._config = None
    manager = SusPatternsManager(SyncSecurityConfig())
    SusPatternsManager._instance = original_instance
    SusPatternsManager._config = original_config
    return manager


def _legacy_manager() -> SusPatternsManager:
    original_instance = SusPatternsManager._instance
    original_config = SusPatternsManager._config
    SusPatternsManager._instance = None
    SusPatternsManager._config = None
    manager = SusPatternsManager()
    SusPatternsManager._instance = original_instance
    SusPatternsManager._config = original_config
    return manager


def test_backtick_command_appended_after_bulk_prose_is_detected() -> None:
    manager = _manager()
    payload = _FILLER + "`whoami`"
    result = manager.detect(
        content=payload, ip_address="203.0.113.9", context="request_body"
    )
    assert result["is_threat"] is True
    assert any(
        threat.get("category") == "cmd_injection" for threat in result["threats"]
    )


def test_backtick_quoted_word_mid_sentence_stays_benign() -> None:
    manager = _manager()
    payload = "See error code `ETIMEDOUT` in the attached log for details."
    result = manager.detect(
        content=payload, ip_address="198.51.100.4", context="request_body"
    )
    assert result["is_threat"] is False


def test_sql_dotted_identifier_chain_at_string_end_stays_benign() -> None:
    manager = _manager()
    payload = (
        "SELECT `u`.`id` FROM `users` `u` JOIN `orders` `o` ON `u`.`id` = `o`.`uid`"
    )
    result = manager.detect(
        content=payload, ip_address="198.51.100.4", context="request_body"
    )
    assert result["is_threat"] is False


def test_backtick_pair_preceded_only_by_whitespace_is_detected() -> None:
    manager = _legacy_manager()
    payload = "   `whoami`   "
    result = manager.detect(
        content=payload, ip_address="203.0.113.9", context="request_body"
    )
    assert result["is_threat"] is True
    assert any(
        threat.get("category") == "cmd_injection" for threat in result["threats"]
    )
