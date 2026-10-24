import pytest

from guard_core._security_config_field_validators import (
    _validate_blocked_user_agents_value,
)
from guard_core._utils.detection_scan import _MAX_USER_AGENT_MATCH_LENGTH
from guard_core.detection_engine.compiler import PatternCompiler


def test_config_field_validator_cap_covers_the_user_agent_scan_window(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    caps: list[int | None] = []

    def record(
        _compiler: PatternCompiler,
        _pattern: str,
        test_strings: list[str] | None = None,
        max_content_length: int | None = None,
        flags: int = 0,
    ) -> tuple[bool, str]:
        caps.append(max_content_length)
        return True, "ok"

    monkeypatch.setattr(PatternCompiler, "validate_pattern_safety", record)

    _validate_blocked_user_agents_value(["abc"])

    assert caps == [_MAX_USER_AGENT_MATCH_LENGTH]
