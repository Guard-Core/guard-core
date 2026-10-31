import pytest

from guard_core import models
from guard_core._security_config_blocked_user_agents import (
    _reject_redos_unsafe_blocked_user_agents_at_field,
)
from guard_core.models import SyncSecurityConfig


def test_an_empty_list_passes_the_field_gate_without_redaction_names() -> None:
    _reject_redos_unsafe_blocked_user_agents_at_field("SyncSecurityConfig", [], None)


def test_a_config_without_blocked_user_agents_builds_no_sensitive_name_sets(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def refuse(_config: object) -> object:
        raise AssertionError("built the sensitive name sets for an empty list")

    monkeypatch.setattr(models, "_ConfigSensitiveNames", refuse)

    assert SyncSecurityConfig().blocked_user_agents == []
