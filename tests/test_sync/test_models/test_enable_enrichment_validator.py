import pytest
from pydantic import ValidationError

from guard_core.models import SyncSecurityConfig


def test_default_enable_enrichment_is_false() -> None:
    assert SyncSecurityConfig().enable_enrichment is False


def test_enable_enrichment_requires_enable_agent() -> None:
    with pytest.raises(ValidationError) as exc_info:
        SyncSecurityConfig(enable_enrichment=True)
    assert "enable_enrichment requires enable_agent=True" in str(exc_info.value)


def test_enable_enrichment_with_agent_is_valid() -> None:
    cfg = SyncSecurityConfig(
        enable_agent=True,
        agent_api_key="a" * 10,
        enable_enrichment=True,
    )
    assert cfg.enable_enrichment is True
    assert cfg.enable_agent is True


def test_enable_enrichment_false_with_agent_is_valid() -> None:
    cfg = SyncSecurityConfig(
        enable_agent=True,
        agent_api_key="a" * 10,
        enable_enrichment=False,
    )
    assert cfg.enable_enrichment is False
