import sys
from typing import Any

import pytest
from pydantic import ValidationError

from guard_core.models import SecurityConfig

AGENT: dict[str, Any] = {
    "enable_redis": False,
    "enable_agent": True,
    "agent_api_key": "key",
}


@pytest.mark.parametrize("flag", [True, False])
def test_a_strict_agent_without_the_package_raises_at_construction(
    monkeypatch: pytest.MonkeyPatch, flag: bool
) -> None:
    monkeypatch.setitem(sys.modules, "guard_agent", None)

    with pytest.raises(ValidationError, match="guard-agent is not installed"):
        SecurityConfig(agent_strict=True, fail_on_misconfiguration=flag, **AGENT)


def test_a_strict_agent_the_package_rejects_raises_at_construction(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import guard_agent

    def refuse(**_: object) -> None:
        raise ValueError("endpoint is not a URL")

    monkeypatch.setattr(guard_agent, "AgentConfig", refuse)

    with pytest.raises(ValidationError, match="endpoint is not a URL"):
        SecurityConfig(agent_strict=True, **AGENT)


def test_a_strict_agent_with_no_agent_config_raises_at_construction(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(SecurityConfig, "to_agent_config", lambda self: None)

    with pytest.raises(ValidationError, match="no agent configuration"):
        SecurityConfig(agent_strict=True, **AGENT)


def test_a_non_strict_agent_without_the_package_still_builds(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setitem(sys.modules, "guard_agent", None)

    assert SecurityConfig(**AGENT).enable_agent is True


def test_a_strict_agent_without_the_agent_enabled_builds() -> None:
    assert SecurityConfig(enable_redis=False, agent_strict=True).agent_strict is True


def test_a_strict_agent_the_package_accepts_builds() -> None:
    assert SecurityConfig(agent_strict=True, **AGENT).agent_strict is True


def test_turning_strict_on_later_refuses_an_unusable_agent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setitem(sys.modules, "guard_agent", None)
    config = SecurityConfig(**AGENT)

    with pytest.raises(ValueError, match="guard-agent is not installed"):
        config.agent_strict = True
