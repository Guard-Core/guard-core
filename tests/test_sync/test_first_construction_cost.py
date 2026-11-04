import sys
from collections.abc import Callable
from types import FrameType, MappingProxyType
from typing import Any

import pytest
from pydantic import PrivateAttr

from guard_core import _staged_defaults, models
from guard_core._security_config_fields import DEFAULT_EXCLUDE_PATHS
from guard_core._staged_defaults import StagedDefaultsConfig
from guard_core.models import SecurityConfig, SyncSecurityConfig

STATED_EVERY_CHANGED_DEFAULT: dict[str, Any] = {
    "ban_on_hostile_signals": True,
    "fail_on_misconfiguration": True,
    "rate_limit": 120,
    "enable_redis": False,
}


def _called_function_names(build: Callable[[], object]) -> set[str]:
    called: set[str] = set()

    def record(frame: FrameType, event: str, arg: object) -> None:
        if event == "call":
            called.add(frame.f_code.co_name)

    sys.setprofile(record)
    try:
        build()
    finally:
        sys.setprofile(None)
    return called


def test_the_one_private_attribute_is_started_without_pydantics_initializer() -> None:
    assert "init_private_attributes" not in _called_function_names(SecurityConfig)


def test_the_private_state_equals_what_pydantics_initializer_builds() -> None:
    expected = {
        name: attribute.get_default()
        for name, attribute in SecurityConfig.__private_attributes__.items()
    }

    assert set(SecurityConfig.__private_attributes__) == {"_revision"}
    assert SyncSecurityConfig().__pydantic_private__ == expected


def test_a_subclass_with_a_private_attribute_keeps_both_states() -> None:
    class Extended(SecurityConfig[Any]):
        _note: str = PrivateAttr(default="kept")

    assert Extended().__pydantic_private__ == {"_revision": 0, "_note": "kept"}


def test_a_parametrized_config_starts_with_the_revision_state() -> None:
    assert SecurityConfig[Any]().__pydantic_private__ == {"_revision": 0}


def test_a_model_construct_config_starts_with_the_revision_state() -> None:
    assert SyncSecurityConfig.model_construct().__pydantic_private__ == {"_revision": 0}


def test_each_config_gets_its_own_private_state() -> None:
    first, second = SyncSecurityConfig(), SyncSecurityConfig()

    assert first.__pydantic_private__ is not second.__pydantic_private__


@pytest.mark.parametrize(
    "field", ["cors_allow_origins", "cors_allow_methods", "cors_allow_headers"]
)
def test_a_list_default_is_a_fresh_list_per_config(field: str) -> None:
    first, second = SyncSecurityConfig(), SyncSecurityConfig()

    getattr(first, field).append("X")

    assert "X" not in getattr(second, field)


def test_the_default_exclude_paths_are_a_fresh_list_equal_to_the_constant() -> None:
    first, second = SyncSecurityConfig(), SyncSecurityConfig()

    assert first.exclude_paths == list(DEFAULT_EXCLUDE_PATHS)
    assert first.exclude_paths is not second.exclude_paths


def test_the_default_threat_ban_config_is_an_empty_read_only_mapping() -> None:
    config = SyncSecurityConfig()

    assert isinstance(config.threat_ban_config, MappingProxyType)
    assert dict(config.threat_ban_config) == {}


def test_the_default_detection_categories_are_all_of_them() -> None:
    assert SyncSecurityConfig().enabled_detection_categories == frozenset(
        models.ALL_DETECTION_CATEGORIES
    )


@pytest.mark.parametrize(
    "field", ["muted_event_types", "muted_metric_types", "blocked_countries"]
)
def test_an_empty_frozenset_default_is_still_empty_and_immutable(field: str) -> None:
    value = getattr(SyncSecurityConfig(), field)

    assert value == frozenset()
    assert isinstance(value, frozenset)


def test_an_empty_tuple_default_is_still_an_empty_tuple() -> None:
    config = SyncSecurityConfig()

    assert config.trusted_proxies == ()
    assert config.exempt_ips == ()


def _count_signal_calls(monkeypatch: pytest.MonkeyPatch) -> list[object]:
    signalled: list[object] = []
    real = models.signal_changed_defaults

    def spy(config: StagedDefaultsConfig) -> None:
        signalled.append(config)
        real(config)

    monkeypatch.setattr(models, "signal_changed_defaults", spy)
    return signalled


@pytest.mark.parametrize(
    "extra",
    [
        {},
        {"whitelist": ["10.0.0.1"]},
        {"exclude_paths": ["/"]},
        {"exclude_paths": ["/health"]},
        {"enable_rate_limiting": False},
    ],
)
def test_the_validator_signals_exactly_when_a_changed_default_is_left_unstated(
    monkeypatch: pytest.MonkeyPatch, extra: dict[str, Any]
) -> None:
    signalled = _count_signal_calls(monkeypatch)

    config = SyncSecurityConfig(**STATED_EVERY_CHANGED_DEFAULT, **extra)

    assert bool(signalled) is not _staged_defaults._states_every_changed_default(config)


@pytest.mark.parametrize("missing", sorted(STATED_EVERY_CHANGED_DEFAULT))
def test_leaving_one_changed_default_unstated_signals(
    monkeypatch: pytest.MonkeyPatch, missing: str
) -> None:
    signalled = _count_signal_calls(monkeypatch)
    stated = {k: v for k, v in STATED_EVERY_CHANGED_DEFAULT.items() if k != missing}

    SyncSecurityConfig(**stated)

    assert len(signalled) == 1


def test_a_trigger_assignment_on_a_fully_stated_config_signals_nothing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = SyncSecurityConfig(**STATED_EVERY_CHANGED_DEFAULT)

    def refuse(_config: object) -> object:
        raise AssertionError("the dedupe table was looked up")

    monkeypatch.setattr(_staged_defaults._changed_defaults_logged, "for_app", refuse)

    config.rate_limit = 5

    assert config.rate_limit == 5


def test_a_config_with_the_agent_off_skips_both_agent_helpers() -> None:
    called = _called_function_names(
        lambda: SyncSecurityConfig(**STATED_EVERY_CHANGED_DEFAULT)
    )

    assert "require_agent_config" not in called
    assert "warn_agent_endpoint_in_clear" not in called


def test_a_config_with_the_agent_on_still_runs_both_agent_helpers() -> None:
    called = _called_function_names(
        lambda: SyncSecurityConfig(
            **STATED_EVERY_CHANGED_DEFAULT,
            enable_agent=True,
            agent_api_key="key",
            agent_endpoint="https://agent.example",
        )
    )

    assert {"require_agent_config", "warn_agent_endpoint_in_clear"} <= called


@pytest.mark.parametrize("field", ["enable_dynamic_rules", "enable_enrichment"])
def test_a_dependent_agent_field_without_the_agent_still_refuses(field: str) -> None:
    with pytest.raises(ValueError, match="enable_agent"):
        SyncSecurityConfig(**STATED_EVERY_CHANGED_DEFAULT, **{field: True})
