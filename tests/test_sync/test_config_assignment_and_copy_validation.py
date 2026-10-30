import pytest
from pydantic import ValidationError

from guard_core.models import SecurityConfig, SyncSecurityConfig


def _assign(name: str, value: object) -> None:
    config = SyncSecurityConfig()
    setattr(config, name, value)


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("ipv6_prefix_length", 0),
        ("detection_max_scan_seconds", 0),
        ("redis_pool_timeout", -1),
        ("banned_ips_max_entries", 0),
    ],
)
def test_an_assignment_meets_the_field_constraints(name: str, value: object) -> None:
    config = SyncSecurityConfig()
    before = getattr(config, name)

    with pytest.raises(ValidationError):
        setattr(config, name, value)

    assert getattr(config, name) == before


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("rate_limit", 0),
        ("rate_limit_window", -5),
        ("detection_threat_score_threshold", 0),
        ("exclude_paths", ["/a/*"]),
        ("enable_dynamic_rules", True),
    ],
)
def test_an_assignment_is_refused_where_construction_is(
    name: str, value: object
) -> None:
    config = SyncSecurityConfig()
    before = getattr(config, name)
    revision = config.revision

    with pytest.raises(ValueError):
        setattr(config, name, value)

    assert getattr(config, name) == before
    assert config.revision == revision


def test_a_boolean_field_reads_an_assigned_string_as_construction_does() -> None:
    config = SyncSecurityConfig()

    name = "ban_on_hostile_signals"
    setattr(config, name, "no")

    assert config.ban_on_hostile_signals is False


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("rate_limit", 0),
        ("ipv6_prefix_length", 0),
        ("exclude_paths", ["/a/*"]),
        ("enable_dynamic_rules", True),
    ],
)
def test_model_copy_is_refused_where_construction_is(name: str, value: object) -> None:
    with pytest.raises(ValueError):
        SyncSecurityConfig().model_copy(update={name: value})


def test_a_misconfiguration_assignment_only_warns_when_the_refusal_is_off(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = SyncSecurityConfig(fail_on_misconfiguration=False)

    config.rate_limit = 0

    assert config.rate_limit == 0
    assert "rate_limit is 0" in caplog.text


def test_valid_assignments_and_copies_are_unchanged() -> None:
    config = SyncSecurityConfig()
    config.rate_limit = 7
    config.ipv6_prefix_length = 56

    copied = config.model_copy(update={"rate_limit": 9})

    assert (config.rate_limit, config.ipv6_prefix_length, copied.rate_limit) == (
        7,
        56,
        9,
    )


@pytest.mark.parametrize(
    "fields",
    [
        {"rate_limit": 0},
        {"rate_limit_window": 0},
        {"endpoint_rate_limits": {"/x": (0, 5)}},
    ],
)
def test_a_rate_limit_below_one_is_refused_only_while_the_limiter_is_on(
    fields: dict[str, object],
) -> None:
    with pytest.raises(ValidationError):
        SyncSecurityConfig(**{"enable_rate_limiting": True, **fields})

    assert SyncSecurityConfig(**{"enable_rate_limiting": False, **fields})


def test_every_model_field_has_a_constraint_probe() -> None:
    from guard_core._security_config_assignment_checks import _constraint_probe

    for name in SecurityConfig.model_fields:
        _constraint_probe(SecurityConfig, name)


def test_a_misconfiguration_that_was_already_there_is_not_reported_again(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = SyncSecurityConfig(fail_on_misconfiguration=False, exclude_paths=["/a/*"])
    caplog.clear()

    config.rate_limit_window = 30

    assert "exclude_paths" not in caplog.text


def test_model_copy_with_an_unknown_key_is_left_to_pydantic() -> None:
    copied = SyncSecurityConfig().model_copy(update={"not_a_field": 1})

    assert copied.rate_limit == SyncSecurityConfig().rate_limit
