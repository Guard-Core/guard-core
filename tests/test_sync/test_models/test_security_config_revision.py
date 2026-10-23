from guard_core.models import SecurityConfig, SyncSecurityConfig


def test_fresh_config_has_zero_revision() -> None:
    config = SyncSecurityConfig()
    assert config.revision == 0


def test_revision_increments_on_field_assignment() -> None:
    config = SyncSecurityConfig()
    config.blocked_user_agents = ["badbot"]
    assert config.revision == 1
    config.rate_limit = 5
    assert config.revision == 2


def test_revision_is_not_a_model_field() -> None:
    assert "_revision" not in SecurityConfig.model_fields
    assert "revision" not in SecurityConfig.model_fields


def test_revision_is_absent_from_model_dump() -> None:
    config = SyncSecurityConfig()
    config.rate_limit = 5
    assert "_revision" not in config.model_dump()
    assert "revision" not in config.model_dump()


def test_revision_does_not_affect_equality() -> None:
    mutated = SyncSecurityConfig()
    mutated.rate_limit = 5
    mutated.rate_limit_window = 30

    fresh = SyncSecurityConfig(rate_limit=5, rate_limit_window=30)

    assert mutated.revision != fresh.revision
    assert mutated == fresh


def test_revision_survives_model_copy() -> None:
    config = SyncSecurityConfig()
    config.rate_limit = 5
    copy = config.model_copy()

    assert copy.revision == config.revision

    copy.rate_limit_window = 30
    assert copy.revision == config.revision + 1
    assert config.revision == 1


def test_directly_assigning_revision_before_any_bump_is_visible() -> None:
    config = SyncSecurityConfig()
    config._revision = 100
    assert config.revision == 100


def test_directly_assigning_revision_after_a_bump_does_not_change_it() -> None:
    config = SyncSecurityConfig()
    config.rate_limit = 5
    assert config.revision == 1

    config._revision = 100
    assert config.revision == 1


def test_independent_configs_have_independent_revisions() -> None:
    first = SyncSecurityConfig()
    second = SyncSecurityConfig()

    first.rate_limit = 5

    assert first.revision == 1
    assert second.revision == 0


def test_revision_survives_a_class_level_private_attribute_leak() -> None:
    leaked_descriptor = SecurityConfig._revision
    SecurityConfig._revision = leaked_descriptor
    try:
        config = SyncSecurityConfig()
        config.rate_limit = 5
        assert config.revision == 1
        config.rate_limit_window = 30
        assert config.revision == 2
    finally:
        delattr(SecurityConfig, "_revision")
