from guard_core.models import SyncSecurityConfig


def test_lazy_init_default_is_true() -> None:
    config = SyncSecurityConfig()
    assert config.lazy_init is True


def test_lazy_init_can_be_set_false_explicitly() -> None:
    config = SyncSecurityConfig(lazy_init=False)
    assert config.lazy_init is False
