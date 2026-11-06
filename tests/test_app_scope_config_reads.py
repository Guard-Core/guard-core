from guard_core._utils.app_scope import WeakableConfig, hold_config_weakly
from guard_core._utils.scan_config_scope import ScanConfigScope, _scan_config_scope
from guard_core.handlers.ipban_handler import IPBanManager
from guard_core.handlers.suspatterns_handler import SusPatternsManager
from guard_core.models import SecurityConfig


class _Manager:
    config = WeakableConfig()


class _NotWeaklyReferenceable:
    __slots__ = ()


def test_a_strongly_set_config_is_served_while_another_manager_scans() -> None:
    manager = IPBanManager()
    config = SecurityConfig(enable_redis=False)
    manager.config = config
    other = SusPatternsManager()
    token = _scan_config_scope.set(
        ScanConfigScope(
            other, SecurityConfig(enable_redis=False), other._detection_state
        )
    )
    try:
        assert manager.config is config
    finally:
        _scan_config_scope.reset(token)


def test_a_config_without_a_weakref_slot_is_held_strongly_and_served() -> None:
    manager = _Manager()
    earlier = SecurityConfig(enable_redis=False)
    manager.config = earlier
    hold_config_weakly(manager, earlier)
    assert manager.config is earlier
    unweakable = _NotWeaklyReferenceable()

    hold_config_weakly(manager, unweakable)

    served: object = manager.config
    assert served is unweakable
    assert manager.__dict__["_guard_held_config"] is unweakable
    assert "config" not in manager.__dict__
    assert "_guard_weak_config" not in manager.__dict__
