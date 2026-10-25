import ipaddress
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from guard_core._utils.app_managers import _Held, hold_for_app
from guard_core._utils.config_registry import ConfigHandlerRegistry
from guard_core.handlers import _ipinfo_redis_copy as ipinfo_copy_module
from guard_core.handlers import _suspatterns_enhanced as enhanced_module
from guard_core.handlers.cloud_handler import CloudManager
from guard_core.handlers.ipinfo_handler import IPInfoManager
from guard_core.handlers.suspatterns_handler import (
    SusPatternsManager,
    active_sus_patterns,
    scanning_with,
    sus_patterns_handler,
)
from guard_core.models import SecurityConfig


class _Slotted:
    __slots__ = ("__weakref__",)


class _NoWeakref:
    __slots__ = ()


class _Target:
    pass


def test_held_managers_are_shared_by_a_copy_of_the_config() -> None:
    import copy

    held = _Held(kind=object())
    assert copy.copy(held) is held
    assert copy.deepcopy(held) is held


def test_hold_for_app_ignores_a_config_that_cannot_keep_attributes() -> None:
    hold_for_app(_NoWeakref(), "kind", object())


def test_registry_drop_removes_the_entry_of_a_config() -> None:
    registry = ConfigHandlerRegistry()
    config, handler = _Slotted(), _Target()
    registry.register(config, handler, "kind")
    assert registry.lookup(config, "kind") is handler

    registry.drop(config, "kind")

    assert registry.lookup(config, "kind") is None


def test_ip_info_manager_keeps_a_redis_handler_that_cannot_be_weakly_referenced(
    tmp_path: Path,
) -> None:
    manager = IPInfoManager._fresh("token", tmp_path / "db.mmdb", 1)
    handler = Mock()

    def _refuses(_target: object) -> object:
        raise TypeError("cannot create weak reference")

    with patch.object(ipinfo_copy_module, "weakref", SimpleNamespace(ref=_refuses)):
        manager._bind_redis_handler(handler)

    assert manager._copy_handlers() == [handler]


def test_scanning_with_sets_the_active_manager_only_inside_the_block() -> None:
    manager = SusPatternsManager._for_app(SecurityConfig())

    with scanning_with(manager):
        assert active_sus_patterns() is manager

    assert active_sus_patterns() is sus_patterns_handler


def test_a_config_without_the_enhanced_fields_gets_a_legacy_manager() -> None:
    manager = SusPatternsManager._for_app(SimpleNamespace())

    assert manager._detection_state is sus_patterns_handler._detection_state


def test_configure_survives_a_config_that_refuses_the_manager_reference() -> None:
    class _Refuses(SecurityConfig):
        def __setattr__(self, name: str, value: object) -> None:
            if name == "_guard_pattern_manager":
                raise AttributeError(name)
            super().__setattr__(name, value)

    manager = SusPatternsManager._fresh()
    config = _Refuses()

    enhanced_module._SusPatternsEnhancedMixin.configure(manager, config)

    assert manager._detection_state.compiler is not None


def test_cloud_manager_reuses_downloaded_ranges_only_while_fresh() -> None:
    donor = CloudManager._fresh()
    manager = CloudManager._for_app(donor)
    manager.ip_ranges["AWS"] = set()
    assert manager._ranges_downloaded_within("AWS", 3600) is None

    manager.last_updated["AWS"] = datetime.now(timezone.utc) - timedelta(seconds=7200)
    manager.ip_ranges["AWS"] = {ipaddress.ip_network("10.0.0.0/8")}
    assert manager._ranges_downloaded_within("AWS", 3600) is None

    manager.last_updated["AWS"] = datetime.now(timezone.utc)
    found = manager._ranges_downloaded_within("AWS", 3600)
    assert found is not None
    assert found[0] == {ipaddress.ip_network("10.0.0.0/8")}
