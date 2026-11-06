import gc
import weakref
from collections.abc import Iterator

import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.sync._utils.app_scope import WeakableConfig, release_config_to_app
from guard_core.sync.handlers.suspatterns_handler import SusPatternsManager

_CAP = 1024


@pytest.fixture
def clean_default_manager(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.setattr(SusPatternsManager, "_instance", None)
    monkeypatch.setattr(SusPatternsManager, "_config", SusPatternsManager._config)
    yield
    gc.collect()


@pytest.mark.usefixtures("clean_default_manager")
def test_a_manager_built_with_a_config_nobody_else_holds_keeps_it() -> None:
    manager = SusPatternsManager(
        SyncSecurityConfig(detection_max_body_inspect_bytes=_CAP)
    )
    gc.collect()

    config = manager._config

    assert config is not None
    assert config.detection_max_body_inspect_bytes == _CAP


@pytest.mark.usefixtures("clean_default_manager")
def test_a_manager_built_after_a_class_level_reset_keeps_its_config(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(SusPatternsManager, "_config", None)
    config = SyncSecurityConfig(detection_max_body_inspect_bytes=_CAP)

    manager = SusPatternsManager(config)

    assert manager._config is config


@pytest.mark.usefixtures("clean_default_manager")
def test_a_class_level_reset_leaves_the_descriptor_in_place_for_the_next_manager(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(SusPatternsManager, "_config", None)
    SusPatternsManager(SyncSecurityConfig())

    assert isinstance(SusPatternsManager.__dict__["_config"], WeakableConfig)


@pytest.mark.usefixtures("clean_default_manager")
def test_a_manager_an_app_adopted_stops_keeping_the_config_alive() -> None:
    config = SyncSecurityConfig()
    manager = SusPatternsManager(config)
    released = weakref.ref(config)

    release_config_to_app(manager, config, "_config")
    gc.disable()
    try:
        del config
        assert released() is None
    finally:
        gc.enable()
