import copy

import pytest

from guard_core._utils import detection_scan, sampling
from guard_core._utils.app_managers import SHARED_BY_APPS, mark_shared_by_apps
from guard_core._utils.app_scope import (
    ScopedConfig,
    _current_app_scope,
    app_scope_of,
    existing_app_scope_of,
    release_app_scope,
)
from guard_core._utils.ip_extraction import (
    _take_evicted_suppressed_count,
    _untrusted_peers,
)
from guard_core._utils.sampling import PerApp, SampledKeys
from guard_core.models import SecurityConfig


def test_a_copy_of_an_app_scope_is_the_scope_itself() -> None:
    scope = app_scope_of(SecurityConfig(enable_redis=False))

    assert copy.copy(scope) is scope
    assert copy.deepcopy(scope) is scope


def test_a_class_reads_the_scoped_attribute_descriptor_itself() -> None:
    class Manager:
        config = ScopedConfig()

    assert isinstance(Manager.config, ScopedConfig)


def test_releasing_no_token_leaves_the_scope_in_force() -> None:
    scope = app_scope_of(SecurityConfig(enable_redis=False))
    token = _current_app_scope.set(scope)
    try:
        release_app_scope(None)

        assert _current_app_scope.get() is scope
    finally:
        _current_app_scope.reset(token)
    assert existing_app_scope_of(scope.config) is scope


def test_marking_a_manager_shared_twice_keeps_both_apps() -> None:
    first = SecurityConfig(enable_redis=False)
    second = SecurityConfig(enable_redis=False)
    manager = type("Manager", (), {})()

    mark_shared_by_apps(manager, first)
    mark_shared_by_apps(manager, second)

    sharing = manager.__dict__[SHARED_BY_APPS]
    assert sharing[id(first)] is first
    assert sharing[id(second)] is second


def test_a_charge_from_text_extraction_counts_only_outside_a_cpu_pass() -> None:
    spent_token = detection_scan._scan_time_spent.set(0.0)
    try:
        detection_scan._charge_extraction_cpu(2.0)
        assert detection_scan._scan_time_spent.get() == 2.0

        mark_token = detection_scan._scan_cpu_mark.set(1.0)
        try:
            detection_scan._charge_extraction_cpu(5.0)
        finally:
            detection_scan._scan_cpu_mark.reset(mark_token)
        assert detection_scan._scan_time_spent.get() == 2.0
    finally:
        detection_scan._scan_time_spent.reset(spent_token)


def test_the_evicted_untrusted_peer_count_is_taken_once_per_app() -> None:
    config = SecurityConfig(enable_redis=False)
    other = SecurityConfig(enable_redis=False)
    _untrusted_peers.for_app(config).evicted_pending = 3

    assert _take_evicted_suppressed_count(config) == 3
    assert _take_evicted_suppressed_count(config) == 0
    assert _take_evicted_suppressed_count(other) == 0


def test_a_table_installed_while_waiting_for_the_lock_is_the_one_served(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = SecurityConfig(enable_redis=False)
    winner = SampledKeys()
    held_reads: list[tuple[object, str]] = []

    def another_thread_won_the_race(config: object, kind: str) -> object:
        held_reads.append((config, kind))
        return winner

    monkeypatch.setattr(sampling, "held_for_app", another_thread_won_the_race)
    per_app = PerApp("wp303", SampledKeys)

    assert per_app.for_app(config) is winner
    assert held_reads == [(config, "sampling:wp303")]
    assert winner not in per_app._tables.values()
