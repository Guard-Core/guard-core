import logging
import warnings
from collections.abc import Generator
from typing import Any

import pytest

from guard_core import _staged_defaults
from guard_core.models import SyncSecurityConfig
from guard_core.sync._utils.sampling import PerApp, WarnedKeys
from guard_core.sync.core.initialization.handler_initializer import HandlerInitializer

MARKER = "guard-core 5.0.0 changed defaults"

RESTORE_LINES = {
    "ban_on_hostile_signals": "ban_on_hostile_signals=False",
    "fail_on_misconfiguration": "fail_on_misconfiguration=False",
    "rate_limit": "rate_limit=10",
    "whitelist_access_only": "whitelist_access_only=False",
    "enable_redis": "enable_redis=True",
}

EXPLICIT = {
    "ban_on_hostile_signals": True,
    "fail_on_misconfiguration": True,
    "rate_limit": 120,
    "whitelist_access_only": True,
    "enable_redis": False,
}


@pytest.fixture(autouse=True)
def _signal_not_yet_logged(
    monkeypatch: pytest.MonkeyPatch,
) -> Generator[None, None, None]:
    monkeypatch.setattr(
        _staged_defaults,
        "_changed_defaults_logged",
        PerApp("changed_defaults", WarnedKeys),
        raising=False,
    )
    yield


def _signals(caplog: pytest.LogCaptureFixture) -> list[str]:
    return [r.getMessage() for r in caplog.records if MARKER in r.getMessage()]


def _build(caplog: pytest.LogCaptureFixture, **settings: Any) -> list[str]:
    with caplog.at_level(logging.WARNING, logger="guard_core"):
        with warnings.catch_warnings():
            warnings.simplefilter("error")
            SyncSecurityConfig(**settings)
    return _signals(caplog)


def test_every_unset_flip_is_listed_once_with_its_restore_line(
    caplog: pytest.LogCaptureFixture,
) -> None:
    signals = _build(caplog, whitelist=["203.0.113.5"])

    assert len(signals) == 1
    for line in RESTORE_LINES.values():
        assert line in signals[0]


@pytest.mark.parametrize(("name", "value"), EXPLICIT.items())
def test_a_stated_setting_leaves_its_flip_out(
    name: str, value: Any, caplog: pytest.LogCaptureFixture
) -> None:
    signals = _build(caplog, whitelist=["203.0.113.5"], **{name: value})

    assert len(signals) == 1
    assert RESTORE_LINES[name] not in signals[0]
    for other, line in RESTORE_LINES.items():
        if other != name:
            assert line in signals[0]


def test_a_config_that_states_everything_logs_nothing(
    caplog: pytest.LogCaptureFixture,
) -> None:
    assert _build(caplog, whitelist=["203.0.113.5"], **EXPLICIT) == []


def test_the_rate_limit_flip_needs_rate_limiting_on(
    caplog: pytest.LogCaptureFixture,
) -> None:
    signals = _build(caplog, enable_rate_limiting=False)

    assert "rate_limit=10" not in signals[0]


def test_the_whitelist_flip_needs_a_whitelist(
    caplog: pytest.LogCaptureFixture,
) -> None:
    signals = _build(caplog)

    assert "whitelist_access_only" not in signals[0]


def test_the_signal_names_the_field_that_kept_redis_on(
    caplog: pytest.LogCaptureFixture,
) -> None:
    signals = _build(caplog, redis_prefix="app:")

    assert "redis_prefix" in signals[0]
    assert "enable_redis=True" in signals[0]


def test_a_slash_entry_is_listed_while_exclude_all_paths_is_unset(
    caplog: pytest.LogCaptureFixture,
) -> None:
    signals = _build(caplog, exclude_paths=["/"])

    assert "exclude_paths" in signals[0]
    assert "exclude_all_paths=True" in signals[0]


def test_a_stated_exclude_all_paths_leaves_the_slash_entry_out(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.WARNING, logger="guard_core"):
        SyncSecurityConfig(exclude_paths=["/"], exclude_all_paths=False)

    assert "exclude_all_paths=True" not in _signals(caplog)[0]


def test_each_flip_is_logged_once_per_app(
    caplog: pytest.LogCaptureFixture,
) -> None:
    first = _build(caplog)
    second = _build(caplog)

    assert len(first) == 1
    assert second == first * 2


def _logging(caplog: pytest.LogCaptureFixture) -> Any:
    return caplog.at_level(logging.WARNING, logger="guard_core")


def test_a_later_flip_is_logged_alone_on_assignment_and_not_again_at_bind(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with _logging(caplog):
        config = SyncSecurityConfig(
            enable_redis=False, enable_rate_limiting=False, lazy_init=False
        )
        [first] = _signals(caplog)
        assert RESTORE_LINES["ban_on_hostile_signals"] in first
        assert RESTORE_LINES["fail_on_misconfiguration"] in first
        assert "whitelist_access_only" not in first

        config.whitelist = ("203.0.113.5",)
        HandlerInitializer(config=config).initialize_redis_handlers()
        HandlerInitializer(config=config).initialize_redis_handlers()

    [_, second] = _signals(caplog)
    assert RESTORE_LINES["whitelist_access_only"] in second
    assert RESTORE_LINES["ban_on_hostile_signals"] not in second
    assert RESTORE_LINES["fail_on_misconfiguration"] not in second


def test_a_slash_entry_assigned_after_bind_is_logged_once(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with _logging(caplog):
        config = SyncSecurityConfig(enable_redis=False, lazy_init=False)
        HandlerInitializer(config=config).initialize_redis_handlers()
        before = len(_signals(caplog))

        config.exclude_paths = ["/"]
        config.exclude_paths = ["/", "/health"]

    fresh = _signals(caplog)[before:]
    assert len(fresh) == 1
    assert "exclude_all_paths=True" in fresh[0]
    assert "ban_on_hostile_signals" not in fresh[0]


def test_a_stated_trigger_assignment_logs_nothing_new(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = SyncSecurityConfig(**EXPLICIT, whitelist=["203.0.113.5"])

    with _logging(caplog):
        config.rate_limit = 5
        config.whitelist_access_only = False
        config.enable_rate_limiting = True

    assert _signals(caplog) == []


def test_the_redis_flip_keeps_one_id_for_its_two_texts(
    caplog: pytest.LogCaptureFixture,
) -> None:
    stated = {k: v for k, v in EXPLICIT.items() if k != "enable_redis"}
    with _logging(caplog):
        config = SyncSecurityConfig(**stated)
        [first] = _signals(caplog)
        config.redis_prefix = "app:"

    assert "enable_redis is now off" in first
    assert config.enable_redis is True
    assert len(_signals(caplog)) == 1
