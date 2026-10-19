import logging
from typing import Any

import pytest

from guard_core.core.validation.path_matching import path_is_excluded
from guard_core.models import SecurityConfig

PROBLEM = (
    "exclude_paths entry '/' excludes every check for the whole application, "
    "and guard-core 5.0.0 will make '/' cover only the root page."
)


def _build(**settings: Any) -> SecurityConfig:
    return SecurityConfig(enable_redis=False, **settings)


def test_unset_flag_refuses_naming_the_old_value() -> None:
    with pytest.warns(UserWarning), pytest.raises(ValueError) as caught:
        _build(exclude_paths=["/"])

    assert PROBLEM in str(caught.value)
    assert "fail_on_misconfiguration=False" in str(caught.value)


def test_true_raises() -> None:
    with (
        pytest.warns(UserWarning),
        pytest.raises(ValueError, match="whole application"),
    ):
        _build(fail_on_misconfiguration=True, exclude_paths=["/"])


def test_false_logs_one_warning_and_keeps_the_v440_user_warning(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.WARNING, logger="guard_core"):
        with pytest.warns(UserWarning, match="excludes the entire application"):
            _build(fail_on_misconfiguration=False, exclude_paths=["/"])

    messages = [r.getMessage() for r in caplog.records if PROBLEM in r.getMessage()]
    assert len(messages) == 1
    assert "keeps starting" in messages[0]


def test_the_slash_entry_still_excludes_every_path() -> None:
    assert path_is_excluded("/anything/at/all", ["/"]) is True
    assert path_is_excluded("/", ["/"]) is True


def test_other_entries_do_not_report() -> None:
    import warnings

    with warnings.catch_warnings():
        warnings.simplefilter("error")
        _build(fail_on_misconfiguration=True, exclude_paths=["/health", "/static"])
