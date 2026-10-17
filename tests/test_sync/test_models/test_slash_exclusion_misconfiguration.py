import logging
import warnings
from typing import Any

import pytest

from guard_core.models import SecurityConfig
from guard_core.sync.core.validation.path_matching import path_is_excluded

PROBLEM = (
    "exclude_paths entry '/' excludes every check for the whole application, "
    "and guard-core 5.0.0 will make '/' cover only the root page."
)


def _build(**settings: Any) -> SecurityConfig:
    return SecurityConfig(enable_redis=False, **settings)


def test_unset_flag_warns_and_keeps_the_v440_user_warning(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.WARNING, logger="guard_core"):
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            _build(exclude_paths=["/"])

    messages = [(w.category, str(w.message)) for w in caught]
    assert any(
        category is UserWarning
        and "excludes the entire application from all security checks" in text
        for category, text in messages
    )
    assert any(
        category is DeprecationWarning
        and PROBLEM in text
        and "fail_on_misconfiguration=True" in text
        for category, text in messages
    )
    assert any(PROBLEM in r.getMessage() for r in caplog.records)


def test_true_raises() -> None:
    with (
        pytest.warns(UserWarning),
        pytest.raises(ValueError, match="whole application"),
    ):
        _build(fail_on_misconfiguration=True, exclude_paths=["/"])


def test_false_warns_without_the_not_set_part() -> None:
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        _build(fail_on_misconfiguration=False, exclude_paths=["/"])

    texts = [str(w.message) for w in caught if w.category is DeprecationWarning]
    assert any("keeps starting" in text for text in texts)
    assert all("is not set" not in text for text in texts)


def test_the_slash_entry_still_excludes_every_path() -> None:
    assert path_is_excluded("/anything/at/all", ["/"]) is True
    assert path_is_excluded("/", ["/"]) is True


def test_other_entries_do_not_report() -> None:
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        _build(fail_on_misconfiguration=True, exclude_paths=["/health", "/static"])
