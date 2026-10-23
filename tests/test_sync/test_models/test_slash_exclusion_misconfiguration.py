import warnings
from typing import Any

from guard_core.models import SyncSecurityConfig
from guard_core.sync.core.validation.path_matching import path_is_excluded


def _build(**settings: Any) -> SyncSecurityConfig:
    return SyncSecurityConfig(enable_redis=False, **settings)


def test_the_slash_entry_is_accepted_without_any_flag_or_warning() -> None:
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        for flag in ({}, {"fail_on_misconfiguration": True}):
            config = _build(exclude_paths=["/"], **flag)
            assert config.exclude_paths == ["/"]


def test_the_slash_entry_excludes_only_the_root_page() -> None:
    assert path_is_excluded("/anything/at/all", ["/"]) is False
    assert path_is_excluded("/", ["/"]) is True


def test_other_entries_do_not_report() -> None:
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        _build(fail_on_misconfiguration=True, exclude_paths=["/health", "/static"])
