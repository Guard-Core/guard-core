import inspect
import warnings
from pathlib import Path
from typing import Any, cast

import pytest

from guard_core.core.validation.path_matching import path_is_excluded
from guard_core.models import SecurityConfig

DEGENERATE_TO_ROOT_ENTRIES = ["", "//", ".", "..", "%2f", "\\", "%2e%2e", "//../"]


def _current_lineno() -> int:
    frame = inspect.currentframe()
    assert frame is not None
    caller = frame.f_back
    assert caller is not None
    return caller.f_lineno


def test_exclude_paths_default_list_is_accepted_without_warning() -> None:
    with warnings.catch_warnings(record=True) as records:
        warnings.simplefilter("always")
        config = SecurityConfig()
    assert config.exclude_paths == [
        "/docs",
        "/redoc",
        "/openapi.json",
        "/openapi.yaml",
        "/favicon.ico",
        "/static",
    ]
    assert records == []


@pytest.mark.parametrize("entry", DEGENERATE_TO_ROOT_ENTRIES)
def test_exclude_paths_rejects_entries_that_normalize_to_root(entry: str) -> None:
    with pytest.raises(ValueError) as exc:
        SecurityConfig(exclude_paths=[entry])
    msg = str(exc.value)
    assert repr(entry) in msg
    assert "root" in msg


def test_exclude_paths_rejects_root_entry_alongside_valid_entries() -> None:
    with pytest.raises(ValueError) as exc:
        SecurityConfig(exclude_paths=["/static", "..", "/docs"])
    assert repr("..") in str(exc.value)


def test_exclude_paths_accepts_literal_root_with_loud_warning() -> None:
    with pytest.warns(UserWarning, match="excludes the entire application"):
        config = SecurityConfig(exclude_paths=["/"])
    assert config.exclude_paths == ["/"]


def test_exclude_paths_construction_warning_points_at_constructor_call_site() -> None:
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        expected_lineno = _current_lineno() + 1
        SecurityConfig(exclude_paths=["/"])

    matches = [w for w in caught if "excludes the entire application" in str(w.message)]
    assert len(matches) == 1
    assert Path(matches[0].filename).name == Path(__file__).name
    assert matches[0].lineno == expected_lineno


def test_exclude_paths_rejects_entry_that_fails_to_normalize() -> None:
    unresolvable = "%c0%af"
    with pytest.raises(ValueError) as exc:
        SecurityConfig(exclude_paths=[unresolvable])
    msg = str(exc.value)
    assert unresolvable in msg
    assert "could not be normalized" in msg


def test_exclude_paths_accepts_ordinary_entries_without_warning() -> None:
    with warnings.catch_warnings(record=True) as records:
        warnings.simplefilter("always")
        config = SecurityConfig(exclude_paths=["/static", "/docs", "health"])
    assert config.exclude_paths == ["/static", "/docs", "health"]
    assert records == []


@pytest.mark.parametrize("entry", DEGENERATE_TO_ROOT_ENTRIES)
def test_exclude_paths_runtime_assignment_rejects_entries_that_normalize_to_root(
    entry: str,
) -> None:
    config = SecurityConfig(exclude_paths=["/healthz"])

    with pytest.raises(ValueError) as exc:
        config.exclude_paths = [entry]

    msg = str(exc.value)
    assert repr(entry) in msg
    assert "root" in msg


def test_exclude_paths_runtime_assignment_rejects_entry_that_fails_to_normalize() -> (
    None
):
    config = SecurityConfig(exclude_paths=["/healthz"])
    unresolvable = "%c0%af"

    with pytest.raises(ValueError) as exc:
        config.exclude_paths = [unresolvable]

    msg = str(exc.value)
    assert unresolvable in msg
    assert "could not be normalized" in msg


def test_exclude_paths_runtime_rejection_leaves_field_and_revision_unchanged() -> None:
    config = SecurityConfig(exclude_paths=["/healthz"])
    revision_before = config.revision

    with pytest.raises(ValueError):
        config.exclude_paths = [""]

    assert config.exclude_paths == ["/healthz"]
    assert config.revision == revision_before


def test_exclude_paths_runtime_assignment_accepts_literal_root_with_loud_warning() -> (
    None
):
    config = SecurityConfig(exclude_paths=["/healthz"])

    with pytest.warns(UserWarning, match="excludes the entire application"):
        config.exclude_paths = ["/"]

    assert config.exclude_paths == ["/"]


def test_exclude_paths_runtime_assignment_warning_points_at_assignment_site() -> None:
    config = SecurityConfig(exclude_paths=["/healthz"])

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        expected_lineno = _current_lineno() + 1
        config.exclude_paths = ["/"]

    matches = [w for w in caught if "excludes the entire application" in str(w.message)]
    assert len(matches) == 1
    assert Path(matches[0].filename).name == Path(__file__).name
    assert matches[0].lineno == expected_lineno


def test_exclude_paths_runtime_assignment_rejects_bare_string() -> None:
    config = SecurityConfig(exclude_paths=["/healthz"])

    with pytest.raises(ValueError, match="exclude_paths must be a list of str"):
        cast(Any, config).exclude_paths = "not-a-list"

    assert config.exclude_paths == ["/healthz"]


def test_exclude_paths_runtime_assignment_accepts_valid_value_and_bumps_revision() -> (
    None
):
    config = SecurityConfig(exclude_paths=["/healthz"])
    revision_before = config.revision

    config.exclude_paths = ["/healthz", "/metrics"]

    assert config.exclude_paths == ["/healthz", "/metrics"]
    assert config.revision == revision_before + 1


def test_exclude_paths_runtime_assignment_bypass_no_longer_excludes_every_path() -> (
    None
):
    config = SecurityConfig(exclude_paths=["/healthz"])

    with pytest.raises(ValueError):
        config.exclude_paths = [""]

    assert path_is_excluded("/admin/panel", config.exclude_paths) is False


def test_model_copy_update_rejects_entries_that_normalize_to_root() -> None:
    base = SecurityConfig(exclude_paths=["/healthz"])

    with pytest.raises(ValueError) as exc:
        base.model_copy(update={"exclude_paths": [""]})

    msg = str(exc.value)
    assert repr("") in msg
    assert "root" in msg
    assert base.exclude_paths == ["/healthz"]


def test_model_copy_update_accepts_literal_root_with_loud_warning() -> None:
    base = SecurityConfig(exclude_paths=["/healthz"])

    with pytest.warns(UserWarning, match="excludes the entire application"):
        copied = base.model_copy(update={"exclude_paths": ["/"]})

    assert copied.exclude_paths == ["/"]


def test_model_copy_update_warning_points_at_call_site() -> None:
    base = SecurityConfig(exclude_paths=["/healthz"])

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        expected_lineno = _current_lineno() + 1
        base.model_copy(update={"exclude_paths": ["/"]})

    matches = [w for w in caught if "excludes the entire application" in str(w.message)]
    assert len(matches) == 1
    assert Path(matches[0].filename).name == Path(__file__).name
    assert matches[0].lineno == expected_lineno


def test_model_copy_update_without_exclude_paths_skips_revalidation() -> None:
    base = SecurityConfig(exclude_paths=["/healthz"])

    copied = base.model_copy(update={"rate_limit": 999})

    assert copied.rate_limit == 999
    assert copied.exclude_paths == ["/healthz"]


def test_model_copy_with_no_update_returns_valid_copy() -> None:
    base = SecurityConfig(exclude_paths=["/healthz"])

    copied = base.model_copy()

    assert copied.exclude_paths == ["/healthz"]
    assert copied is not base


def test_model_copy_update_accepts_valid_exclude_paths() -> None:
    base = SecurityConfig(exclude_paths=["/healthz"])

    copied = base.model_copy(update={"exclude_paths": ["/healthz", "/metrics"]})

    assert copied.exclude_paths == ["/healthz", "/metrics"]


def test_country_field_assignment_is_unaffected_by_exclude_paths_setattr_branch(
    tmp_path: Path,
) -> None:
    from guard_core.handlers.ipinfo_handler import IPInfoManager

    geo_ip_handler = IPInfoManager(token="dummy", db_path=tmp_path / "country_asn.mmdb")
    config = SecurityConfig(
        whitelist_countries=["US"],
        geo_ip_handler=geo_ip_handler,
        exclude_paths=["/healthz"],
    )
    revision_before = config.revision

    with pytest.warns(UserWarning, match="blocked_countries is ignored"):
        config.blocked_countries = frozenset({"CN"})

    assert config.blocked_countries == frozenset({"CN"})
    assert config.exclude_paths == ["/healthz"]
    assert config.revision == revision_before + 1
