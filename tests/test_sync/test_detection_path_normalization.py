from collections.abc import Generator

import pytest

from guard_core.models import SecurityConfig
from guard_core.sync.handlers.suspatterns_handler import SusPatternsManager
from guard_core.sync.utils import detect_penetration_attempt
from tests.test_sync.conftest import SyncMockGuardRequest


@pytest.fixture(autouse=True)
def _reset_suspatterns_singleton() -> Generator[None, None]:
    original_instance = SusPatternsManager._instance
    original_config = SusPatternsManager._config
    SusPatternsManager._instance = None
    SusPatternsManager._config = None
    yield
    SusPatternsManager._instance = original_instance
    SusPatternsManager._config = original_config


def _is_threat(path: str) -> bool:
    config = SecurityConfig(enable_redis=False, enable_penetration_detection=True)
    result = detect_penetration_attempt(SyncMockGuardRequest(path=path), config)
    return result.is_threat


PROBES = ["/.env", "/.git/config", "/wp-admin/setup-config.php", "/actuator/env"]


@pytest.mark.parametrize("probe", PROBES)
@pytest.mark.parametrize("prefix", ["/", "//", "///"])
def test_repeated_leading_slashes_are_flagged_like_single_slash(
    probe: str, prefix: str
) -> None:
    assert _is_threat(prefix + probe[1:]) is True


@pytest.mark.parametrize(
    "path",
    ["/a//.env", "/./.env", "/x/../.env", "/x/./y/../../.env", "//./.env", "/../.env"],
)
def test_dot_and_empty_segments_do_not_hide_a_probe(path: str) -> None:
    assert _is_threat(path) is True


@pytest.mark.parametrize("path", ["/.env/../x", "/.git/config/../x"])
def test_resolving_dot_dot_never_removes_a_flag_the_literal_path_had(
    path: str,
) -> None:
    assert _is_threat(path) is True


@pytest.mark.parametrize("path", ["/", "//", "/api//users", "/a/./b", "/a/../b"])
def test_normal_paths_stay_clean(path: str) -> None:
    assert _is_threat(path) is False
