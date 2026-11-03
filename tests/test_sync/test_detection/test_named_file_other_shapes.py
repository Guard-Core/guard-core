import json
from collections.abc import Callable
from typing import Any

import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.sync.handlers.suspatterns_handler import sus_patterns_handler
from guard_core.sync.utils import detect_penetration_attempt
from tests.test_sync.conftest import SyncMockGuardRequest

_SHAPES: dict[str, Callable[[str], Any]] = {
    "review comment": lambda name: {
        "path": name,
        "diff_hunk": "@@ -1 +1 @@",
        "position": 3,
    },
    "pull request file": lambda name: {
        "filename": name,
        "status": "modified",
        "patch": "@@ -1 +1 @@",
    },
    "stack frame": lambda name: {
        "frames": [{"filename": name, "lineno": 3, "function": "f"}]
    },
}
_PLAIN_NAMES = [".env", ".env.example", "config/settings.py", "tsconfig.json"]
_NOT_PLAIN_NAMES = ["../.env", "/etc/passwd", ".env?x=1", ".env%00.jpg", ".env/x"]
_PUSH_NAMES = [
    "wp-admin/index.php",
    "wp-content/plugins/x/y.php",
    "administrator/index.php",
    "foo.py~",
    "src/foo.py~",
    "foo.py.swp",
    "foo.py.bak",
]
_PUSH_NOT_PLAIN = [
    "wp-admin/../x.php",
    "/wp-admin/index.php",
    "wp-admin/x?y=1",
    "wp-admin/%2e%2e/x",
    "../foo.py~",
    "foo.py~?x=1",
]


@pytest.fixture(autouse=True)
def _force_enhanced_detection_singleton() -> None:
    sus_patterns_handler.configure(SyncSecurityConfig())


def _is_threat(payload: object) -> bool:
    body = json.dumps(payload).encode()
    request = SyncMockGuardRequest(
        path="/webhooks",
        method="POST",
        headers={"content-type": "application/json", "content-length": str(len(body))},
        body_content=body,
    )
    config = SyncSecurityConfig(enable_redis=False, rate_limit=10_000_000)
    return (detect_penetration_attempt(request, config)).is_threat


@pytest.mark.parametrize("name", _PLAIN_NAMES)
@pytest.mark.parametrize("shape", _SHAPES)
def test_a_plain_name_in_another_shape_is_cleared(shape: str, name: str) -> None:
    assert _is_threat(_SHAPES[shape](name)) is False


@pytest.mark.parametrize("name", _PLAIN_NAMES)
def test_the_same_names_as_scalars_or_under_another_key_are_flagged(
    name: str,
) -> None:
    assert _is_threat({"file": name}) is True
    assert _is_threat({"other": name, "diff_hunk": "x", "position": 1}) is True
    assert _is_threat({"other": name, "status": "modified", "patch": "x"}) is True
    assert _is_threat({"frames": [{"other": name, "lineno": 3}]}) is True


@pytest.mark.parametrize("name", _NOT_PLAIN_NAMES)
@pytest.mark.parametrize("shape", _SHAPES)
def test_a_traversal_an_absolute_path_or_a_trick_stays_flagged_in_the_shape(
    shape: str, name: str
) -> None:
    assert _is_threat(_SHAPES[shape](name)) is True


@pytest.mark.parametrize("name", _PUSH_NAMES)
def test_a_push_list_may_name_a_directory_row_file_or_an_editor_backup(
    name: str,
) -> None:
    assert _is_threat({"commits": [{"added": [name]}]}) is False
    assert _is_threat({"head_commit": {"modified": [name]}}) is False
    assert _is_threat({"file": name}) is True
    assert _is_threat({"other": {"added": [name]}}) is True


@pytest.mark.parametrize("name", _PUSH_NOT_PLAIN)
def test_a_traversal_a_query_or_an_absolute_path_stays_flagged_in_a_push_list(
    name: str,
) -> None:
    assert _is_threat({"commits": [{"added": [name]}]}) is True


def test_a_push_list_with_a_plain_name_and_a_traversal_is_flagged() -> None:
    entry = {"added": ["wp-admin/index.php", "foo.py~", "../foo.py~"]}
    assert _is_threat({"commits": [entry]}) is True
