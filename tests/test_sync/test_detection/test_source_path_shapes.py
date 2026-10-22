import json
from collections.abc import Callable
from typing import Any

import pytest

from guard_core.models import SecurityConfig
from guard_core.sync._utils.source_path_shapes import BENIGN_SOURCE_PATH_SHAPES
from guard_core.sync.handlers.suspatterns_handler import sus_patterns_handler
from guard_core.sync.utils import detect_penetration_attempt
from tests.test_sync.conftest import SyncMockGuardRequest


@pytest.fixture(autouse=True)
def _force_enhanced_detection_singleton() -> None:
    sus_patterns_handler.configure(SecurityConfig())


def _body(content_type: str, body: bytes) -> SyncMockGuardRequest:
    return SyncMockGuardRequest(
        path="/webhooks",
        method="POST",
        headers={"content-type": content_type, "content-length": str(len(body))},
        body_content=body,
    )


def _json(payload: Any) -> SyncMockGuardRequest:
    return _body("application/json", json.dumps(payload).encode())


def _text(payload: Any) -> SyncMockGuardRequest:
    return _body("text/plain", json.dumps(payload).encode())


def _query(value: str) -> SyncMockGuardRequest:
    return SyncMockGuardRequest(path="/api", query_params={"f": value})


def _is_threat(request: SyncMockGuardRequest) -> bool:
    config = SecurityConfig(enable_redis=False, rate_limit=10_000_000)
    return (detect_penetration_attempt(request, config)).is_threat


def _push(**change_list: list[str]) -> dict[str, Any]:
    commit = {"id": "a1b2c3", "message": "Fix", "added": [], "removed": []}
    commit.update({"modified": [], **change_list})
    return {"ref": "refs/heads/main", "commits": [commit], "head_commit": commit}


REVIEW_COMMENT = {
    "action": "created",
    "comment": {
        "path": "src/app/main.py",
        "diff_hunk": "@@ -1,3 +1,4 @@",
        "position": 3,
        "line": 3,
        "body": "Looks good",
    },
}
PULL_REQUEST_FILES = [
    {
        "sha": "bbcd538c",
        "filename": "setup.py",
        "status": "modified",
        "additions": 1,
        "deletions": 0,
        "changes": 1,
        "patch": "@@ -1 +1,2 @@",
    }
]
STACK_TRACE = {
    "exception": {
        "values": [
            {
                "type": "ValueError",
                "stacktrace": {
                    "frames": [
                        {
                            "function": "main",
                            "filename": "app/main.py",
                            "lineno": 9,
                            "in_app": True,
                        }
                    ]
                },
            }
        ]
    }
}

BENIGN_SHAPES: dict[str, Any] = {
    "push modified source": _push(modified=["src/app/main.py"]),
    "push added typescript": _push(added=["web/index.ts"]),
    "push removed bare name": _push(removed=["main.py"]),
    "push bare shell": _push(added=["run.sh"]),
    "push bare sql": _push(modified=["q.sql"]),
    "review comment": REVIEW_COMMENT,
    "pull request files": PULL_REQUEST_FILES,
    "stack trace": STACK_TRACE,
    "push named files": _push(added=["config/settings.py", ".env.example"]),
    "stack frame with an absolute path": {
        "frames": [
            {
                "filename": "app/main.py",
                "abs_path": "/srv/app/app/main.py",
                "function": "main",
                "lineno": 9,
            }
        ]
    },
}


@pytest.mark.parametrize("shape", sorted(BENIGN_SHAPES))
def test_a_known_benign_shape_is_not_refused(shape: str) -> None:
    assert _is_threat(_json(BENIGN_SHAPES[shape])) is False


SCALARS: dict[str, Any] = {
    "template": {"template": "settings.py"},
    "view": {"view": "app/models.py"},
    "path": {"path": "x.py"},
    "filename": {"filename": "x.py"},
    "page": {"page": "index.php"},
    "path with a foreign sibling": {"path": "x.py", "note": "hi"},
    "added outside a commit": {"added": ["x.py"]},
}


@pytest.mark.parametrize("name", sorted(SCALARS))
def test_a_scalar_path_outside_the_known_shapes_is_still_flagged(
    name: str,
) -> None:
    assert _is_threat(_json(SCALARS[name])) is True


TRICKS: dict[str, Callable[[], dict[str, Any]]] = {
    "push trick suffix": lambda: _push(modified=["src/app/main.php;.jpg"]),
    "push null byte": lambda: _push(modified=["src/app/main.php%00.jpg"]),
    "push path info": lambda: _push(modified=["index.php/x"]),
    "push traversal": lambda: _push(modified=["../../etc/passwd"]),
    "push traversal source": lambda: _push(modified=["../../app/main.py"]),
    "review comment trick": lambda: {
        "path": "main.php;.jpg",
        "diff_hunk": "@@",
        "position": 1,
    },
    "pull request file traversal": lambda: {
        "filename": "../../etc/passwd",
        "status": "added",
        "patch": "@@",
    },
    "frame trick": lambda: {"filename": "main.php%00.jpg", "lineno": 3},
}


@pytest.mark.parametrize("name", sorted(TRICKS))
def test_a_trick_suffix_or_traversal_inside_a_known_shape_is_still_flagged(
    name: str,
) -> None:
    assert _is_threat(_json(TRICKS[name]())) is True


BARE_NAMES = ["index.php", "x.php", "config.inc.php", "app.rb", "run.sh", "q.sql"]
BENIGN_NAMES = ["report.pdf", "photo.jpg"]


@pytest.mark.parametrize("name", BARE_NAMES)
def test_a_bare_script_name_in_a_query_value_is_flagged(name: str) -> None:
    assert _is_threat(_query(name)) is True


@pytest.mark.parametrize("name", BARE_NAMES)
def test_a_bare_script_name_in_a_json_body_field_is_flagged(name: str) -> None:
    assert _is_threat(_json({"f": name})) is True


@pytest.mark.parametrize("name", BENIGN_NAMES)
def test_a_bare_document_or_image_name_stays_clean(name: str) -> None:
    assert _is_threat(_query(name)) is False
    assert _is_threat(_json({"f": name})) is False


@pytest.mark.parametrize("name", BARE_NAMES)
def test_a_bare_script_name_inside_an_undeclared_json_body_stays_clean(
    name: str,
) -> None:
    assert _is_threat(_text({"f": name})) is False
    assert _is_threat(_text(_push(modified=[name]))) is False


@pytest.mark.parametrize("name", ["index.php", "src/app/main.py"])
def test_an_undeclared_body_that_is_one_path_is_flagged_as_in_v440(
    name: str,
) -> None:
    assert _is_threat(_body("text/plain", name.encode())) is True


UNDECLARED_PATH_LEAVES = [
    "/wp-admin/install.php",
    "/var/www/.env",
    "login.asp",
    "credentials",
    "README.md",
]


@pytest.mark.parametrize("leaf", UNDECLARED_PATH_LEAVES)
def test_a_path_leaf_of_an_undeclared_json_body_is_not_judged_as_a_path(
    leaf: str,
) -> None:
    assert _is_threat(_text({"f": leaf})) is False


@pytest.mark.parametrize("leaf", ["/wp-admin/install.php", "/.env", "/var/www/.env"])
def test_a_path_in_json_nested_in_a_json_field_is_flagged_as_in_a_query(
    leaf: str,
) -> None:
    nested = json.dumps({"f": leaf})
    assert _is_threat(_json({"data": nested})) is True
    assert _is_threat(_query(nested)) is True


def test_a_plain_source_path_in_nested_json_stays_clean() -> None:
    nested = json.dumps({"f": "src/app/main.py"})
    assert _is_threat(_json({"data": nested})) is False


def test_an_undeclared_body_leaf_still_gets_the_attack_categories() -> None:
    escaped = {"f": "\\u003cscript\\u003ealert(1)\\u003c/script\\u003e"}
    body = json.dumps({"data": json.dumps(escaped)})
    assert _is_threat(_body("text/plain", body.encode())) is True


def test_a_declared_body_field_exclusion_covers_an_undeclared_walk() -> None:
    payload = {
        "notes": json.dumps({"q": "\\u003cscript\\u003ealert(1)\\u003c/script\\u003e"})
    }
    request = _text(payload)
    config = SecurityConfig(
        enable_redis=False, excluded_detection_body_fields={"notes"}
    )
    assert (detect_penetration_attempt(request, config)).is_threat is False


def test_a_shape_key_with_a_non_text_value_is_not_refused() -> None:
    assert _is_threat(_json({"commits": [{"added": 5}]})) is False
    assert _is_threat(_json({"path": 5, "diff_hunk": "@@", "position": 1})) is False


def test_the_benign_shape_constant_is_pinned() -> None:
    assert [
        (
            shape.name,
            sorted(shape.keys),
            sorted(shape.siblings),
            sorted(shape.containers),
            sorted(shape.grants),
        )
        for shape in BENIGN_SOURCE_PATH_SHAPES
    ] == [
        (
            "push change list",
            ["added", "modified", "removed"],
            [],
            ["commits", "head_commit"],
            ["named_files", "source"],
        ),
        (
            "review comment",
            ["path"],
            ["diff_hunk", "position"],
            [],
            ["named_files", "source"],
        ),
        (
            "pull request file",
            ["filename"],
            ["patch", "status"],
            [],
            ["named_files", "source"],
        ),
        (
            "stack frame",
            ["filename"],
            ["function", "lineno"],
            ["frames"],
            ["named_files", "source"],
        ),
        (
            "stack frame absolute path",
            ["abs_path"],
            ["function", "lineno"],
            ["frames"],
            ["absolute_path", "source"],
        ),
    ]
