import json
from typing import Any

import pytest

from guard_core.handlers.suspatterns_handler import sus_patterns_handler
from guard_core.models import SecurityConfig
from guard_core.utils import detect_penetration_attempt
from tests.conftest import MockGuardRequest

NAMED_FILES = [
    "config/settings.py",
    "settings.py",
    "local_settings.py",
    "config.py",
    "secrets.py",
    "configuration.py",
    "wp-config.php",
    "config.php",
    "configuration.php",
    ".env",
    ".env.example",
    ".env.local",
    ".env.production",
    "src/.env.example",
    "config/database.yml",
    "database.yml",
    "database.yaml",
    "appsettings.json",
    "appsettings.Production.json",
    "config.yml",
    "config.yaml",
    "config.json",
    "config.toml",
    "config.ini",
    "config.xml",
    "config.conf",
    "config.env",
    "tsconfig.json",
    "app-config.yml",
    ".git",
    ".svn",
    ".hg",
    ".bzr",
    "info.php",
    "test.php",
    "phpinfo.php",
    "php_info.php",
    "web.config",
    ".htaccess",
    ".htpasswd",
    "wp-login.php",
    "xmlrpc.php",
]
CHANGE_LISTS = ["added", "removed", "modified"]
PLACES = ["commits", "head_commit"]
NOT_PLAIN_NAMES = [
    "../.env",
    "../config/settings.py",
    "a/../.env",
    "./../.env",
    "%2e%2e/.env",
    "..\\.env",
    "/etc/passwd",
    "/srv/app/.env",
    "/srv/app/config/settings.py",
    ".env?x=1",
    "settings.py/x",
    ".env/x",
    ".env%00.jpg",
    "settings.py;.jpg",
    "wp-config.php%00.jpg",
]
SENTRY_FRAME = {"abs_path": "/srv/app/app/main.py", "lineno": 3, "function": "f"}


@pytest.fixture(autouse=True)
def _force_enhanced_detection_singleton() -> None:
    sus_patterns_handler.configure(SecurityConfig())


def _json(payload: Any) -> MockGuardRequest:
    body = json.dumps(payload).encode()
    return MockGuardRequest(
        path="/webhooks",
        method="POST",
        headers={"content-type": "application/json", "content-length": str(len(body))},
        body_content=body,
    )


async def _is_threat(payload: Any) -> bool:
    config = SecurityConfig(enable_redis=False, rate_limit=10_000_000)
    return (await detect_penetration_attempt(_json(payload), config)).is_threat


def _push(place: str, change_list: str, name: str) -> dict[str, Any]:
    entry = {"id": "a1b2c3", "message": "Fix", change_list: [name]}
    return {"ref": "refs/heads/main", place: [entry] if place == "commits" else entry}


@pytest.mark.parametrize("name", NAMED_FILES)
@pytest.mark.parametrize("change_list", CHANGE_LISTS)
@pytest.mark.parametrize("place", PLACES)
async def test_a_push_change_list_may_name_a_sensitive_file(
    place: str, change_list: str, name: str
) -> None:
    assert await _is_threat(_push(place, change_list, name)) is False


@pytest.mark.parametrize("name", NAMED_FILES)
async def test_the_same_name_outside_a_change_list_is_flagged(name: str) -> None:
    assert await _is_threat({"file": name}) is True
    assert await _is_threat({"commits": [{"note": name}]}) is True
    assert await _is_threat({"commits": [{"added": {"file": name}}]}) is True
    assert await _is_threat({"other": {"added": [name]}}) is True


@pytest.mark.parametrize("name", NOT_PLAIN_NAMES)
@pytest.mark.parametrize("change_list", CHANGE_LISTS)
async def test_a_traversal_an_absolute_path_or_a_trick_stays_flagged_in_a_change_list(
    change_list: str, name: str
) -> None:
    assert await _is_threat(_push("commits", change_list, name)) is True


async def test_a_change_list_with_a_plain_name_and_a_traversal_is_flagged() -> None:
    entry = {"added": [".env.example", "src/app.py", "../.env"], "removed": []}
    assert await _is_threat({"commits": [entry]}) is True


async def test_the_other_shapes_do_not_clear_the_named_file_rows() -> None:
    assert await _is_threat({"filename": ".env", "status": "modified"}) is True
    assert await _is_threat({"path": ".env", "position": 3}) is True
    assert await _is_threat({"frames": [{"filename": ".env", "lineno": 3}]}) is True


async def test_a_sentry_frame_may_carry_an_absolute_path() -> None:
    assert await _is_threat({"frames": [SENTRY_FRAME]}) is False
    assert (
        await _is_threat(
            {"frames": [{"abs_path": SENTRY_FRAME["abs_path"], "function": "f"}]}
        )
        is False
    )


async def test_a_sentry_event_with_filename_and_absolute_path_is_clean() -> None:
    frame = {"filename": "app/main.py", **SENTRY_FRAME}
    event = {"exception": {"values": [{"stacktrace": {"frames": [frame]}}]}}
    assert await _is_threat(event) is False


@pytest.mark.parametrize(
    "path",
    [
        "/srv/app/../../etc/passwd",
        "/srv/app/..%2f..%2fetc/passwd",
        "/etc/passwd",
        "/srv/app/app/main.py;.jpg",
    ],
)
async def test_a_traversal_or_a_trick_in_a_frame_absolute_path_is_flagged(
    path: str,
) -> None:
    assert await _is_threat({"frames": [{"abs_path": path, "lineno": 3}]}) is True


@pytest.mark.parametrize(
    "payload",
    [
        {"abs_path": SENTRY_FRAME["abs_path"], "lineno": 3},
        {"frames": [{"abs_path": SENTRY_FRAME["abs_path"]}]},
        {"stack": [SENTRY_FRAME]},
        {"frames": [{"filename": "/srv/app/app/main.py", "lineno": 3}]},
    ],
)
async def test_an_absolute_path_outside_a_frame_with_a_line_is_flagged(
    payload: Any,
) -> None:
    assert await _is_threat(payload) is True
