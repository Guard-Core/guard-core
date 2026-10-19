import pytest

from guard_core._utils.route_gate import route_knowledge
from guard_core.handlers.suspatterns_handler import sus_patterns_handler

SENSITIVE_FILE_PATHS_FLAGGED = [
    pytest.param("/.env", id="dotenv_root"),
    pytest.param("/.env.production", id="dotenv_environment_suffix"),
    pytest.param("/api/.env", id="dotenv_nested"),
    pytest.param("/config.yml", id="config_yml"),
    pytest.param("/nested/path/db-config.json", id="config_json_nested"),
    pytest.param("/config.yml?download=1", id="config_yml_with_query"),
    pytest.param("/bundle.js.map", id="sourcemap"),
    pytest.param("/app/settings.py", id="python_source"),
    pytest.param("/app/settings.py?debug=1", id="python_source_with_query"),
    pytest.param("/handler.go", id="go_source_root"),
    pytest.param("/deploy.sh", id="shell_script"),
    pytest.param("/migrate.sql", id="sql_script"),
    pytest.param("/.git/config", id="git_dir"),
    pytest.param("/.svn/entries", id="svn_dir"),
    pytest.param("/.hg/store", id="hg_dir"),
    pytest.param("/.bzr/README", id="bzr_dir"),
]

NESTED_SOURCE_PATHS_NOT_PROBES = [
    pytest.param("/static/bundle.js.map", id="sourcemap_nested"),
    pytest.param("/services/payments/handler.go", id="go_source_nested"),
    pytest.param("/scripts/deploy.sh", id="shell_script_nested"),
    pytest.param("/db/migrate.sql", id="sql_script_nested"),
]

MULTILINE_CONTENT_WITH_EMBEDDED_PATH_NOT_FLAGGED = [
    pytest.param(
        "diff --git a/src/utils.py b/src/utils.py\n--- a/src/utils.py\n"
        "+++ b/src/utils.py\n@@ -10,7 +10,7 @@ def parse(x):\n"
        "-    return x.strip()\n+    return x.strip().lower()",
        id="git_diff_ending_in_python_source",
    ),
    pytest.param(
        "Copy the template to config/.env\nRestart the service to pick up changes.",
        id="prose_line_ending_in_dotenv",
    ),
    pytest.param(
        "See infra/app-config.yml\nfor the full list of settings.",
        id="prose_line_ending_in_config_yml",
    ),
    pytest.param(
        "Uploaded dist/bundle.js.map\nto the CDN yesterday.",
        id="prose_line_ending_in_sourcemap",
    ),
    pytest.param(
        "Run the migration via scripts/migrate.sql\nthen verify the schema version.",
        id="prose_line_ending_in_sql_source",
    ),
    pytest.param(
        "Cloned the repo into /tmp/build/.git\nthen ran the test suite.",
        id="prose_line_ending_in_git_dir",
    ),
]


@pytest.mark.asyncio
@pytest.mark.parametrize("payload", SENSITIVE_FILE_PATHS_FLAGGED)
async def test_sensitive_file_path_flagged(payload: str) -> None:
    result = await sus_patterns_handler.detect(
        content=payload, ip_address="203.0.113.9", context="request_body"
    )
    assert result["is_threat"] is True
    assert any(
        threat.get("category") == "sensitive_file" for threat in result["threats"]
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("payload", NESTED_SOURCE_PATHS_NOT_PROBES)
async def test_nested_source_path_is_not_a_probe_when_the_app_declares_it(
    payload: str,
) -> None:
    # D-75: a nested script path is flagged by default and clean when the matched
    # route template literally contains the file extension. A nested source map
    # has no extension row and stays clean (opt-in return_pattern status:404).
    with route_knowledge(payload):
        result = await sus_patterns_handler.detect(
            content=payload, ip_address="203.0.113.9", context="url_path"
        )
    assert result["is_threat"] is False


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "payload",
    [case for case in NESTED_SOURCE_PATHS_NOT_PROBES if "map" not in str(case.id)],
)
@pytest.mark.parametrize("template", [None, "/{page:path}", "/api/{name}"])
async def test_nested_source_path_without_its_own_route_is_flagged_as_in_v440(
    payload: str, template: str | None
) -> None:
    with route_knowledge(template):
        result = await sus_patterns_handler.detect(
            content=payload, ip_address="203.0.113.9", context="url_path"
        )
    assert result["is_threat"] is True


@pytest.mark.asyncio
@pytest.mark.parametrize("payload", MULTILINE_CONTENT_WITH_EMBEDDED_PATH_NOT_FLAGGED)
async def test_multiline_content_with_embedded_path_not_flagged(payload: str) -> None:
    result = await sus_patterns_handler.detect(
        content=payload, ip_address="198.51.100.4", context="request_body"
    )
    assert result["is_threat"] is False
