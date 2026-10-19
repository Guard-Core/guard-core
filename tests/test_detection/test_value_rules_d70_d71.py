import pytest

from guard_core.handlers._suspatterns_shell_validators import (
    _shell_token_is_command_with_arguments_or_known,
)
from guard_core.models import SecurityConfig
from guard_core.utils import detect_penetration_attempt
from tests.conftest import MockGuardRequest


async def _categories(value: str, surface: str = "query") -> list[str] | None:
    if surface == "query":
        request = MockGuardRequest(path="/s", query_params={"q": value})
    elif surface == "path":
        request = MockGuardRequest(path=value)
    else:
        raw = f'{{"note": {value!r}}}'.replace("'", '"').encode()
        request = MockGuardRequest(
            method="POST",
            path="/s",
            headers={
                "content-type": "application/json",
                "content-length": str(len(raw)),
            },
            body_content=raw,
        )
    result = await detect_penetration_attempt(
        request, SecurityConfig(enable_redis=False)
    )
    return sorted(result.threat_categories) if result.is_threat else None


NILADIC_FLAGGED = [
    "union select current_user",
    "x union select user",
    "1 union select session_user",
    "1 union select current_timestamp",
    "1 union select localtime",
]
NILADIC_CLEAN = [
    "union select committee",
    "union select",
    "how to union select two tables",
    "union select shelf",
]

COMMAND_SUBSTITUTION_FLAGGED = [
    "$(whoami)",
    "$(WHOAMI)",
    "$(ID)",
    "$(UNAME)",
    "$(pwd)",
    "$(rm)",
    "$(hostname)",
    "$(foo bar)",
    "x=$(id)",
    "echo $(date)",
    "`ls`",
    "`WHOAMI`",
    "`ls -la`",
    "${IFS}",
    "cat${IFS}/etc/passwd",
    "${@}",
    "${x:0:3}",
]
COMMAND_SUBSTITUTION_CLEAN = [
    "Use ${var} in shell scripts",
    "${HOME}/bin",
    "$(CC)",
    "$(RM)",
    "$(PWD)",
    "$(HOSTNAME)",
    "$(AR)",
    "$(CFLAGS)",
    "cc $(CFLAGS) -o x",
    "`CC`",
    "$HOME",
]

BARE_FILE_NAMES_CLEAN = ["setup.py", "main.go", "style.css.map", "app.config.ts"]

KEPT_FLAGGED = [
    "my password is 'secret' and 1=1",
    "cd /usr/local/bin && ls",
]

PATH_VALUES_FLAGGED = [
    "/var/www/app/main.go",
    "/home/user/.ssh/id_rsa",
    "/home/deploy/.bash_history",
    "/etc/hostname",
    "/root/.bashrc",
    "/boot/grub/grub.cfg",
    "/dev/null",
    "/dev/shm/x",
    "/sys/class/net",
    "/var/tmp/x",
    "/var/lib/mysql/x",
    "/usr/bin/python",
    "/opt/app/run.sh",
    "/srv/www/index.html",
    "C:\\Windows\\win.ini",
    "D:\\data\\export.txt",
    "\\\\host\\share\\f",
]
PATH_VALUES_CLEAN = [
    "/home/images/banner.jpg",
    "/home/blog/post.html",
    "/home/dashboard",
    "/opt/app/readme",
    "/dev/foo",
    "/sys/foo",
    "C:\\fakepath\\a.txt",
    "/api/v1/users",
    "/static/css/site.css",
    "images/a.png",
]


@pytest.mark.parametrize("value", NILADIC_FLAGGED)
async def test_a_union_select_of_a_niladic_keyword_is_flagged(value: str) -> None:
    assert await _categories(value) is not None


@pytest.mark.parametrize("value", NILADIC_CLEAN)
async def test_a_union_select_of_a_bare_word_at_the_end_is_not_flagged(
    value: str,
) -> None:
    assert await _categories(value) is None


@pytest.mark.parametrize("value", COMMAND_SUBSTITUTION_FLAGGED)
async def test_command_substitution_with_a_command_arguments_or_ifs_is_flagged(
    value: str,
) -> None:
    assert await _categories(value) is not None


@pytest.mark.parametrize("value", COMMAND_SUBSTITUTION_CLEAN)
async def test_make_variables_and_plain_parameter_expansion_are_not_flagged(
    value: str,
) -> None:
    assert await _categories(value) is None


@pytest.mark.parametrize("value", BARE_FILE_NAMES_CLEAN)
async def test_a_bare_file_name_as_a_value_is_not_a_path_probe(value: str) -> None:
    assert await _categories(value) is None
    assert await _categories(value, "body") is None


@pytest.mark.parametrize("value", ["/setup.py", "/main.go", "/style.css.map"])
async def test_the_same_file_names_as_a_url_path_are_still_probes(value: str) -> None:
    categories = await _categories(value, "path")

    assert categories is not None
    assert "sensitive_file" in categories


@pytest.mark.parametrize("value", KEPT_FLAGGED)
async def test_free_text_that_has_a_sql_or_shell_structure_stays_flagged(
    value: str,
) -> None:
    assert await _categories(value) is not None


@pytest.mark.parametrize("value", PATH_VALUES_FLAGGED)
async def test_an_absolute_filesystem_path_value_is_dir_traversal(value: str) -> None:
    categories = await _categories(value)

    assert categories is not None
    assert "dir_traversal" in categories


@pytest.mark.parametrize("value", PATH_VALUES_CLEAN)
async def test_ordinary_paths_and_the_browser_fakepath_are_not_flagged(
    value: str,
) -> None:
    assert await _categories(value) is None


async def test_a_path_value_is_not_a_url_path_rule() -> None:
    assert await _categories("/usr/bin/python", "path") is None
    assert await _categories("/var/www/app/main.go", "path") is None


async def test_a_wp_config_and_a_settings_file_under_home_keep_their_categories() -> (
    None
):
    assert await _categories("/home/user/public_html/wp-config.php") == [
        "cms_probing",
        "sensitive_file",
    ]
    assert await _categories("/home/user/app/settings.py") == ["sensitive_file"]


@pytest.mark.parametrize(
    "path",
    [
        "/api/x`id`",
        "/a/`whoami`/b",
        "/run/eval(1)",
        "/run/system(x)",
        "/run/exec(x)",
        "/bin/sh -c id",
        "/x/bash -c id",
    ],
)
async def test_command_execution_shapes_in_the_url_path_are_flagged(path: str) -> None:
    categories = await _categories(path, "path")

    assert categories is not None
    assert "cmd_injection" in categories


@pytest.mark.parametrize(
    "path",
    [
        "/fCBuYyAtZSAvYmluL3NoIDEwLjAuMC4xIDQ0NDQ=",
        "/docs/systemd",
        "/blog/evaluate",
        "/exec",
        "/posts/the-sh-command",
        "/shows/sh",
    ],
)
async def test_a_bare_base64_segment_and_ordinary_words_stay_clean_in_the_path(
    path: str,
) -> None:
    assert await _categories(path, "path") is None


@pytest.mark.parametrize("token", ["", "   ", "\t"])
def test_an_empty_token_between_backticks_is_not_a_command(token: str) -> None:
    assert _shell_token_is_command_with_arguments_or_known(token) is False
