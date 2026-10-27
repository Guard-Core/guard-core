import re
from collections.abc import Generator

import pytest

from guard_core.handlers import _suspatterns_matchers as matchers
from guard_core.handlers.suspatterns_handler import SusPatternsManager
from guard_core.models import SecurityConfig
from guard_core.utils import detect_penetration_attempt
from tests.conftest import MockGuardRequest

_BOUNDARY = "----b"


def _multipart_request(filename: str) -> MockGuardRequest:
    body = (
        f"--{_BOUNDARY}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
        "Content-Type: application/octet-stream\r\n\r\nhello\r\n"
        f"--{_BOUNDARY}--\r\n"
    ).encode()
    return MockGuardRequest(
        method="POST",
        body_content=body,
        headers={
            "content-type": f"multipart/form-data; boundary={_BOUNDARY}",
            "content-length": str(len(body)),
        },
    )


async def _flagged_as_file_upload(filename: str) -> bool:
    result = await detect_penetration_attempt(
        _multipart_request(filename), SecurityConfig()
    )
    return result.is_threat and "file_upload" in result.threat_categories


@pytest.mark.parametrize(
    "filename",
    [
        "web.config",
        "WEB.CONFIG",
        'web"config',
        "web.config.",
        "web.config. . ",
        "Web.Config..",
        "web.config::$DATA",
        "web.config::$data",
        "dir/web.config",
        "..\\web.config",
        ".htaccess",
        "../.htaccess",
        ".htaccess.",
        ".HTACCESS",
        ".htpasswd",
        ".user.ini",
        ".user.ini.",
        ".USER.INI::$DATA",
        "header.inc",
        "header.INC",
        "header.inc.",
        "shell.aspx::$DATA",
        "shell.php::$DATA",
        "shell.aspx. . ",
        "shell.aspx.",
        'shell"php',
        "shell.php.jpg::$DATA",
    ],
)
async def test_server_config_and_stream_spellings_are_flagged(filename: str) -> None:
    assert await _flagged_as_file_upload(filename)


@pytest.mark.parametrize(
    "filename",
    [
        "app.config",
        "nlog.config",
        "nuget.config",
        "App.exe.config",
        "appsettings.json",
        "settings.yaml",
        "shell.inc.jpg",
        "readme.txt",
        "report.pdf",
        "photo.jpg",
        "php.ini",
        "photo.jpg.",
        "notes::draft.txt",
        'a"b',
    ],
)
async def test_benign_names_are_clean(filename: str) -> None:
    assert not await _flagged_as_file_upload(filename)


@pytest.mark.parametrize(
    "filename",
    ["app.js", "script.py", "run.sh", "cert.cer", "notes.com", "foo.htaccess"],
)
async def test_whole_extension_rows_are_unchanged(filename: str) -> None:
    assert await _flagged_as_file_upload(filename)


@pytest.fixture
def manager() -> Generator[SusPatternsManager, None, None]:
    original_instance = SusPatternsManager._instance
    original_config = SusPatternsManager._config
    SusPatternsManager._instance = None
    SusPatternsManager._config = None
    yield SusPatternsManager()
    SusPatternsManager._instance = original_instance
    SusPatternsManager._config = original_config


@pytest.mark.parametrize(
    "payload",
    [
        'filename="a.jpg"x',
        'filename="web"config',
        'filename="a"' + "b" * 300 + '.php"',
    ],
)
async def test_an_unterminated_or_overlong_inner_quote_name_stays_clean(
    manager: SusPatternsManager, payload: str
) -> None:
    result = await manager.detect(payload, "127.0.0.1", context="header")
    assert not result["is_threat"]


@pytest.mark.parametrize(
    ("text", "converted"),
    [
        ('filename="web"config"', 'filename="web.config"'),
        ('filename="shell"php"', 'filename="shell.php"'),
        ('filename="shell"php" filename="a.jpg"', 'filename="shell.php"'),
    ],
)
def test_an_inner_quote_name_spans_the_name_the_regex_accepts_converted(
    text: str, converted: str
) -> None:
    compiled = re.compile(matchers._FILE_UPLOAD_DANGEROUS_EXTENSION_RE, re.IGNORECASE)
    [match] = matchers._file_upload_scan_matches(text, compiled)
    expected = compiled.match(converted)
    assert expected is not None
    assert expected.group() == converted
    assert match.group() == text[: len(converted)]


def test_a_filename_token_inside_an_earlier_matched_span_is_not_matched_again() -> None:
    compiled = re.compile(matchers._FILE_UPLOAD_TRUNCATION_RE, re.IGNORECASE)
    text = 'filename="shell.php;filename="x.php;b"'
    matches = matchers._file_upload_scan_matches(text, compiled)
    assert [m.span() for m in matches] == [(0, 30)]
