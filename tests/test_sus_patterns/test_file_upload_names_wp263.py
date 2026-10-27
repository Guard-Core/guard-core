import pytest

from guard_core.models import SecurityConfig
from guard_core.utils import detect_penetration_attempt
from tests.conftest import MockGuardRequest

_BOUNDARY = "----b"


async def _flagged_as_file_upload(disposition_parameters: str) -> bool:
    body = (
        f"--{_BOUNDARY}\r\n"
        f'Content-Disposition: form-data; name="file"; {disposition_parameters}\r\n'
        "Content-Type: application/octet-stream\r\n\r\nhello\r\n"
        f"--{_BOUNDARY}--\r\n"
    ).encode()
    request = MockGuardRequest(
        method="POST",
        body_content=body,
        headers={
            "content-type": f"multipart/form-data; boundary={_BOUNDARY}",
            "content-length": str(len(body)),
        },
    )
    result = await detect_penetration_attempt(request, SecurityConfig())
    return result.is_threat and "file_upload" in result.threat_categories


@pytest.mark.parametrize(
    "filename",
    [
        "shell.php:$DATA",
        "shell.asp:$DATA",
        "web.config:$DATA",
        "WEB.CONFIG:$data",
        "web.config::$DATA:",
        "web.config:$DATA:",
        "web.config::$INDEX_ALLOCATION",
        "shell.php::$INDEX_ALLOCATION",
        "shell.php::$index_allocation",
        "shell.php::$INDEX_ALLOCATION:",
        "shell.php.jpg:$DATA",
    ],
)
async def test_every_ntfs_default_stream_spelling_is_flagged(filename: str) -> None:
    assert await _flagged_as_file_upload(f'filename="{filename}"')


@pytest.mark.parametrize(
    "filename",
    [
        "shell.php.txt",
        "report:2026.pdf",
        "notes.txt",
        "notes.txt:$DATA",
        "notes.txt::$INDEX_ALLOCATION",
    ],
)
async def test_names_that_stay_benign_after_the_stream_suffix_are_clean(
    filename: str,
) -> None:
    assert not await _flagged_as_file_upload(f'filename="{filename}"')


@pytest.mark.parametrize(
    "parameters",
    [
        "filename=\"ok.txt\"; filename*=UTF-8''shell.php",
        "filename*=UTF-8''shell.php; filename=\"ok.txt\"",
        "filename=\"ok.txt\"; filename*=UTF-8''web.config",
        "filename=\"ok.txt\"; filename*=UTF-8''web.config%3A%3A%24DATA",
        'filename="ok.txt"; filename*0="sh"; filename*1="ell.php"',
        "filename*=UTF-8''shell.php",
        'filename="ok.txt"; filename="shell.php"',
    ],
)
async def test_either_filename_parameter_naming_a_dangerous_file_is_flagged(
    parameters: str,
) -> None:
    assert await _flagged_as_file_upload(parameters)


@pytest.mark.parametrize(
    "parameters",
    [
        "filename=\"ok.txt\"; filename*=UTF-8''report.pdf",
        'filename="ok.txt"',
        "filename*=UTF-8''notes.txt",
    ],
)
async def test_benign_filename_parameters_are_clean(parameters: str) -> None:
    assert not await _flagged_as_file_upload(parameters)
