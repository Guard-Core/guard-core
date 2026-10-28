from guard_core.models import SyncSecurityConfig
from guard_core.sync._utils.body_form_scan import (
    _multipart_part_entries,
    _multipart_text_parts,
)
from guard_core.sync.utils import detect_penetration_attempt
from tests.test_sync.conftest import SyncMockGuardRequest

_CONTENT_TYPE_MULTIPART = "multipart/form-data; boundary=B0"
_XSS = "<script>alert(1)</script>"


def _multipart_request(body: bytes) -> SyncMockGuardRequest:
    return SyncMockGuardRequest(
        method="POST",
        client_host="127.0.0.1",
        body_content=body,
        headers={
            "content-type": _CONTENT_TYPE_MULTIPART,
            "content-length": str(len(body)),
        },
    )


def _file_part_body(filename: str, content: str = "binary-file-payload") -> bytes:
    return (
        f'--B0\r\nContent-Disposition: form-data; name="upload"; '
        f'filename="{filename}"\r\n\r\n{content}\r\n--B0--\r\n'
    ).encode()


def _text_part_body(name: str, value: str) -> bytes:
    return (
        f'--B0\r\nContent-Disposition: form-data; name="{name}"\r\n\r\n'
        f"{value}\r\n--B0--\r\n"
    ).encode()


def test_filename_with_semicolon_and_single_quote_still_detected() -> None:
    filename = f"filename=\"x=1;NOTE:'benign {_XSS}';y=2\""
    request = _multipart_request(_file_part_body(filename))

    result = detect_penetration_attempt(request, SyncSecurityConfig())

    assert result.is_threat is True


def test_filename_with_pct_encoded_equals_and_semicolon_still_detected() -> None:
    filename = 'filename%3D"x%3D1;cookie: "benign ' + _XSS + '";y%3D2"'
    request = _multipart_request(_file_part_body(filename))

    result = detect_penetration_attempt(request, SyncSecurityConfig())

    assert result.is_threat is True


def test_filename_with_bare_newline_still_detected() -> None:
    filename = f"benign {_XSS}\nx=1\ny=2"
    request = _multipart_request(_file_part_body(filename))

    result = detect_penetration_attempt(request, SyncSecurityConfig())

    assert result.is_threat is True


def test_filename_with_bare_cr_smuggled_header_payload_still_detected() -> None:
    filename = f"x=1\rcustom-secret-field: '{_XSS}'\ry=2"
    request = _multipart_request(_file_part_body(filename))

    result = detect_penetration_attempt(request, SyncSecurityConfig())

    assert result.is_threat is True


def test_well_formed_dangerous_filename_still_detected() -> None:
    request = _multipart_request(_file_part_body("shell.php"))

    result = detect_penetration_attempt(request, SyncSecurityConfig())

    assert result.is_threat is True


def test_well_formed_benign_filename_not_detected() -> None:
    request = _multipart_request(_file_part_body("report.pdf"))

    result = detect_penetration_attempt(request, SyncSecurityConfig())

    assert result.is_threat is False


def test_text_field_without_filename_still_detected_via_payload() -> None:
    request = _multipart_request(_text_part_body("note", _XSS))

    result = detect_penetration_attempt(request, SyncSecurityConfig())

    assert result.is_threat is True


def test_multipart_part_entries_adds_raw_content_disposition_with_filename() -> None:
    body = _file_part_body("report.pdf").decode()
    parts = _multipart_text_parts(body, _CONTENT_TYPE_MULTIPART)

    assert parts is not None
    values = [value for _key, _label, value in parts]
    assert 'filename="report.pdf"' in values
    assert any(
        value.startswith("Content-Disposition:") and "report.pdf" in value
        for value in values
    )
    assert "binary-file-payload" in values


def test_multipart_part_entries_scans_content_disposition_without_filename() -> None:
    body = _text_part_body("note", "hello").decode()
    parts = _multipart_text_parts(body, _CONTENT_TYPE_MULTIPART)

    assert parts == [
        ("note", "note", 'Content-Disposition: form-data; name="note"'),
        ("note", "note", "hello"),
    ]


class _FakePart:
    def __init__(
        self,
        name: str | None,
        filename: str | None,
        headers: list[tuple[str, str]] | None = None,
        params: list[tuple[str, str]] | None = None,
        has_disposition: bool = True,
    ) -> None:
        self._params = (params or []) if has_disposition else None
        self._name = name
        self._filename = filename
        self._headers = headers or []
        self._payload = "payload-text-sample"

    def get_param(self, key: str, header: str) -> str | None:
        assert key == "name"
        assert header == "content-disposition"
        return self._name

    def get_filename(self) -> str | None:
        return self._filename

    def get_params(self, header: str) -> list[tuple[str, str]] | None:
        assert header == "content-disposition"
        return self._params

    def items(self) -> list[tuple[str, str]]:
        return self._headers


def test_multipart_part_entries_skips_raw_lines_when_part_has_no_headers() -> None:
    part = _FakePart(name="upload", filename="report.pdf")

    entries = _multipart_part_entries(part)

    assert entries == [
        ("upload", "upload", 'filename="report.pdf"'),
        ("upload", "upload", "payload-text-sample"),
    ]


def test_multipart_part_entries_falls_back_to_file_label_without_name() -> None:
    part = _FakePart(name=None, filename="report.pdf")

    entries = _multipart_part_entries(part)

    assert entries[0] == (None, "file", 'filename="report.pdf"')


def test_multipart_part_entries_includes_every_part_header() -> None:
    part = _FakePart(
        name="upload",
        filename="report.pdf",
        headers=[
            ("Content-Disposition", 'form-data; name="upload"; filename="report.pdf"'),
            ("Custom-Secret-Field", "' OR 1=1--"),
        ],
    )

    entries = _multipart_part_entries(part)

    assert entries == [
        ("upload", "upload", 'filename="report.pdf"'),
        (
            "upload",
            "upload",
            'Content-Disposition: form-data; name="upload"; filename="report.pdf"',
        ),
        ("upload", "upload", "Custom-Secret-Field: ' OR 1=1--"),
        ("upload", "upload", "payload-text-sample"),
    ]


def test_multipart_part_entries_emit_every_filename_parameter_once() -> None:
    part = _FakePart(
        name="upload",
        filename="ok.txt",
        headers=[
            (
                "Content-Disposition",
                'form-data; name="upload"; filename="ok.txt"; filename="shell.php"',
            )
        ],
        params=[
            ("name", "upload"),
            ("filename", "ok.txt"),
            ("filename", "shell.php"),
            ("filename", "shell.php"),
        ],
    )

    entries = _multipart_part_entries(part)

    assert [entry[2] for entry in entries[:2]] == [
        'filename="ok.txt"',
        'filename="shell.php"',
    ]
    assert len(entries) == 4


def test_multipart_part_entries_skip_parameter_parsing_for_one_plain_filename() -> None:
    part = _FakePart(
        name="upload",
        filename="ok.txt",
        headers=[
            ("Content-Disposition", 'form-data; name="upload"; filename="ok.txt"')
        ],
        params=[("filename", "never-read.php")],
    )

    entries = _multipart_part_entries(part)

    assert [entry[2] for entry in entries if entry[2].startswith("filename=")] == [
        'filename="ok.txt"'
    ]


def test_multipart_part_entries_tolerate_a_part_without_a_disposition() -> None:
    part = _FakePart(name=None, filename=None, has_disposition=False)
    assert _multipart_part_entries(part) == [(None, "file", "payload-text-sample")]
