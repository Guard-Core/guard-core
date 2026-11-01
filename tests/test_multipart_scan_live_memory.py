import random
import tracemalloc
from collections.abc import Callable
from typing import ParamSpec, TypeVar

import pytest

from guard_core._utils import body_content_scan
from guard_core.handlers.suspatterns_handler import sus_patterns_handler
from guard_core.models import SecurityConfig
from guard_core.utils import _scan_request_body, detect_penetration_attempt
from tests.conftest import MockGuardRequest

_ONE_MIB = 1048576
_BOUNDARY = "livememoryboundary"
_LIVE_BUDGET_BYTES = 3 * _ONE_MIB
_PEAK_BUDGET_BYTES = 8 * _ONE_MIB
_P = ParamSpec("_P")
_R = TypeVar("_R")


@pytest.fixture(autouse=True)
def _force_enhanced_detection_singleton() -> None:
    sus_patterns_handler.configure(SecurityConfig())


def _recording_live_memory(
    original: Callable[_P, _R], live: list[int]
) -> Callable[_P, _R]:
    def _spy(*args: _P.args, **kwargs: _P.kwargs) -> _R:
        live.append(tracemalloc.get_traced_memory()[0])
        return original(*args, **kwargs)

    return _spy


def _binary_upload() -> bytes:
    head = (
        f'--{_BOUNDARY}\r\nContent-Disposition: form-data; name="file"; '
        f'filename="upload.dat"\r\nContent-Type: application/octet-stream\r\n\r\n'
    ).encode()
    tail = f"\r\n--{_BOUNDARY}--\r\n".encode()
    blob = random.Random(1).randbytes(_ONE_MIB - len(head) - len(tail))
    return head + blob + tail


def _upload_request() -> MockGuardRequest:
    body = _binary_upload()
    return MockGuardRequest(
        method="POST",
        body_content=body,
        headers={
            "content-type": f"multipart/form-data; boundary={_BOUNDARY}",
            "content-length": str(len(body)),
        },
    )


def _whole_body_config() -> SecurityConfig:
    return SecurityConfig(
        detection_max_file_inspect_bytes=_ONE_MIB,
        detection_max_body_inspect_bytes=_ONE_MIB,
    )


async def test_the_decoded_body_is_released_before_the_multipart_parts_are_scanned(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request = _upload_request()
    config = _whole_body_config()
    live_at_part_scan: list[int] = []
    monkeypatch.setattr(
        body_content_scan,
        "_scan_body_field",
        _recording_live_memory(body_content_scan._scan_body_field, live_at_part_scan),
    )
    tracemalloc.start()
    try:
        result = await detect_penetration_attempt(request, config)
    finally:
        tracemalloc.stop()

    assert not result.is_threat
    assert live_at_part_scan
    assert max(live_at_part_scan) < _LIVE_BUDGET_BYTES


async def test_a_megabyte_binary_upload_peaks_within_a_few_megabytes() -> None:
    request = _upload_request()
    config = _whole_body_config()
    tracemalloc.start()
    try:
        tracemalloc.reset_peak()
        result = await detect_penetration_attempt(request, config)
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()

    assert not result.is_threat
    assert peak < _PEAK_BUDGET_BYTES


def _without_timings(
    result: tuple[bool, str, list[dict]],
) -> tuple[bool, str, list[dict]]:
    detected, trigger, threats = result
    return (
        detected,
        trigger,
        [
            {k: v for k, v in threat.items() if k != "execution_time"}
            for threat in threats
        ],
    )


@pytest.mark.parametrize(
    ("content_type", "body"),
    [
        ("application/json", b'{"q": "<script>alert(1)</script>", "n": "caf\xc3\xa9"}'),
        ("application/x-www-form-urlencoded", b"q=%3Cscript%3Ealert(1)%3C%2Fscript%3E"),
        ("text/plain", b"plain \xff\xfe <script>alert(1)</script>"),
        ("application/json", b'{"clean": "caf\xc3\xa9"}'),
    ],
)
async def test_a_body_given_as_bytes_scans_like_its_decoded_string(
    content_type: str, body: bytes
) -> None:
    decoded = body.decode("utf-8", errors="surrogateescape")

    async def _scan(raw: str | bytes) -> tuple[bool, str, list[dict]]:
        return await _scan_request_body(
            raw, content_type, set(), None, "203.0.113.9", "case", None
        )

    from_bytes = await _scan(body)
    from_text = await _scan(decoded)

    assert _without_timings(from_bytes) == _without_timings(from_text)
