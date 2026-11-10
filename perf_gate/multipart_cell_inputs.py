"""The framework-free parts of the multipart upload cells (body shapes, settings,
refusal counts), in their own module so mypy checks them and the tests import
them without the web frameworks `multipart_cells` needs."""

import random
from collections.abc import Collection
from urllib.parse import quote_from_bytes

SLOTS = 64
_REFUSAL_REASONS: dict[str, int] = {}
BOUNDARY = "wp251boundary"
_WORDS = (
    b"quarterly onboarding metrics for the regional sales team include revenue "
    b"churn retention pipeline coverage forecast accuracy and headcount plans "
)


def _note_refusal(status: int, text: str) -> int:
    if status != 200:
        key = f"{status} {text.strip()[:80]}"
        _REFUSAL_REASONS[key] = _REFUSAL_REASONS.get(key, 0) + 1
    return status


def build_multipart(shape: str, size: int) -> tuple[bytes, str]:
    kind = "application/octet-stream" if shape == "mp-binary" else "text/plain"
    head = (
        f'--{BOUNDARY}\r\nContent-Disposition: form-data; name="file"; '
        f'filename="upload.dat"\r\nContent-Type: {kind}\r\n\r\n'
    ).encode()
    tail = f"\r\n--{BOUNDARY}--\r\n".encode()
    room = max(size - len(head) - len(tail), 0)
    if shape == "mp-binary":
        blob = random.Random(1).randbytes(room)
    elif shape == "mp-flat":
        blob = (_WORDS * (room // len(_WORDS) + 1))[:room]
    else:
        raw = (_WORDS * (room // (3 * len(_WORDS)) + 1))[: room // 3]
        blob = quote_from_bytes(raw, safe="").encode()[:room].ljust(room, b"a")
    return head + blob + tail, f"multipart/form-data; boundary={BOUNDARY}"


def _config_kwargs(size: int, accepted: Collection[str]) -> dict[str, object]:
    """The cell's settings, without the ones the engine under test does not have
    (v4.4.0 has no body read slots, so it measures with its own limits)."""
    wanted: dict[str, object] = {
        "enable_redis": False,
        "enable_penetration_detection": True,
        "detection_max_file_inspect_bytes": min(max(size, 1024), 10485760),
        "detection_max_body_inspect_bytes": min(max(size, 1024), 10485760),
        "async_body_read_max_concurrent": SLOTS,
        "sync_body_read_max_concurrent": SLOTS,
        "body_read_timeout": 30.0,
        "rate_limit": 10_000_000,
        "auto_ban_threshold": 10**6,
        "trusted_proxies": ("127.0.0.1",),
    }
    return {key: value for key, value in wanted.items() if key in accepted}
