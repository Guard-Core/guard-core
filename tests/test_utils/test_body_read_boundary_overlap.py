import re
from typing import cast

import pytest

from guard_core import utils
from guard_core._utils import body_reader, detection_scan
from guard_core.handlers.suspatterns_handler import SusPatternsManager
from guard_core.models import SecurityConfig
from guard_core.protocols.request_protocol import GuardRequest

_MAGIC = "MAGIC-STRADDLE-SIGNATURE-0000000000"
_real_straddle_overlap_bytes = utils._straddle_overlap_bytes


class _PrefixOnlyRequest:
    def __init__(self, body: bytes) -> None:
        self._body = body
        self.query_params: dict[str, str] = {}
        self.headers: dict[str, str] = {}
        self.url_path = "/"
        self.method = "POST"
        self.client_host = "127.0.0.1"
        self.state = type("S", (), {})()
        self.requested_max_bytes: int | None = None

    async def body(self) -> bytes:
        return self._body

    async def read_body_prefix(self, max_bytes: int) -> bytes:
        self.requested_max_bytes = max_bytes
        return self._body[:max_bytes]


async def _fake_component_check(
    value: str,
    context: str,
    client_ip: str,
    correlation_id: str,
    enabled_categories: set[str] | None = None,
    scan_embedded_json: bool = True,
    content_preview: str | None = None,
    sensitive_body_fields: frozenset[str] = frozenset(),
    excluded_body_fields: frozenset[str] = frozenset(),
    json_redact_all: bool | None = None,
    sensitive_params: frozenset[str] = frozenset(),
    *,
    patterns: object = None,
) -> tuple[bool, str, list[dict], str | None]:
    if _MAGIC in value:
        return (
            True,
            "matched magic signature",
            [{"type": "regex", "pattern": _MAGIC, "category": "test"}],
            None,
        )
    return False, "", [], None


def _straddling_body(cap: int) -> bytes:
    padding = "A" * (cap - len(_MAGIC) // 2)
    return (padding + _MAGIC).encode()


async def test_a_signature_split_across_the_cap_boundary_is_missed_with_no_overlap(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(detection_scan, "_check_value_enhanced", _fake_component_check)
    request = _PrefixOnlyRequest(body=_straddling_body(1024))
    config = SecurityConfig(detection_max_body_inspect_bytes=1024)

    result = await utils.detect_penetration_attempt(cast(GuardRequest, request), config)

    assert result.is_threat is False
    assert request.requested_max_bytes == 1024


async def test_the_same_straddling_signature_is_matched_once_the_overlap_covers_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(detection_scan, "_check_value_enhanced", _fake_component_check)

    async def _fixed_overlap(*, patterns: object = None) -> int:
        return len(_MAGIC)

    monkeypatch.setattr(body_reader, "_straddle_overlap_bytes", _fixed_overlap)
    request = _PrefixOnlyRequest(body=_straddling_body(1024))
    config = SecurityConfig(detection_max_body_inspect_bytes=1024)

    result = await utils.detect_penetration_attempt(cast(GuardRequest, request), config)

    assert result.is_threat is True
    assert request.requested_max_bytes == 1024 + len(_MAGIC)


async def test_a_straddling_signature_is_matched_on_the_oversized_content_length_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(detection_scan, "_check_value_enhanced", _fake_component_check)

    async def _fixed_overlap(*, patterns: object = None) -> int:
        return len(_MAGIC)

    monkeypatch.setattr(body_reader, "_straddle_overlap_bytes", _fixed_overlap)
    body = _straddling_body(1024)
    request = _PrefixOnlyRequest(body=body)
    request.headers["content-length"] = str(len(body))
    config = SecurityConfig(detection_max_body_inspect_bytes=1024)

    result = await utils.detect_penetration_attempt(cast(GuardRequest, request), config)

    assert result.is_threat is True
    assert request.requested_max_bytes == 1024 + len(_MAGIC)


async def test_a_payload_placed_entirely_past_the_cap_is_still_not_detected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(detection_scan, "_check_value_enhanced", _fake_component_check)

    async def _fixed_overlap(*, patterns: object = None) -> int:
        return len(_MAGIC)

    monkeypatch.setattr(body_reader, "_straddle_overlap_bytes", _fixed_overlap)
    body = ("A" * 2048 + _MAGIC).encode()
    request = _PrefixOnlyRequest(body=body)
    config = SecurityConfig(detection_max_body_inspect_bytes=1024)

    result = await utils.detect_penetration_attempt(cast(GuardRequest, request), config)

    assert result.is_threat is False


async def test_straddle_overlap_uses_the_longest_compiled_pattern_length(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_patterns: list[tuple[re.Pattern[str], frozenset[str], str]] = [
        (re.compile("short"), frozenset(), "cat"),
        (re.compile("a" * 40), frozenset(), "cat"),
    ]

    async def _fake_get_all(
        self: SusPatternsManager,
    ) -> list[tuple[re.Pattern[str], frozenset[str], str]]:
        return fake_patterns

    monkeypatch.setattr(SusPatternsManager, "get_all_compiled_patterns", _fake_get_all)

    assert await _real_straddle_overlap_bytes() == 40


async def test_straddle_overlap_is_clamped_to_the_documented_ceiling(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_patterns: list[tuple[re.Pattern[str], frozenset[str], str]] = [
        (re.compile("x" * 5000), frozenset(), "cat")
    ]

    async def _fake_get_all(
        self: SusPatternsManager,
    ) -> list[tuple[re.Pattern[str], frozenset[str], str]]:
        return fake_patterns

    monkeypatch.setattr(SusPatternsManager, "get_all_compiled_patterns", _fake_get_all)

    overlap = await _real_straddle_overlap_bytes()

    assert overlap == utils._MAX_STRADDLE_OVERLAP_BYTES
    assert overlap < 5000


async def test_straddle_overlap_is_zero_when_there_are_no_patterns(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def _fake_get_all(self: SusPatternsManager) -> list:
        return []

    monkeypatch.setattr(SusPatternsManager, "get_all_compiled_patterns", _fake_get_all)

    assert await _real_straddle_overlap_bytes() == 0


async def test_straddle_overlap_degrades_to_zero_if_the_pattern_engine_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def _raise(self: SusPatternsManager) -> list:
        raise RuntimeError("boom")

    monkeypatch.setattr(SusPatternsManager, "get_all_compiled_patterns", _raise)

    assert await _real_straddle_overlap_bytes() == 0


async def test_real_pattern_set_produces_a_bounded_nonzero_overlap() -> None:
    overlap = await _real_straddle_overlap_bytes()

    assert 0 < overlap <= utils._MAX_STRADDLE_OVERLAP_BYTES
