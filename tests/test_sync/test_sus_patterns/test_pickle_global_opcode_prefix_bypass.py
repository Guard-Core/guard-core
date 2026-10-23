import io
import json
import pickle
from unittest.mock import patch
from urllib.parse import urlencode

import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.sync.handlers.suspatterns_handler import (
    _PICKLE_OPCODE_WORK_BUDGET_BYTES,
    _pickle_global_prefix_is_opcode_stream,
    _pickle_global_suffix_reaches_reduce_or_build,
    sus_patterns_handler,
)
from guard_core.sync.utils import detect_penetration_attempt
from tests.test_sync.conftest import SyncMockGuardRequest

_BASELINE_PICKLE_PAYLOAD = b"cshutil\nrmtree\n(S'/tmp/x'\ntR."
_MEMOIZED_PICKLE_PAYLOAD = (
    b"cshutil\nrmtree\nq\x00X\x06\x00\x00\x00/tmp/xq\x01\x85q\x02Rq\x03."
)


def _clean_multibyte_opcode_padding(length: int) -> bytes:
    unit = b"Nq\x00"
    whole_units, remainder = divmod(length, len(unit))
    return b"N" * remainder + unit * whole_units


@pytest.fixture(autouse=True)
def _force_enhanced_detection_singleton() -> None:
    sus_patterns_handler.configure(SyncSecurityConfig())


def _decoded_like_production(raw: bytes) -> str:
    return raw.decode("utf-8", errors="surrogateescape")


def _deserialization_detected(raw: bytes) -> bool:
    result = sus_patterns_handler.detect(
        content=_decoded_like_production(raw),
        ip_address="203.0.113.9",
        context="request_body",
    )
    return any(
        threat.get("category") == "deserialization" for threat in result["threats"]
    )


_OPCODE_PREFIX_FAMILY_CASES: list[tuple[bytes, str]] = [
    (b"N", "none_opcode"),
    (b"\x88", "newtrue_opcode"),
    (b"\x89", "newfalse_opcode"),
    (b")", "empty_tuple_opcode"),
    (b"]", "empty_list_opcode"),
    (b"}", "empty_dict_opcode"),
    (b"\x8f", "empty_set_opcode"),
    (b"(", "mark_opcode"),
    (b"\x80\x04", "proto_header_opcode"),
    (b"K\x00", "binint1_opcode"),
    (b"M\x00\x00", "binint2_opcode"),
    (b"J\x00\x00\x00\x00", "binint_opcode"),
    (b"\x8a\x00", "long1_opcode"),
    (b"\x8b\x00\x00\x00\x00", "long4_opcode"),
    (b"T\x00\x00\x00\x00", "binstring_opcode"),
    (b"U\x00", "short_binstring_opcode"),
    (b"B\x00\x00\x00\x00", "binbytes_opcode"),
    (b"C\x00", "short_binbytes_opcode"),
    (b"\x8e\x00\x00\x00\x00\x00\x00\x00\x00", "binbytes8_opcode"),
    (b"\x96\x00\x00\x00\x00\x00\x00\x00\x00", "bytearray8_opcode"),
    (b"\x8c\x00", "short_binunicode_opcode"),
    (b"X\x00\x00\x00\x00", "binunicode_opcode"),
    (b"\x8d\x00\x00\x00\x00\x00\x00\x00\x00", "binunicode8_opcode"),
    (b"G\x00\x00\x00\x00\x00\x00\x00\x00", "binfloat_opcode"),
    (b"N\x94", "none_then_memoize"),
    (b"Nq\x00", "none_then_binput"),
]

OPCODE_PREFIX_BYPASS_FAMILY = [
    pytest.param(prefix, id=case_id) for prefix, case_id in _OPCODE_PREFIX_FAMILY_CASES
]


@pytest.mark.parametrize("prefix", OPCODE_PREFIX_BYPASS_FAMILY)
def test_opcode_prefixed_global_payload_detected(prefix: bytes) -> None:
    assert _deserialization_detected(prefix + _BASELINE_PICKLE_PAYLOAD) is True


BYTE_SENSITIVE_OPCODE_PREFIX_FAMILY = [
    pytest.param(prefix, id=case_id)
    for prefix, case_id in _OPCODE_PREFIX_FAMILY_CASES
    if any(byte >= 0x80 for byte in prefix)
]


def _body_request(payload: str, content_type: str) -> SyncMockGuardRequest:
    body = payload.encode("utf-8", errors="surrogateescape")
    headers = {"content-length": str(len(body))}
    if content_type:
        headers["content-type"] = content_type
    return SyncMockGuardRequest(body_content=body, headers=headers)


def _raw_body_request(payload: str) -> SyncMockGuardRequest:
    return _body_request(payload, "")


def _form_body_request(payload: str) -> SyncMockGuardRequest:
    return _body_request(
        urlencode({"field": payload}, errors="surrogateescape"),
        "application/x-www-form-urlencoded",
    )


def _multipart_body_request(payload: str) -> SyncMockGuardRequest:
    boundary = "B0"
    part = f'Content-Disposition: form-data; name="field"\r\n\r\n{payload}'
    body = f"--{boundary}\r\n{part}\r\n--{boundary}--\r\n"
    return _body_request(body, f"multipart/form-data; boundary={boundary}")


_REAL_ENTRY_POINT_BODY_REQUEST_BUILDERS = {
    "raw_body": _raw_body_request,
    "form_body": _form_body_request,
    "multipart_body": _multipart_body_request,
}


def _query_param_request(payload: str) -> SyncMockGuardRequest:
    return SyncMockGuardRequest(
        query_params={"v": payload}, headers={"content-length": "0"}
    )


def _json_body_request(payload: str) -> SyncMockGuardRequest:
    body = b'{"v":' + json.dumps(payload).encode("utf-8") + b"}"
    return SyncMockGuardRequest(
        body_content=body,
        headers={
            "content-type": "application/json",
            "content-length": str(len(body)),
        },
    )


_WINDOW_BOUNDARY_MECHANISM_BUILDERS = {
    **_REAL_ENTRY_POINT_BODY_REQUEST_BUILDERS,
    "query_param": _query_param_request,
    "json_body": _json_body_request,
}


_WINDOW_BOUNDARY_PREFIX_LENGTHS = [31, 32, 33, 200, 4096]

_WINDOW_BOUNDARY_TAIL_SHAPES = {
    "bare_reduce": _BASELINE_PICKLE_PAYLOAD,
    "memoized_reduce": _MEMOIZED_PICKLE_PAYLOAD,
}


@pytest.mark.parametrize("prefix_len", _WINDOW_BOUNDARY_PREFIX_LENGTHS)
@pytest.mark.parametrize("tail_shape", sorted(_WINDOW_BOUNDARY_TAIL_SHAPES))
@pytest.mark.parametrize("mechanism", sorted(_WINDOW_BOUNDARY_MECHANISM_BUILDERS))
def test_opcode_prefix_at_window_boundary_lengths_detected_via_real_entry_point(
    mechanism: str, tail_shape: str, prefix_len: int
) -> None:
    padding = _clean_multibyte_opcode_padding(prefix_len)
    tail = _WINDOW_BOUNDARY_TAIL_SHAPES[tail_shape]
    payload = _decoded_like_production(padding + tail)
    request = _WINDOW_BOUNDARY_MECHANISM_BUILDERS[mechanism](payload)
    result = detect_penetration_attempt(request, SyncSecurityConfig())
    assert result.is_threat is True


class _CallRecordingUnpickler(pickle.Unpickler):
    def __init__(self, file: io.BytesIO) -> None:
        super().__init__(file)
        self.find_class_calls: list[tuple[str, str]] = []
        self.reduce_call_args: list[tuple[tuple, dict]] = []

    def find_class(self, module: str, name: str) -> object:
        self.find_class_calls.append((module, name))

        def _sentinel(*args: object, **kwargs: object) -> object:
            self.reduce_call_args.append((args, kwargs))
            raise RuntimeError("blocked-before-real-call")

        return _sentinel


def test_opcode_prefix_at_window_boundary_lengths_genuinely_execute() -> None:
    for tail in _WINDOW_BOUNDARY_TAIL_SHAPES.values():
        for prefix_len in _WINDOW_BOUNDARY_PREFIX_LENGTHS:
            payload = _clean_multibyte_opcode_padding(prefix_len) + tail
            unpickler = _CallRecordingUnpickler(io.BytesIO(payload))
            with pytest.raises(RuntimeError, match="blocked-before-real-call"):
                unpickler.load()
            assert unpickler.find_class_calls == [("shutil", "rmtree")]
            assert unpickler.reduce_call_args == [(("/tmp/x",), {})]


@pytest.mark.parametrize("prefix_len", [4097, 5000, 8192])
def test_opcode_prefix_beyond_work_budget_still_flags(prefix_len: int) -> None:
    assert prefix_len > _PICKLE_OPCODE_WORK_BUDGET_BYTES
    padding = _clean_multibyte_opcode_padding(prefix_len)
    payload = _decoded_like_production(padding + _BASELINE_PICKLE_PAYLOAD)
    request = _raw_body_request(payload)
    result = detect_penetration_attempt(request, SyncSecurityConfig())
    assert result.is_threat is True


@pytest.mark.parametrize("prefix", BYTE_SENSITIVE_OPCODE_PREFIX_FAMILY)
@pytest.mark.parametrize("mechanism", sorted(_REAL_ENTRY_POINT_BODY_REQUEST_BUILDERS))
def test_byte_sensitive_opcode_prefix_detected_via_real_entry_point(
    mechanism: str, prefix: bytes
) -> None:
    payload = _decoded_like_production(prefix + _BASELINE_PICKLE_PAYLOAD)
    request = _REAL_ENTRY_POINT_BODY_REQUEST_BUILDERS[mechanism](payload)
    result = detect_penetration_attempt(request, SyncSecurityConfig())
    assert result.is_threat is True


_FRAME_PREFIX_WITH_LENGTH_FIELD = b"\x95" + b"\x00" * 8


def test_frame_prefixed_payload_with_length_field_is_detected() -> None:
    assert (
        _deserialization_detected(
            _FRAME_PREFIX_WITH_LENGTH_FIELD + _BASELINE_PICKLE_PAYLOAD
        )
        is True
    )


def test_frame_opcode_without_length_field_is_not_a_working_attack() -> None:
    malformed = b"\x95" + _BASELINE_PICKLE_PAYLOAD
    resolved: list[tuple[str, str]] = []

    class _BlockingUnpickler(pickle._Unpickler):
        def find_class(self, module: str, name: str) -> object:
            resolved.append((module, name))
            raise RuntimeError("find_class reached")

    with pytest.raises((pickle.UnpicklingError, RuntimeError, IndexError)):
        _BlockingUnpickler(io.BytesIO(malformed)).load()
    assert resolved == []


@pytest.mark.parametrize("mechanism", sorted(_REAL_ENTRY_POINT_BODY_REQUEST_BUILDERS))
def test_frame_prefixed_payload_detected_via_real_entry_point(
    mechanism: str,
) -> None:
    payload = _decoded_like_production(
        _FRAME_PREFIX_WITH_LENGTH_FIELD + _BASELINE_PICKLE_PAYLOAD
    )
    request = _REAL_ENTRY_POINT_BODY_REQUEST_BUILDERS[mechanism](payload)
    result = detect_penetration_attempt(request, SyncSecurityConfig())
    assert result.is_threat is True


def test_baseline_pickle_global_payload_still_detected() -> None:
    assert _deserialization_detected(_BASELINE_PICKLE_PAYLOAD) is True


def test_newline_preceded_global_payload_still_detected() -> None:
    assert _deserialization_detected(b"prior line\n" + _BASELINE_PICKLE_PAYLOAD) is True


BENIGN_PROSE_NOT_MATCHING_GLOBAL_SHAPE = [
    pytest.param(b"syncmodule\nsettings\nvalue.b.", id="lowercase_c_glued_mid_word"),
    pytest.param(
        b"AN" + b"config\nsettings\nid123.b.", id="uppercase_n_glued_before_c"
    ),
    pytest.param(
        b"K" + b"config\nsettings\nid123.b.", id="ascii_letter_glued_before_c"
    ),
    pytest.param(b"0" + b"config\nsettings\nid123.b.", id="digit_glued_before_c"),
    pytest.param(
        b"Build log: step finished(cache\nvalue\nR.\n",
        id="glued_mark_prefix_in_prose",
    ),
    pytest.param(
        b"Internal tools we use:\nconfluence\nhelpdesk\njira",
        id="bare_letter_after_newline_glued_global_in_prose",
    ),
]


@pytest.mark.parametrize("payload", BENIGN_PROSE_NOT_MATCHING_GLOBAL_SHAPE)
def test_benign_prose_resembling_global_shape_not_detected(
    payload: bytes,
) -> None:
    assert _deserialization_detected(payload) is False


def test_short_read_length_prefixed_opcode_at_window_boundary_not_detected() -> None:
    padding = b"padding padding padding "
    window_body = b"U" + b"Z" + b"x" * 30
    assert _deserialization_detected(padding + window_body) is False


def test_opcode_prefix_family_genuinely_executes_under_real_pickle_loads() -> None:
    calls: list[tuple[str, str]] = []

    class _RecordingUnpickler(pickle._Unpickler):
        def find_class(self, module: str, name: str) -> object:
            calls.append((module, name))
            return super().find_class(module, name)

    for prefix in (b"\x80\x04", b"\x88", _FRAME_PREFIX_WITH_LENGTH_FIELD):
        calls.clear()
        with patch("shutil.rmtree") as mock_rmtree:
            _RecordingUnpickler(io.BytesIO(prefix + _BASELINE_PICKLE_PAYLOAD)).load()
        assert calls == [("shutil", "rmtree")]
        mock_rmtree.assert_called_once_with("/tmp/x")


_PINNED_256_BYTE_SWEEP_ACCEPT_SET = frozenset(
    {0x0A, 0x28, 0x29, 0x43, 0x4E, 0x5D, 0x63, 0x7D, 0x88, 0x89, 0x8F}
)


def test_full_256_byte_prefix_sweep_matches_pinned_accept_set() -> None:
    accepted = set()
    for prefix_byte in range(256):
        raw = bytes([prefix_byte]) + _BASELINE_PICKLE_PAYLOAD
        if _deserialization_detected(raw):
            accepted.add(prefix_byte)
    assert accepted == _PINNED_256_BYTE_SWEEP_ACCEPT_SET


def test_256_byte_sweep_accept_set_is_case_fold_self_match_or_opcode_family() -> None:
    case_fold_self_match_bytes = {ord("C"), ord("c")}
    newline_shortcut_bytes = {ord("\n")}
    genuine_opcode_family_bytes = {
        opcode_byte
        for opcode_byte in _PINNED_256_BYTE_SWEEP_ACCEPT_SET
        - case_fold_self_match_bytes
        - newline_shortcut_bytes
        if _pickle_global_prefix_is_opcode_stream(
            bytes([opcode_byte]).decode("utf-8", errors="surrogateescape")
        )
    }
    assert (
        case_fold_self_match_bytes
        | newline_shortcut_bytes
        | genuine_opcode_family_bytes
        == _PINNED_256_BYTE_SWEEP_ACCEPT_SET
    )


def test_prefix_validator_empty_prefix_is_valid() -> None:
    assert _pickle_global_prefix_is_opcode_stream("") is True


def test_prefix_validator_newline_terminated_prefix_is_valid() -> None:
    assert _pickle_global_prefix_is_opcode_stream("prior line\n") is True


def test_prefix_validator_codepoint_beyond_byte_range_is_rejected() -> None:
    assert _pickle_global_prefix_is_opcode_stream("☃") is False


def test_prefix_validator_surrogateescape_codepoint_matches_raw_byte() -> None:
    surrogate_escaped = bytes([0x88]).decode("utf-8", errors="surrogateescape")
    assert surrogate_escaped != "\x88"
    assert _pickle_global_prefix_is_opcode_stream(
        surrogate_escaped
    ) == _pickle_global_prefix_is_opcode_stream("\x88")
    assert _pickle_global_prefix_is_opcode_stream(surrogate_escaped) is True


def test_prefix_validator_unknown_opcode_byte_is_rejected() -> None:
    assert _pickle_global_prefix_is_opcode_stream("config") is False


def test_prefix_validator_dangling_argument_opcode_is_rejected() -> None:
    assert _pickle_global_prefix_is_opcode_stream("K") is False


def test_prefix_validator_stack_underflow_opcode_is_rejected() -> None:
    assert _pickle_global_prefix_is_opcode_stream("0") is False


def test_prefix_validator_clean_multi_opcode_chain_is_valid() -> None:
    assert _pickle_global_prefix_is_opcode_stream("N\x94") is True


def test_prefix_validator_extension_opcode_never_resolves() -> None:
    assert _pickle_global_prefix_is_opcode_stream("\x82\x01") is False


def test_prefix_validator_persistent_id_opcode_never_resolves() -> None:
    assert _pickle_global_prefix_is_opcode_stream("Pfoo\nN") is False


def test_prefix_validator_embedded_global_opcode_never_resolves() -> None:
    assert _pickle_global_prefix_is_opcode_stream("(cshutil\nrmtree\nX") is False


def test_prefix_validator_frame_opcode_with_valid_length_field_is_valid() -> None:
    assert (
        _pickle_global_prefix_is_opcode_stream("\x95\x00\x00\x00\x00\x00\x00\x00\x00")
        is True
    )


def test_prefix_validator_frame_length_exceeding_sys_maxsize_is_rejected() -> None:
    overflowing_length = bytes([0xFF] * 8).decode("utf-8", errors="surrogateescape")
    assert _pickle_global_prefix_is_opcode_stream("\x95" + overflowing_length) is False


def test_prefix_validator_declared_length_past_window_end_is_rejected() -> None:
    assert _pickle_global_prefix_is_opcode_stream("C" + "Z" + "x" * 30) is False


def test_prefix_validator_readinto_short_read_is_rejected() -> None:
    assert (
        _pickle_global_prefix_is_opcode_stream(
            "\x96" + "\x0a\x00\x00\x00\x00\x00\x00\x00"
        )
        is False
    )


def test_prefix_validator_exactly_at_budget_clean_run_is_resolved_true() -> None:
    prefix = "N" * _PICKLE_OPCODE_WORK_BUDGET_BYTES
    assert _pickle_global_prefix_is_opcode_stream(prefix) is True


def test_prefix_validator_budget_exceeded_clean_run_is_unresolved_and_flags() -> None:
    prefix = "N" * (_PICKLE_OPCODE_WORK_BUDGET_BYTES + 1000)
    assert _pickle_global_prefix_is_opcode_stream(prefix) is True


def test_prefix_validator_budget_exceeded_dangling_opcode_is_unresolved_and_flags() -> (
    None
):
    budget = _PICKLE_OPCODE_WORK_BUDGET_BYTES
    dangling = _clean_multibyte_opcode_padding(budget - 1) + b"K" + b"extra"
    prefix = dangling.decode("utf-8", errors="surrogateescape")
    assert len(prefix) > budget
    assert _pickle_global_prefix_is_opcode_stream(prefix) is True


def test_prefix_validator_budget_exceeded_early_dispatch_failure_still_rejected() -> (
    None
):
    prefix = "Z" + "A" * (_PICKLE_OPCODE_WORK_BUDGET_BYTES + 1000)
    assert _pickle_global_prefix_is_opcode_stream(prefix) is False


def test_suffix_validator_reaches_reduce_directly() -> None:
    assert _pickle_global_suffix_reaches_reduce_or_build("R") is True


def test_suffix_validator_reaches_build_directly() -> None:
    assert _pickle_global_suffix_reaches_reduce_or_build("b") is True


def test_suffix_validator_clean_run_without_reduce_is_rejected() -> None:
    assert _pickle_global_suffix_reaches_reduce_or_build("N") is False


def test_suffix_validator_unknown_opcode_byte_is_rejected() -> None:
    assert _pickle_global_suffix_reaches_reduce_or_build("Z") is False


def test_suffix_validator_codepoint_beyond_byte_range_is_rejected() -> None:
    assert _pickle_global_suffix_reaches_reduce_or_build("☃") is False


def test_suffix_validator_frame_opcode_before_reduce_is_detected() -> None:
    suffix = "\x95" + "\x00" * 8 + "R"
    assert _pickle_global_suffix_reaches_reduce_or_build(suffix) is True


def test_suffix_validator_frame_length_exceeding_sys_maxsize_is_rejected() -> None:
    overflowing_length = bytes([0xFF] * 8).decode("utf-8", errors="surrogateescape")
    suffix = "\x95" + overflowing_length + "R"
    assert _pickle_global_suffix_reaches_reduce_or_build(suffix) is False


def test_suffix_validator_exactly_at_budget_clean_run_is_resolved_false() -> None:
    suffix = "N" * _PICKLE_OPCODE_WORK_BUDGET_BYTES
    assert _pickle_global_suffix_reaches_reduce_or_build(suffix) is False


def test_suffix_validator_budget_exceeded_clean_run_is_unresolved_and_flags() -> None:
    suffix = "N" * (_PICKLE_OPCODE_WORK_BUDGET_BYTES + 1000)
    assert _pickle_global_suffix_reaches_reduce_or_build(suffix) is True


def test_suffix_validator_budget_exceeded_dangling_opcode_is_unresolved_and_flags() -> (
    None
):
    budget = _PICKLE_OPCODE_WORK_BUDGET_BYTES
    dangling = _clean_multibyte_opcode_padding(budget - 1) + b"K" + b"extra"
    suffix = dangling.decode("utf-8", errors="surrogateescape")
    assert len(suffix) > budget
    assert _pickle_global_suffix_reaches_reduce_or_build(suffix) is True


def test_suffix_validator_budget_exceeded_early_dispatch_failure_still_rejected() -> (
    None
):
    suffix = "Z" + "A" * (_PICKLE_OPCODE_WORK_BUDGET_BYTES + 1000)
    assert _pickle_global_suffix_reaches_reduce_or_build(suffix) is False
