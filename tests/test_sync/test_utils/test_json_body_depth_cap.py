import json
import logging
from typing import Any

import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.sync._utils.body_content_scan import _scan_body_field
from guard_core.sync.utils import detect_penetration_attempt
from tests.test_sync.conftest import SyncMockGuardRequest

_SQLI_PAYLOAD = "' OR 1=1--"
_XSS_PAYLOAD = "<script>alert(1)</script>"


def _nested_json_body(depth: int, leaf: str) -> bytes:
    leaf_json = json.dumps(leaf)
    prefix = '{"a":' * depth
    suffix = "}" * depth
    return (prefix + leaf_json + suffix).encode()


def _nested_json_value(depth: int, leaf: Any) -> Any:
    value = leaf
    for _ in range(depth):
        value = {"a": value}
    return value


def _json_request(body: bytes, client_host: str = "127.0.0.1") -> SyncMockGuardRequest:
    return SyncMockGuardRequest(
        method="POST",
        client_host=client_host,
        body_content=body,
        headers={
            "content-type": "application/json",
            "content-length": str(len(body)),
        },
    )


@pytest.mark.parametrize("depth", [100, 325, 400])
def test_nested_json_body_under_json_loads_limit_scans_without_exception(
    depth: int,
) -> None:
    body = _nested_json_body(depth, "benign")

    result = detect_penetration_attempt(_json_request(body), SyncSecurityConfig())

    assert result.is_threat is False


@pytest.mark.parametrize("depth", [990, 1500])
def test_nested_json_body_beyond_json_loads_limit_falls_back_to_blob_scan(
    depth: int,
) -> None:
    body = _nested_json_body(depth, _SQLI_PAYLOAD)

    result = detect_penetration_attempt(_json_request(body), SyncSecurityConfig())

    assert result.is_threat is True
    assert result.trigger_info.startswith("Request body: ")


def test_sqli_at_depth_ten_matches_a_direct_scalar_scan() -> None:
    expected = _scan_body_field(
        _SQLI_PAYLOAD, "a", None, "127.0.0.1", "direct-scan-corr", "WARNING"
    )
    body = _nested_json_body(10, _SQLI_PAYLOAD)

    result = detect_penetration_attempt(_json_request(body), SyncSecurityConfig())

    assert result.is_threat is True
    assert result.threat_categories == ["sqli"]
    assert result.trigger_info == expected[1]


def test_sqli_at_depth_ten_does_not_trip_the_depth_cap_warning(
    caplog: pytest.LogCaptureFixture,
) -> None:
    body = _nested_json_body(10, _SQLI_PAYLOAD)

    with caplog.at_level(logging.WARNING, logger="guard_core"):
        detect_penetration_attempt(_json_request(body), SyncSecurityConfig())

    assert "detection_max_json_depth" not in caplog.text


def test_sqli_below_default_cap_depth_detected_via_serialised_capped_subtree(
    caplog: pytest.LogCaptureFixture,
) -> None:
    subtree = _nested_json_value(40 - 32 + 1, _SQLI_PAYLOAD)
    serialized = json.dumps(subtree, separators=(",", ":"), ensure_ascii=False)
    expected = _scan_body_field(
        serialized,
        "a",
        None,
        "127.0.0.1",
        "direct-scan-corr",
        "WARNING",
        scan_embedded_json=False,
    )
    body = _nested_json_body(40, _SQLI_PAYLOAD)

    with caplog.at_level(logging.WARNING, logger="guard_core"):
        result = detect_penetration_attempt(_json_request(body), SyncSecurityConfig())

    assert result.is_threat is True
    assert result.threat_categories == ["sqli"]
    assert result.trigger_info == expected[1]
    assert "detection_max_json_depth (32) reached" in caplog.text


def test_two_capped_subtrees_in_one_request_warn_only_once(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = SyncSecurityConfig(detection_max_json_depth=5)
    body = json.dumps(
        {
            "branch1": _nested_json_value(10, "benign"),
            "branch2": _nested_json_value(10, "benign"),
        }
    ).encode()

    with caplog.at_level(logging.WARNING, logger="guard_core"):
        result = detect_penetration_attempt(_json_request(body), config)

    assert result.is_threat is False
    assert caplog.text.count("detection_max_json_depth (5) reached") == 1


def test_depth_cap_warning_resets_between_requests(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = SyncSecurityConfig(detection_max_json_depth=5)
    body = _nested_json_body(10, "benign")
    request = _json_request(body)

    with caplog.at_level(logging.WARNING, logger="guard_core"):
        detect_penetration_attempt(request, config)
        detect_penetration_attempt(request, config)

    assert caplog.text.count("detection_max_json_depth (5) reached") == 2


def test_max_json_depth_of_one_scans_a_flat_objects_values_as_text() -> None:
    config = SyncSecurityConfig(detection_max_json_depth=1)
    body = json.dumps({"a": "benign", "b": _SQLI_PAYLOAD}).encode()

    result = detect_penetration_attempt(_json_request(body), config)

    assert result.is_threat is True
    assert result.trigger_info.startswith("Request body field '': ")


def test_ordering_and_first_hit_parity_across_dict_and_nested_list() -> None:
    config = SyncSecurityConfig(excluded_detection_body_fields=["excluded_field"])
    body = json.dumps(
        {
            "excluded_field": _SQLI_PAYLOAD,
            "safe_key": "benign",
            "nested_list": [
                {"inner_scalar": _SQLI_PAYLOAD},
                {"other": "value"},
            ],
            "$ne": "operator_value",
            "trailing_scalar": _XSS_PAYLOAD,
        }
    ).encode()

    result = detect_penetration_attempt(_json_request(body), config)

    assert result.is_threat is True
    assert result.trigger_info.startswith("Request body field 'inner_scalar': ")
    assert "$ne" not in result.trigger_info
    assert "trailing_scalar" not in result.trigger_info


def test_excluded_key_without_the_exclusion_configured_wins_instead() -> None:
    body = json.dumps(
        {
            "excluded_field": _SQLI_PAYLOAD,
            "nested_list": [{"inner_scalar": _SQLI_PAYLOAD}],
        }
    ).encode()

    result = detect_penetration_attempt(_json_request(body), SyncSecurityConfig())

    assert result.is_threat is True
    assert result.trigger_info.startswith("Request body field 'excluded_field': ")


def test_default_cap_never_trips_on_an_ordinary_shallow_json_body(
    caplog: pytest.LogCaptureFixture,
) -> None:
    body = json.dumps({"query": {"filter": {"active": True}}}).encode()

    with caplog.at_level(logging.WARNING, logger="guard_core"):
        result = detect_penetration_attempt(_json_request(body), SyncSecurityConfig())

    assert result.is_threat is False
    assert "detection_max_json_depth" not in caplog.text


def test_config_none_still_uses_the_default_depth_cap(
    caplog: pytest.LogCaptureFixture,
) -> None:
    body = _nested_json_body(40, _SQLI_PAYLOAD)

    with caplog.at_level(logging.WARNING, logger="guard_core"):
        result = detect_penetration_attempt(_json_request(body))

    assert result.is_threat is True
    assert "detection_max_json_depth (32) reached" in caplog.text


def test_detection_max_json_depth_default_is_thirty_two() -> None:
    config = SyncSecurityConfig()

    assert config.detection_max_json_depth == 32


def test_detection_max_json_depth_of_zero_is_rejected() -> None:
    with pytest.raises(ValueError, match="greater than or equal to 1"):
        SyncSecurityConfig(detection_max_json_depth=0)


def test_detection_max_json_depth_of_one_is_accepted() -> None:
    config = SyncSecurityConfig(detection_max_json_depth=1)

    assert config.detection_max_json_depth == 1


def test_detection_max_json_depth_of_one_thousand_is_accepted() -> None:
    config = SyncSecurityConfig(detection_max_json_depth=1000)

    assert config.detection_max_json_depth == 1000


def test_detection_max_json_depth_above_one_thousand_is_rejected() -> None:
    with pytest.raises(ValueError, match="less than or equal to 1000"):
        SyncSecurityConfig(detection_max_json_depth=1001)
