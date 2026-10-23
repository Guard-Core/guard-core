import pytest
from pydantic import ValidationError

from guard_core.models import SyncSecurityConfig
from guard_core.sync.handlers.suspatterns_handler import (
    DETECTION_CATEGORY_WEIGHTS,
    SusPatternsManager,
    _resolve_pattern_weight,
)


def test_threshold_field_default_and_bounds() -> None:
    assert SyncSecurityConfig().detection_threat_score_threshold == 1.0
    raised = SyncSecurityConfig(detection_threat_score_threshold=2.5)
    assert raised.detection_threat_score_threshold == 2.5
    with pytest.raises(ValidationError):
        SyncSecurityConfig(detection_threat_score_threshold=-1.0)


def test_anomaly_emission_cooldown_default_and_bounds() -> None:
    assert SyncSecurityConfig().detection_anomaly_emission_cooldown == 60.0
    raised = SyncSecurityConfig(detection_anomaly_emission_cooldown=300)
    assert raised.detection_anomaly_emission_cooldown == 300
    with pytest.raises(ValidationError):
        SyncSecurityConfig(detection_anomaly_emission_cooldown=0.5)
    with pytest.raises(ValidationError):
        SyncSecurityConfig(detection_anomaly_emission_cooldown=4000.0)


def test_min_samples_for_anomaly_default_and_bounds() -> None:
    assert SyncSecurityConfig().detection_min_samples_for_anomaly == 30
    raised = SyncSecurityConfig(detection_min_samples_for_anomaly=50)
    assert raised.detection_min_samples_for_anomaly == 50
    with pytest.raises(ValidationError):
        SyncSecurityConfig(detection_min_samples_for_anomaly=5)
    with pytest.raises(ValidationError):
        SyncSecurityConfig(detection_min_samples_for_anomaly=2000)


def test_new_detection_fields_round_trip() -> None:
    config = SyncSecurityConfig(
        detection_anomaly_emission_cooldown=300,
        detection_min_samples_for_anomaly=50,
    )
    assert config.detection_anomaly_emission_cooldown == 300
    assert config.detection_min_samples_for_anomaly == 50


def test_resolve_weight_defaults_to_category_one() -> None:
    assert _resolve_pattern_weight(r"some-pattern", "sqli") == 1.0
    assert DETECTION_CATEGORY_WEIGHTS["sqli"] == 1.0


def test_regex_threat_dict_carries_weight(
    sus_patterns_manager_with_detection: SusPatternsManager,
) -> None:
    result = sus_patterns_manager_with_detection.detect(
        "<script>alert(1)</script>", "127.0.0.1", context="unknown"
    )
    regex_threats = [t for t in result["threats"] if t["type"] == "regex"]
    assert regex_threats
    assert all(t["weight"] == 1.0 for t in regex_threats)


def test_single_match_still_flagged_at_default_threshold(
    sus_patterns_manager_with_detection: SusPatternsManager,
) -> None:
    result = sus_patterns_manager_with_detection.detect(
        "<script>alert(1)</script>", "127.0.0.1", context="unknown"
    )
    assert result["is_threat"] is True
    assert result["threat_score"] == 1.0


def test_threshold_gate_suppresses_below_threshold() -> None:
    SusPatternsManager._instance = None
    SusPatternsManager._config = None
    config = SyncSecurityConfig(detection_threat_score_threshold=2.0)
    manager = SusPatternsManager(config)
    try:
        result = manager.detect(
            "<script>alert(1)</script>", "127.0.0.1", context="unknown"
        )
        assert result["is_threat"] is False
    finally:
        manager.reset()
        SusPatternsManager._instance = None
        SusPatternsManager._config = None
