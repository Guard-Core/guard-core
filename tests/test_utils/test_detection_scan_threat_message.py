import pytest

from guard_core._utils.detection_scan import _build_threat_message


@pytest.mark.parametrize(
    "threat,expected",
    [
        (
            {"type": "regex", "pattern": "evil"},
            "Value matched pattern 'evil'",
        ),
        (
            {"type": "semantic", "attack_type": "sqli", "probability": 0.91},
            "Semantic attack: sqli (score: 0.91)",
        ),
        (
            {"type": "semantic", "attack_type": "xss", "threat_score": 0.77},
            "Semantic attack: xss (score: 0.77)",
        ),
        (
            {"type": "semantic"},
            "Semantic attack: suspicious (score: 0.00)",
        ),
        (
            {"type": "pattern_timeout", "pattern": "evil"},
            "Pattern exceeded scan time budget: 'evil'",
        ),
        (
            {"type": "pattern_timeout", "pattern": 7},
            "Pattern exceeded scan time budget: '7'",
        ),
        (
            {"type": "unknown"},
            "Threat detected",
        ),
    ],
)
def test_build_threat_message_formats_each_branch(threat: dict, expected: str) -> None:
    assert _build_threat_message(threat) == expected
