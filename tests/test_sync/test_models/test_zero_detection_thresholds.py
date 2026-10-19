import logging
import warnings
from typing import Any

import pytest

from guard_core.models import SecurityConfig


def _build(**settings: Any) -> SecurityConfig:
    return SecurityConfig(enable_redis=False, **settings)


@pytest.mark.parametrize(
    "field",
    ["detection_threat_score_threshold", "detection_semantic_threshold"],
)
class TestZeroDetectionThreshold:
    def test_unset_flag_refuses_naming_the_field_and_the_old_value(
        self, field: str
    ) -> None:
        with pytest.raises(ValueError) as caught:
            _build(**{field: 0.0})

        message = str(caught.value)
        assert f"{field} is 0.0" in message
        assert "fail_on_misconfiguration=False" in message

    def test_true_raises(self, field: str) -> None:
        with pytest.raises(ValueError, match=f"{field} is 0.0"):
            _build(fail_on_misconfiguration=True, **{field: 0.0})

    def test_false_logs_one_warning_and_starts(
        self, field: str, caplog: pytest.LogCaptureFixture
    ) -> None:
        with caplog.at_level(logging.WARNING, logger="guard_core"):
            with warnings.catch_warnings():
                warnings.simplefilter("error")
                _build(fail_on_misconfiguration=False, **{field: 0.0})

        messages = [
            r.getMessage() for r in caplog.records if f"{field} is 0.0" in r.message
        ]
        assert len(messages) == 1
        assert "keeps starting" in messages[0]

    def test_a_positive_threshold_never_warns(self, field: str) -> None:
        with warnings.catch_warnings():
            warnings.simplefilter("error")
            _build(fail_on_misconfiguration=True, **{field: 0.01})
