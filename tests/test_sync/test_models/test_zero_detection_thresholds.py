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
    def test_unset_flag_warns_naming_the_field_and_the_opt_in(
        self, field: str, caplog: pytest.LogCaptureFixture
    ) -> None:
        with caplog.at_level(logging.WARNING, logger="guard_core"):
            with pytest.warns(DeprecationWarning) as caught:
                _build(**{field: 0.0})

        message = str(caught[0].message)
        assert f"{field} is 0.0" in message
        assert "fail_on_misconfiguration=True" in message
        assert any(f"{field} is 0.0" in r.getMessage() for r in caplog.records)

    def test_true_raises(self, field: str) -> None:
        with pytest.raises(ValueError, match=f"{field} is 0.0"):
            _build(fail_on_misconfiguration=True, **{field: 0.0})

    def test_false_warns_without_the_not_set_part(self, field: str) -> None:
        with pytest.warns(DeprecationWarning, match="keeps starting") as caught:
            _build(fail_on_misconfiguration=False, **{field: 0.0})
        assert "is not set" not in str(caught[0].message)

    def test_a_positive_threshold_never_warns(self, field: str) -> None:
        with warnings.catch_warnings():
            warnings.simplefilter("error")
            _build(fail_on_misconfiguration=True, **{field: 0.01})
