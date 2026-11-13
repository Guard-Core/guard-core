import logging

import pytest
from pydantic import ValidationError

from guard_core.models import SecurityConfig

_NOTE = "Set fail_on_misconfiguration=False to start with it anyway."


def _two_bad_settings(flag: bool) -> SecurityConfig:
    return SecurityConfig(
        enable_redis=False,
        ban_on_hostile_signals=False,
        fail_on_misconfiguration=flag,
        rate_limit=0,
        rate_limit_window=0,
    )


def test_two_bad_settings_raise_once_naming_both() -> None:
    with pytest.raises(ValidationError) as caught:
        _two_bad_settings(True)

    [error] = caught.value.errors()
    message = str(error["ctx"]["error"])
    assert "rate_limit is 0" in message
    assert "rate_limit_window is 0" in message


def test_the_raise_lists_every_problem_and_ends_with_one_note() -> None:
    with pytest.raises(ValidationError) as caught:
        _two_bad_settings(True)

    message = str(caught.value.errors()[0]["ctx"]["error"])
    assert message.startswith("2 misconfigurations:\n- rate_limit is 0")
    assert "\n- rate_limit_window is 0" in message
    assert message.endswith(f"\n{_NOTE}")
    assert message.count(_NOTE) == 1


def test_a_single_problem_keeps_the_text_it_always_had() -> None:
    with pytest.raises(ValidationError) as caught:
        SecurityConfig(
            enable_redis=False,
            ban_on_hostile_signals=False,
            fail_on_misconfiguration=True,
            rate_limit=0,
        )

    message = str(caught.value.errors()[0]["ctx"]["error"])
    assert message == (
        "rate_limit is 0: a limit below 1 blocks every request. " + _NOTE
    )


def test_with_the_flag_off_both_are_logged_and_nothing_raises(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.WARNING, logger="guard_core"):
        _two_bad_settings(False)

    texts = [record.getMessage() for record in caplog.records]
    assert any("rate_limit is 0" in text for text in texts)
    assert any("rate_limit_window is 0" in text for text in texts)


def test_construction_wraps_the_error_and_assignment_raises_it_directly() -> None:
    from guard_core.exceptions import MisconfigurationError

    with pytest.raises(ValidationError) as built:
        _two_bad_settings(True)
    wrapped = built.value.errors()[0]["ctx"]["error"]
    assert isinstance(wrapped, MisconfigurationError)
    assert wrapped.kinds == ["rate_limit.below_one", "rate_limit_window.below_one"]

    config = SecurityConfig(
        enable_redis=False, ban_on_hostile_signals=False, fail_on_misconfiguration=True
    )
    with pytest.raises(MisconfigurationError) as assigned:
        config.rate_limit = 0
    assert assigned.value.kinds == ["rate_limit.below_one"]
    assert not isinstance(assigned.value, ValidationError)
