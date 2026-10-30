import pytest

from guard_core.models import SecurityConfig
from guard_core.utils import detect_penetration_attempt
from tests.conftest import MockGuardRequest


@pytest.mark.parametrize("payload", ["${7*7}", "${1+1}", "${ 7 * 7 }", "${10-3}"])
async def test_a_brace_arithmetic_probe_is_cmd_injection_as_in_4_4_0(
    payload: str,
) -> None:
    config = SecurityConfig(
        enable_redis=False, enabled_detection_categories=frozenset({"cmd_injection"})
    )

    result = await detect_penetration_attempt(
        MockGuardRequest(path="/x", query_params={"q": payload}), config
    )

    assert result.is_threat is True
    assert "cmd_injection" in result.threat_categories


async def test_the_probe_still_reports_template_with_every_category_enabled() -> None:
    result = await detect_penetration_attempt(
        MockGuardRequest(path="/x", query_params={"q": "${7*7}"}),
        SecurityConfig(enable_redis=False),
    )

    assert {"cmd_injection", "template"} <= set(result.threat_categories)


@pytest.mark.parametrize("payload", ["${a}", "${HOME}", "price is ${total}"])
async def test_a_plain_variable_reference_is_still_not_cmd_injection(
    payload: str,
) -> None:
    config = SecurityConfig(
        enable_redis=False, enabled_detection_categories=frozenset({"cmd_injection"})
    )

    result = await detect_penetration_attempt(
        MockGuardRequest(path="/x", query_params={"q": payload}), config
    )

    assert result.is_threat is False
