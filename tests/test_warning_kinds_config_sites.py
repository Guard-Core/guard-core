import logging
import warnings

import pytest

from guard_core._misconfiguration_kinds import Problem
from guard_core.models import SecurityConfig

_QUIET = {"enable_redis": False, "rate_limit": 10, "ban_on_hostile_signals": False}
_FLAGS = [True, False]


class _StubGeo:
    is_initialized = True

    async def initialize(self) -> None:
        return None

    async def refresh(self) -> None:
        return None

    def close(self) -> None:
        return None

    async def initialize_redis(self, redis_handler: object) -> None:
        return None

    async def initialize_agent(self, agent_handler: object) -> None:
        return None

    def get_country(self, ip: str) -> str | None:
        return None


@pytest.mark.parametrize("flag", _FLAGS)
def test_an_unknown_field_warns_with_its_kind_in_both_flag_modes(
    flag: bool, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.WARNING):
        SecurityConfig(**{**_QUIET, "fail_on_misconfiguration": flag, "zzzz": 1})

    [record] = [r for r in caplog.records if "unknown field" in r.getMessage()]
    assert record.getMessage() == (
        "SecurityConfig received unknown field 'zzzz'; it was ignored and had no "
        "effect."
    )
    assert getattr(record, "problems", None) == (("config.unknown_field", "zzzz"),)


@pytest.mark.parametrize("flag", _FLAGS)
def test_an_unknown_field_near_a_real_one_keeps_its_hint_and_its_kind(
    flag: bool, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.WARNING):
        SecurityConfig(**{**_QUIET, "fail_on_misconfiguration": flag, "rate_limt": 5})

    [record] = [r for r in caplog.records if "unknown field" in r.getMessage()]
    assert record.getMessage() == (
        "SecurityConfig received unknown field 'rate_limt'; it was ignored and had "
        "no effect. Did you mean 'rate_limit'?"
    )
    assert getattr(record, "problems", None) == (("config.unknown_field", "rate_limt"),)


@pytest.mark.parametrize("flag", _FLAGS)
def test_a_country_allowlist_shadowing_the_blocklist_warns_with_its_kind(
    flag: bool,
) -> None:
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        SecurityConfig(
            **_QUIET,
            fail_on_misconfiguration=flag,
            geo_ip_handler=_StubGeo(),
            whitelist_countries=["FR"],
            blocked_countries=["CN"],
        )

    [warning] = [w for w in caught if issubclass(w.category, UserWarning)]
    assert isinstance(warning.message, Warning)
    problem = warning.message.args[0]
    assert str(warning.message) == (
        "blocked_countries is ignored when whitelist_countries is non-empty: a "
        "non-empty whitelist_countries is restrictive (only listed countries "
        "pass), so blocked_countries has no effect. Use one or the other."
    )
    assert isinstance(problem, Problem)
    assert (problem.kind, problem.subject) == (
        "whitelist_countries.shadows_blocked_countries",
        None,
    )
