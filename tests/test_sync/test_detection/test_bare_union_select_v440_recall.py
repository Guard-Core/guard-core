import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.sync.utils import detect_penetration_attempt
from tests.test_sync.conftest import SyncMockGuardRequest

# The values v4.4.0 (66f3072e) flags on a default SecurityConfig, per surface, from
# ledger_gaps/verify/critic-6c/u_v440.tsv (WP114, D-74: zero loss against v4.4.0),
# stored, never computed from v4.4.0 at test time.
# LOST_AT_LANDING_6C: the 21 of them landing-6c (7bee8f73) did not flag (CRITIC-6c).
V440_FLAGGED: dict[str, list[str]] = {
    "q": [
        "'union select",
        " union select ",
        "1 union select",
        "UNION  SELECT\n",
        "UNION ALL SELECT",
        "UNION%20SELECT",
        "UnIoN sElEcT",
        "\ufeffunion select",
        "union all select",
        "union select #",
        "union select * from t",
        "union select --",
        "union select 1",
        "union select ;",
        "union select",
        "union select/**/",
        "union select;",
        "union select\x00",
        "union select\xa0",
        "union/**/select",
        "union\nselect",
        "union\tselect",
        "union\xa0select",
    ],
    "header": [
        "'union select",
        " union select ",
        "1 union select",
        "UNION  SELECT\n",
        "UNION ALL SELECT",
        "UNION%20SELECT",
        "UnIoN sElEcT",
        "\ufeffunion select",
        "union all select",
        "union select #",
        "union select * from t",
        "union select --",
        "union select 1",
        "union select ;",
        "union select",
        "union select/**/",
        "union select;",
        "union select\x00",
        "union select\xa0",
        "union\nselect",
        "union\tselect",
        "union\xa0select",
    ],
    "path": [
        "'union select",
        " union select ",
        "1 union select",
        "UNION  SELECT\n",
        "UNION ALL SELECT",
        "UNION%20SELECT",
        "UnIoN sElEcT",
        "\ufeffunion select",
        "union all select",
        "union select #",
        "union select * from t",
        "union select --",
        "union select 1",
        "union select ;",
        "union select",
        "union select/**/",
        "union select;",
        "union select\x00",
        "union select\xa0",
        "union\nselect",
        "union\tselect",
        "union\xa0select",
    ],
}

CASES = [
    (surface, value) for surface, values in V440_FLAGGED.items() for value in values
]


LOST_AT_LANDING_6C: list[tuple[str, str]] = [
    ("header", "union select ;"),
    ("header", "union select;"),
    ("path", " union select "),
    ("path", "UNION  SELECT\n"),
    ("path", "UNION ALL SELECT"),
    ("path", "UNION%20SELECT"),
    ("path", "UnIoN sElEcT"),
    ("path", "\ufeffunion select"),
    ("path", "union all select"),
    ("path", "union select #"),
    ("path", "union select ;"),
    ("path", "union select"),
    ("path", "union select/**/"),
    ("path", "union select;"),
    ("path", "union select\x00"),
    ("path", "union select\xa0"),
    ("path", "union\nselect"),
    ("path", "union\tselect"),
    ("path", "union\xa0select"),
    ("q", "union select ;"),
    ("q", "union select;"),
]


def _request(surface: str, value: str) -> SyncMockGuardRequest:
    if surface == "q":
        return SyncMockGuardRequest(path="/s", query_params={"q": value})
    if surface == "header":
        return SyncMockGuardRequest(path="/s", headers={"x-foo": value})
    return SyncMockGuardRequest(path="/" + value.replace(" ", "%20"))


@pytest.mark.parametrize(("surface", "value"), CASES)
def test_every_verdict_v440_raises_is_raised_on_the_default_config(
    surface: str, value: str
) -> None:
    result = detect_penetration_attempt(_request(surface, value), SyncSecurityConfig())
    assert result.is_threat is True


@pytest.mark.parametrize(("surface", "value"), LOST_AT_LANDING_6C)
def test_the_switch_turns_the_bare_row_off_for_the_21_verdicts_landing_6c_lost(
    surface: str, value: str
) -> None:
    result = detect_penetration_attempt(
        _request(surface, value), SyncSecurityConfig(flag_bare_union_select=False)
    )
    assert result.is_threat is False
