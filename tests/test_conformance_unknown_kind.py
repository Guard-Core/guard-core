import pytest
import run_fixtures
from run_fixtures import STAGED_FIELDS, load_index, replay_suites, suite_cases

from guard_core.handlers.suspatterns_handler import sus_patterns_handler
from guard_core.models import SecurityConfig


async def test_a_suite_of_an_unknown_kind_fails_closed_and_replays_none_of_its_cases(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sus_patterns_handler.configure(SecurityConfig(**STAGED_FIELDS))
    real_index = load_index()
    real_case = suite_cases("xss")[0]
    index = {
        **real_index,
        "suites": {
            **real_index["suites"],
            "future_suite": {
                "case_count": 1,
                "kind": "future_kind",
                "consumers": ["python"],
            },
        },
    }
    monkeypatch.setattr(run_fixtures, "load_index", lambda: index)
    real_cases = run_fixtures.suite_cases
    monkeypatch.setattr(
        run_fixtures,
        "suite_cases",
        lambda name: [real_case] if name == "future_suite" else real_cases(name),
    )

    failures, total = await replay_suites(["future_suite"], {})

    assert len(failures) == 1
    assert "future_suite" in failures[0] and "future_kind" in failures[0]
    assert total == 0
