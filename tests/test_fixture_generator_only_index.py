import json
import sys
from pathlib import Path

import pytest

from guard_core.models import SecurityConfig

_TOOLS = Path(__file__).resolve().parent.parent / "specs" / "fixtures" / "tools"


def test_an_only_run_refreshes_the_counts_of_its_suites_and_keeps_the_rest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.syspath_prepend(str(_TOOLS))
    sys.modules.pop("generate_fixtures", None)
    import generate_fixtures

    committed = {
        "engine_commit": "committed-commit",
        "generated_at": "committed-stamp",
        "suites": {
            "a": {"case_count": 1, "kind": "detect", "consumers": ["x"]},
            "b": {"case_count": 7, "kind": "detect", "consumers": ["x"]},
        },
        "cost_budgets": {"budgets": {"w": {"reference_ms": 9.1}}},
    }
    (tmp_path / "index.json").write_text(json.dumps(committed))
    monkeypatch.setattr(generate_fixtures, "CASES_DIR", tmp_path)
    results = {"a": {"suite": "a", "kind": "detect", "cases": [{}, {}, {}]}}
    config = SecurityConfig(
        enable_redis=False, rate_limit=10, ban_on_hostile_signals=False
    )

    generate_fixtures.write_corpus(results, config, write_index=False)

    written = json.loads((tmp_path / "index.json").read_text())
    assert written["suites"]["a"]["case_count"] == 3
    assert written["suites"]["b"]["case_count"] == 7
    assert {k: v for k, v in written.items() if k != "suites"} == {
        k: v for k, v in committed.items() if k != "suites"
    }
