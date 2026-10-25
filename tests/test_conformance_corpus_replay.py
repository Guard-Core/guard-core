import json
import re
import subprocess
import sys
from pathlib import Path

import pytest
from generate_safety_gates import (
    CLASS_RULES,
    FIXED_CASES,
    RETIRED_CASES,
    UNPINNED_CLASSES,
    classify,
)
from pipeline_harness import DEFAULT_STATE
from run_fixtures import (
    CASES_DIR,
    STAGED_FIELDS,
    load_index,
    safety_case_failure,
    suite_cases,
)

from guard_core import _staged_defaults
from guard_core.models import SecurityConfig

_REPO_ROOT = Path(__file__).resolve().parent.parent
_RUNNER = _REPO_ROOT / "specs" / "fixtures" / "tools" / "run_fixtures.py"


def test_every_suite_in_the_index_replays_green_through_the_reference_engine() -> None:
    completed = subprocess.run(
        [sys.executable, str(_RUNNER)],
        capture_output=True,
        text=True,
        cwd=_REPO_ROOT,
        timeout=900,
    )
    index = load_index()
    replayed = sum(
        meta["case_count"]
        for meta in index["suites"].values()
        if meta["kind"] != "pattern_safety"
    )
    assert completed.returncode == 0, (
        completed.stdout[-4000:] + completed.stderr[-2000:]
    )
    assert f"conformance green: {replayed} cases match engine" in completed.stdout


def test_every_registered_suite_file_holds_its_registered_case_count() -> None:
    suites = load_index()["suites"]
    assert {path.stem for path in CASES_DIR.glob("*.json")} - {"index"} == set(suites)
    for name, meta in suites.items():
        assert len(suite_cases(name)) == meta["case_count"], name


def test_the_safety_corpus_pins_every_class_except_the_named_unpinned_ones() -> None:
    pinned = {case["expected"]["reason_class"] for case in suite_cases("safety_gates")}
    wanted = {cls for _prefix, cls in CLASS_RULES}
    assert wanted - pinned == set(UNPINNED_CLASSES)
    assert not pinned & set(UNPINNED_CLASSES)
    assert "probe_subprocess_timeout" in UNPINNED_CLASSES
    assert {"stray_cpu_budget", "probe_subprocess_failure"} <= set(UNPINNED_CLASSES)
    assert "construction_budget" in pinned


def test_every_unpinned_class_names_a_unit_test_that_exists_in_both_trees() -> None:
    for cls, entry in UNPINNED_CLASSES.items():
        assert entry["reason"], cls
        if entry["unit_pin"] is None:
            continue
        path, name = entry["unit_pin"].split("::")
        for tree_path in (path, path.replace("tests/", "tests/test_sync/", 1)):
            assert re.search(
                rf"^def {name}\(", (_REPO_ROOT / tree_path).read_text(), re.MULTILINE
            ), f"{cls}: {name} is missing from {tree_path}"


def test_the_builder_deadline_reason_classifies_as_its_unpinned_class() -> None:
    reason = "Pattern validation probe construction exceeded its deadline"
    assert classify(reason) == "builder_deadline"
    assert "builder_deadline" in UNPINNED_CLASSES


def test_the_index_publishes_the_unpinned_classes_and_the_retired_ids() -> None:
    published = load_index()["suites"]["safety_gates"]
    assert published["unpinned_classes"] == UNPINNED_CLASSES
    assert published["retired_case_ids"] == RETIRED_CASES
    ids = {case["id"] for case in suite_cases("safety_gates")}
    for retired in RETIRED_CASES:
        assert retired["id"] not in ids
        assert retired["replaced_by"] in ids


def test_the_fixed_timing_cases_are_in_the_corpus_with_their_margins() -> None:
    cases = {case["id"]: case for case in suite_cases("safety_gates")}
    for fixed in FIXED_CASES:
        case = cases[fixed["id"]]
        assert case["expected"] == {
            "safe": False,
            "reason_class": fixed["reason_class"],
        }
    over_budget = cases["safety_cost_verdict_over_budget_02"]["reference"]
    assert over_budget["margin"] >= 100
    string_timeout = cases["safety_test_strings_probe_string_timeout_01"]["reference"]
    assert (
        min(
            string_timeout["margin_over_threshold"], string_timeout["margin_under_kill"]
        )
        >= 5
    )


@pytest.mark.parametrize(
    ("want_class", "observed_class", "failed"),
    [
        ("over_budget", "over_budget", False),
        ("over_budget", "probe_subprocess_timeout", False),
        ("probe_string_timeout", "probe_subprocess_timeout", False),
        ("builder_deadline", "probe_subprocess_timeout", False),
        ("stray_cpu_budget", "probe_subprocess_timeout", False),
        ("construction_budget", "probe_subprocess_timeout", True),
        ("over_budget", "probe_subprocess_failure", True),
        ("over_budget", "other", True),
        ("over_budget", "safe", True),
        ("structural_nested_unbounded", "probe_subprocess_timeout", True),
        ("structural_nested_unbounded", "structural_adjacent_broad", True),
        ("compile_failed", "compile_failed", False),
    ],
)
def test_a_loaded_host_may_turn_only_the_timed_classes_into_a_subprocess_timeout(
    want_class: str, observed_class: str, failed: bool
) -> None:
    case = {"id": "x", "expected": {"safe": False, "reason_class": want_class}}
    outcome = safety_case_failure(case, False, observed_class)
    assert (outcome is not None) is failed


def test_the_safe_verdict_is_exact() -> None:
    case = {"id": "x", "expected": {"safe": True, "reason_class": "safe"}}
    assert safety_case_failure(case, True, "safe") is None
    assert safety_case_failure(case, False, "safe") is not None
    assert safety_case_failure(case, True, "over_budget") is not None


def test_the_index_publishes_the_pipeline_defaults_of_every_case() -> None:
    published = load_index()["pipeline_defaults"]
    assert published == json.loads(json.dumps(DEFAULT_STATE))
    assert STAGED_FIELDS.items() <= published.items()


def test_the_index_publishes_the_events_prefix_rules() -> None:
    rules = load_index()["comparison"]["events_prefix_rules"]
    assert [rule["event_type"] for rule in rules] == ["redis_error"]


def test_every_tool_config_states_the_staged_fields() -> None:
    from events_harness import _make_events_config
    from pipeline_harness import _make_config, _StubGeoHandler
    from redis_interop_cases import _rio_config

    configs = [
        SecurityConfig(**STAGED_FIELDS),
        _make_config({"config": {"whitelist": ["203.0.113.9"]}}, _StubGeoHandler({})),
        _make_events_config({"config": {}}, _StubGeoHandler({})),
        _rio_config(),
    ]
    for config in configs:
        assert set(STAGED_FIELDS) <= config.model_fields_set
        assert _staged_defaults._changed_default_entries(config) == []
