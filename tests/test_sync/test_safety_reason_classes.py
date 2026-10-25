import ast
import re
from collections.abc import Callable
from pathlib import Path

import generate_safety_gates
import pytest
from generate_safety_gates import FAILING_CLASSES, UNPINNED_CLASSES, Job, classify
from run_fixtures import safety_case_failure, suite_cases

_Job = Job
_Result = tuple[str, str, bool, str, str]

_REPO_ROOT = next(
    path for path in Path(__file__).resolve().parents if (path / "guard_core").is_dir()
)
_ENGINE_DIR = _REPO_ROOT / "guard_core" / "detection_engine"
_REASON_TEXT = re.compile(
    r"""Pattern (?:validation|timed out|appears|extrapolated|contains)[^'"\\\n]*"""
)
_NOT_A_VERDICT_REASON = ("Pattern validation cache not trusted",)
_SAFETY_CHAIN_FILES = sorted(_ENGINE_DIR.glob("_redos_*.py")) + [
    _ENGINE_DIR / "compiler.py"
]


def _constant_text(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        return "".join(
            part.value
            if isinstance(part, ast.Constant) and isinstance(part.value, str)
            else "{}"
            for part in node.values
        )
    return None


def _engine_reason_texts() -> set[str]:
    reasons: set[str] = set()
    for path in _SAFETY_CHAIN_FILES:
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            text = _constant_text(node)
            if text is None:
                continue
            reasons.update(
                found.rstrip()
                for found in _REASON_TEXT.findall(text)
                if not found.startswith(_NOT_A_VERDICT_REASON)
            )
    return reasons


_SD = "Pattern validation stray verification"
_PV = "Pattern validation"
# Every reason text the walk finds, with the class D-91 item 2 gives it.
EXPECTED_CLASS: dict[str, str] = {
    "Pattern appears safe": "safe",
    "Pattern contains a broad scan whose terminator cannot be reached by repeating "
    "its own prefix:": "structural_unreachable_terminator",
    "Pattern contains a quantified class that can absorb the mandatory literal "
    "immediately following it:": "structural_literal_absorb",
    "Pattern contains adjacent broad unbounded quantifiers:": (
        "structural_adjacent_broad"
    ),
    "Pattern contains an ambiguous optional tail inside an unbounded quantified "
    "group:": "structural_ambiguous_tail",
    "Pattern contains dangerous construct:": "dangerous_construct",
    "Pattern contains dangerous construct: {}": "dangerous_construct",
    "Pattern contains nested unbounded quantifier:": "structural_nested_unbounded",
    "Pattern extrapolated CPU cost at cap (": "over_budget",
    "Pattern extrapolated CPU cost at cap ({} chars) is {}s, exceeding the {}s "
    "safety budget (growth ratio {}x per doubling, CPU time at 32000 chars: min {}s, "
    "median {}s over {} runs, normalized by host load factor {})": "over_budget",
    "Pattern timed out on test string of length {len(test_str)}": (
        "probe_string_timeout"
    ),
    f"{_PV} alphabet exceeded its deadline": "builder_deadline",
    f"{_PV} probe construction exceeded its deadline": "builder_deadline",
    f"{_PV} repeat-prefix construction exceeded its deadline": "builder_deadline",
    f"{_PV} cannot resolve capture-dependent lookbehind": "unreachable_probe",
    f"{_PV} cannot resolve nested assertion constraints": "unreachable_probe",
    f"{_PV} cannot resolve repeat-site prefixes": "unreachable_probe",
    f"{_PV} failed:": "compile_failed",
    f"{_PV} failed: {{exc}}": "compile_failed",
    f"{_PV} failed: {{}}": "compile_failed",
    f"{_PV} group-probe candidate budget exceeded": "construction_budget",
    f"{_PV} lookbehind state budget exceeded": "construction_budget",
    f"{_PV} prefixed-probe candidate budget exceeded": "construction_budget",
    f"{_PV} repeat-prefix candidate budget exceeded": "construction_budget",
    f"{_PV} repeat-prefix length budget exceeded": "construction_budget",
    f"{_PV} repeat-prefix state budget exceeded": "construction_budget",
    f"{_PV} repeat-prefix text budget exceeded": "construction_budget",
    f"{_PV} repeat-unit budget exceeded": "construction_budget",
    f"{_PV} repeat-unit text budget exceeded": "construction_budget",
    f"{_PV} probe could not construct a test string that reaches every quantified "
    "region of this pattern; rejecting rather than certifying safety on an "
    "unreachable probe": "unreachable_probe",
    f"{_PV} probe exceeded the": "probe_subprocess_timeout",
    f"{_PV} probe exceeded the killable-subprocess timeout while measuring "
    "reach-probe cost at scale": "probe_subprocess_timeout",
    f"{_PV} probe exceeded the {{}}s killable-subprocess timeout": (
        "probe_subprocess_timeout"
    ),
    f"{_PV} probe failed to run:": "probe_subprocess_failure",
    f"{_PV} probe failed to run: {{}}": "probe_subprocess_failure",
    f"{_PV} probe failed:": "probe_subprocess_failure",
    f"{_PV} probe failed: {{}}": "probe_subprocess_failure",
    f"{_PV} probe returned malformed output:": "probe_subprocess_failure",
    f"{_PV} probe returned malformed output: {{}}": "probe_subprocess_failure",
    f"{_SD} exceeded its CPU budget": "stray_cpu_budget",
    f"{_SD} exceeded its killable-subprocess timeout": "probe_subprocess_timeout",
    f"{_SD} killable-subprocess exited unexpectedly": "probe_subprocess_failure",
    f"{_SD} killable-subprocess failed to run": "probe_subprocess_failure",
    f"{_SD} killable-subprocess returned malformed output": "probe_subprocess_failure",
}


def _unresolvable_raises() -> list[str]:
    """Locations where a TimeoutError is raised with a message the walk cannot read."""
    found: list[str] = []
    for path in _SAFETY_CHAIN_FILES:
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if (
                isinstance(node, ast.Raise)
                and isinstance(node.exc, ast.Call)
                and isinstance(node.exc.func, ast.Name)
                and node.exc.func.id == "TimeoutError"
                and node.exc.args
                and _constant_text(node.exc.args[0]) is None
            ):
                found.append(f"{path.name}:{node.lineno}")
    return found


def test_the_walk_finds_the_reasons_the_engine_raises() -> None:
    reasons = _engine_reason_texts()
    assert len(reasons) >= 30
    assert "Pattern validation alphabet exceeded its deadline" in reasons
    assert (
        "Pattern validation repeat-prefix construction exceeded its deadline" in reasons
    )
    assert any(reason.startswith("Pattern appears safe") for reason in reasons)


def test_every_reason_the_engine_can_produce_is_in_the_expected_class_table() -> None:
    reasons = _engine_reason_texts()
    assert sorted(reasons - EXPECTED_CLASS.keys()) == []
    assert sorted(EXPECTED_CLASS.keys() - reasons) == []


def test_every_reason_classifies_as_the_class_the_table_expects() -> None:
    wrong = {
        reason: (classify(reason), expected)
        for reason, expected in EXPECTED_CLASS.items()
        if classify(reason) != expected
    }
    assert wrong == {}


def test_no_reason_the_engine_raises_has_a_message_the_walk_cannot_resolve() -> None:
    assert _unresolvable_raises() == []


def test_no_reason_classifies_as_other() -> None:
    assert "other" not in set(EXPECTED_CLASS.values())
    assert classify("a reason no rule names") == "other"


def test_a_probe_subprocess_failure_fails_the_replay_case_with_its_first_line() -> None:
    case = {"id": "x", "expected": {"safe": False, "reason_class": "over_budget"}}
    reason = "Pattern validation probe failed: sre crash\nTraceback second line"
    message = safety_case_failure(case, False, classify(reason), reason)
    assert message == "safety_gates/x: probe_subprocess_failure reason: " + (
        "Pattern validation probe failed: sre crash"
    )


@pytest.mark.parametrize("observed_class", ["other", "probe_subprocess_failure"])
def test_the_replay_fails_on_other_and_on_a_subprocess_failure(
    observed_class: str,
) -> None:
    case = {"id": "x", "expected": {"safe": False, "reason_class": observed_class}}
    assert safety_case_failure(case, False, observed_class, "why") is not None


def test_the_generator_fails_on_exactly_other_and_a_subprocess_failure() -> None:
    assert set(FAILING_CLASSES) == {"other", "probe_subprocess_failure"}


def test_the_generator_stops_on_a_failing_reason(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(generate_safety_gates, "harvest", list)
    monkeypatch.setattr(generate_safety_gates, "CURATED", [("a+b", "both")])
    monkeypatch.setattr(generate_safety_gates, "FIXED_CASES", [])
    monkeypatch.setattr(
        generate_safety_gates,
        "_worker",
        lambda job: (
            job[0],
            job[1],
            False,
            "Pattern validation probe failed: boom",
            "ok",
        ),
    )
    monkeypatch.setattr(generate_safety_gates, "ProcessPoolExecutor", _InlinePool)
    with pytest.raises(SystemExit, match="probe_subprocess_failure reason: .*boom"):
        generate_safety_gates.build_suite()


class _InlinePool:
    def __init__(self, max_workers: int) -> None:
        self.max_workers = max_workers

    def __enter__(self) -> "_InlinePool":
        return self

    def __exit__(self, *_exc: object) -> None:
        return None

    @staticmethod
    def map(function: Callable[[_Job], _Result], jobs: list[_Job]) -> list[_Result]:
        return [function(job) for job in jobs]


@pytest.mark.parametrize(
    "reason",
    [
        "Pattern validation probe construction exceeded its deadline",
        "Pattern validation repeat-prefix construction exceeded its deadline",
        "Pattern validation alphabet exceeded its deadline",
    ],
)
def test_every_exceeded_its_deadline_reason_is_builder_deadline(reason: str) -> None:
    assert classify(reason) == "builder_deadline"


def test_the_construction_budget_trigger_is_pinned_by_a_fixture_case() -> None:
    cases = {case["id"]: case for case in suite_cases("safety_gates")}
    pinned = cases["safety_cost_verdict_construction_budget_01"]
    assert pinned["expected"] == {"safe": False, "reason_class": "construction_budget"}
    assert "stray_cpu_budget" in UNPINNED_CLASSES
    assert "probe_subprocess_failure" in UNPINNED_CLASSES


def test_no_engine_reason_class_would_add_a_case_to_the_safety_corpus() -> None:
    pinned = {case["expected"]["reason_class"] for case in suite_cases("safety_gates")}
    classes = {classify(reason) for reason in _engine_reason_texts()}
    assert classes <= pinned | set(UNPINNED_CLASSES)
