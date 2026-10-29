from collections.abc import Callable, Sequence
from pathlib import Path

import pytest

from tests.ecosystem_gate_scripts import load_gate_script

proof = load_gate_script("ecosystem_gate_cap_proof")

CAPPED = ["pydantic>=2", "guard-core>=4.4.0,<5"]
OPEN = ["pydantic>=2", "guard-core>=4.4.0"]
NO_SOLUTION = "x No solution found when resolving dependencies:"


def fake_pypi(requires: dict[str, list[str]]) -> Callable[[str], dict[str, object]]:
    def fetch(url: str) -> dict[str, object]:
        parts = url.split("/")
        if len(parts) == 6:
            releases: dict[str, list[dict[str, bool]]] = {
                version: [{"yanked": False}] for version in requires
            }
            releases["99.0.0rc1"] = [{"yanked": False}]
            releases["0.0.1"] = []
            return {"releases": releases}
        return {"info": {"requires_dist": requires[parts[-2]]}}

    return fetch


def fake_resolver(
    capped_versions: set[str], calls: list[Sequence[str]], failure: str = NO_SOLUTION
) -> Callable[[Sequence[str], str, Sequence[str]], tuple[int, str]]:
    def resolve(
        requirements: Sequence[str], python_version: str, find_links: Sequence[str]
    ) -> tuple[int, str]:
        calls.append(requirements)
        dist_pin = requirements[0].split("==")[1]
        if dist_pin in capped_versions:
            return 1, failure
        return 0, "resolved"

    return resolve


def run(
    requires: dict[str, list[str]],
    tag: str,
    tag_requires: list[str],
    capped_versions: set[str],
    calls: list[Sequence[str]],
    failure: str = NO_SOLUTION,
) -> tuple[str, list[str]]:
    result: tuple[str, list[str]] = proof.prove_cap(
        "tornadoapi-guard",
        tag,
        "5.0.0",
        ["/wheels"],
        "3.10",
        tag_requires,
        fake_pypi(requires),
        fake_resolver(capped_versions, calls, failure),
    )
    return result


def test_a_release_that_admits_the_pr_version_runs_the_suite_without_resolving() -> (
    None
):
    calls: list[Sequence[str]] = []
    outcome, errors = run({"2.0.0": OPEN}, "2.0.0", OPEN, set(), calls)
    assert (outcome, errors, calls) == ("admitted", [], [])


def test_a_release_without_an_engine_requirement_is_admitted() -> None:
    outcome, errors = run({"4.0.0": ["httpx"]}, "4.0.0", ["httpx"], set(), [])
    assert (outcome, errors) == ("admitted", [])


def test_a_proven_cap_with_a_resolving_control_passes() -> None:
    calls: list[Sequence[str]] = []
    versions = {"2.0.1": CAPPED, "2.0.0": OPEN, "1.9.0": OPEN}
    outcome, errors = run(versions, "2.0.1", CAPPED, {"2.0.1"}, calls)
    assert (outcome, errors) == ("capped", [])
    assert calls == [
        ["tornadoapi-guard==2.0.1", "guard-core==5.0.0"],
        ["tornadoapi-guard==2.0.0", "guard-core==5.0.0"],
    ]


def test_a_cap_that_still_resolves_fails() -> None:
    versions = {"2.0.1": CAPPED, "2.0.0": OPEN}
    _, errors = run(versions, "2.0.1", CAPPED, set(), [])
    assert len(errors) == 1
    assert "did not report it unsatisfiable (exit 0)" in errors[0]


def test_a_resolver_failure_that_is_not_unsatisfiability_fails() -> None:
    versions = {"2.0.1": CAPPED, "2.0.0": OPEN}
    _, errors = run(versions, "2.0.1", CAPPED, {"2.0.1"}, [], failure="network down")
    assert len(errors) == 1
    assert "network down" in errors[0]


def test_a_control_that_does_not_resolve_fails() -> None:
    versions = {"2.0.1": CAPPED, "2.0.0": OPEN}
    _, errors = run(versions, "2.0.1", CAPPED, {"2.0.1", "2.0.0"}, [])
    assert len(errors) == 1
    assert errors[0].startswith("negative control tornadoapi-guard==2.0.0")


def test_no_uncapped_release_in_history_fails() -> None:
    _, errors = run({"2.0.1": CAPPED}, "2.0.1", CAPPED, {"2.0.1"}, [])
    assert errors == [
        "no uncapped tornadoapi-guard release in PyPI history for the control"
    ]


def test_a_tag_range_that_disagrees_with_pypi_fails() -> None:
    versions = {"2.0.1": CAPPED, "2.0.0": OPEN}
    _, errors = run(versions, "2.0.1", OPEN, {"2.0.1"}, [])
    assert len(errors) == 1
    assert "disagrees with PyPI's" in errors[0]


def test_an_extra_only_requirement_does_not_count_as_the_cap() -> None:
    spec = proof.engine_specifier(["guard-core<5; extra == 'old'", "guard-core>=4"])
    assert proof.admits(spec, "5.0.0")


def test_main_reports_the_proven_cap_with_its_own_exit_code(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    requires = tmp_path / "requires.txt"
    requires.write_text("\n".join(CAPPED))
    versions = {"2.0.1": CAPPED, "2.0.0": OPEN}
    real = proof.prove_cap
    monkeypatch.setattr(
        proof,
        "prove_cap",
        lambda *args: real(*args, fake_pypi(versions), fake_resolver({"2.0.1"}, [])),
    )
    argv = ["p", "tornadoapi-guard", "2.0.1", "5.0.0", "/wheels", "3.10", str(requires)]
    assert proof.main(argv) == proof.CAPPED_AND_PROVEN
    assert (
        "::notice::tornadoapi-guard==2.0.1 cap on guard-core proven"
        in capsys.readouterr().out
    )
    assert proof.main(["p"]) == 2
    requires.write_text("\n".join(OPEN))
    assert proof.main(argv) == 1
    assert "::error::" in capsys.readouterr().out
