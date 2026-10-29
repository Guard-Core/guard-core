import json
from pathlib import Path

import pytest

from tests.ecosystem_gate_scripts import load_gate_script

judge = load_gate_script("ecosystem_gate_judge")

PYTEST_OUTPUT = """\
tests/test_a.py ..F
=========================== short test summary info ============================
FAILED tests/test_a.py::test_one - AttributeError: 'coroutine' has no attribute 'lstrip'
FAILED tests/test_a.py::test_two[a b] - AssertionError: assert 1 == 2
ERROR tests/test_b.py::test_three
FAILED tests/test_d.py::test_plain_assert - assert 1 == 2
FAILED tests/test_d.py::test_bare_exception - KeyError
=================== 3 failed, 10 passed in 1.00s ===================
FAILED tests/test_c.py::not_in_the_summary - Boom: nope
"""


def entry(
    test: str, exception: str, message: str, reason: str = "D-1", **scope: object
) -> dict[str, object]:
    return {
        "test": test,
        "exception": exception,
        "message": message,
        "reason": reason,
        **scope,
    }


def all_listed() -> list[dict[str, object]]:
    return [
        entry("tests/test_a.py::test_one", "AttributeError", "lstrip"),
        entry("tests/test_a.py::test_two[a b]", "AssertionError", "1 == 2"),
        entry("tests/test_b.py::test_three", "", "", outcome="error"),
        entry("tests/test_d.py::test_plain_assert", "AssertionError", "1 == 2"),
        entry("tests/test_d.py::test_bare_exception", "KeyError", ""),
    ]


def test_failures_are_read_from_the_short_summary_only() -> None:
    failures = judge.parse_failures(PYTEST_OUTPUT)
    assert sorted(failures) == [
        ("tests/test_a.py::test_one", "failed"),
        ("tests/test_a.py::test_two[a b]", "failed"),
        ("tests/test_b.py::test_three", "error"),
        ("tests/test_d.py::test_bare_exception", "failed"),
        ("tests/test_d.py::test_plain_assert", "failed"),
    ]
    plain = failures[("tests/test_d.py::test_plain_assert", "failed")]
    assert (plain.exception, plain.message) == ("AssertionError", "assert 1 == 2")
    bare = failures[("tests/test_d.py::test_bare_exception", "failed")]
    assert bare.exception == "KeyError"
    one = failures[("tests/test_a.py::test_one", "failed")]
    assert one.exception == "AttributeError"
    assert failures[("tests/test_b.py::test_three", "error")].message == ""


def test_an_untyped_detail_that_is_not_an_assert_keeps_an_empty_exception() -> None:
    failures = judge.parse_failures(
        "=== short test summary info ===\n"
        "FAILED t.py::x - Failed: DID NOT RAISE <class 'E'>\n"
        "FAILED t.py::y - (1 == 2) is false\n"
    )
    assert failures[("t.py::x", "failed")].exception == "Failed"
    assert failures[("t.py::y", "failed")][2:] == ("", "(1 == 2) is false")


def test_every_failure_listed_with_its_signature_is_accepted_with_its_reason() -> None:
    failures = judge.parse_failures(PYTEST_OUTPUT)
    expected = [
        entry(
            "tests/test_a.py::test_one",
            "AttributeError",
            "no attribute 'lstrip'",
            "D-9",
        ),
        entry("tests/test_a.py::test_two[a b]", "AssertionError", "1 == 2"),
        entry("tests/test_b.py::test_three", "", "", outcome="error"),
        entry("tests/test_d.py::test_plain_assert", "AssertionError", "assert 1 == 2"),
        entry("tests/test_d.py::test_bare_exception", "KeyError", ""),
    ]
    errors, notices = judge.judge(failures, expected, "3.10")
    assert errors == []
    assert "expected failure tests/test_a.py::test_one: D-9" in notices


def test_an_unlisted_failure_is_an_error() -> None:
    failures = judge.parse_failures(PYTEST_OUTPUT)
    errors, _ = judge.judge(failures, [], "3.10")
    assert len(errors) == 5
    assert all(error.startswith("unlisted failure") for error in errors)
    assert "unlisted failure tests/test_b.py::test_three (error): : " in errors


def test_a_listed_test_failing_with_another_signature_is_an_error() -> None:
    failures = judge.parse_failures(PYTEST_OUTPUT)
    expected = [
        entry("tests/test_a.py::test_one", "TypeError", "no attribute 'lstrip'"),
        entry("tests/test_a.py::test_two[a b]", "AssertionError", "something else"),
        entry("tests/test_b.py::test_three", "", "", outcome="error"),
        entry("tests/test_d.py::test_plain_assert", "AssertionError", "1 == 2"),
        entry("tests/test_d.py::test_bare_exception", "KeyError", ""),
    ]
    errors, notices = judge.judge(failures, expected, "3.10")
    assert len(errors) == 2
    assert all("another signature" in error for error in errors)
    assert len(notices) == 3


def test_a_qualified_exception_name_matches_its_short_listed_name() -> None:
    failures = judge.parse_failures(
        "=== short test summary info ===\n"
        "FAILED t.py::x - pydantic_core._pydantic_core.ValidationError: 1 error\n"
    )
    errors, _ = judge.judge(
        failures, [entry("t.py::x", "ValidationError", "1 error")], "3.10"
    )
    assert errors == []


def test_a_bare_assert_listed_without_its_exception_type_is_another_signature() -> None:
    failures = judge.parse_failures(PYTEST_OUTPUT)
    expected = [
        *all_listed()[:3],
        entry("tests/test_d.py::test_plain_assert", "", "1 == 2"),
        all_listed()[4],
    ]
    errors, _ = judge.judge(failures, expected, "3.10")
    assert errors == [
        "listed test tests/test_d.py::test_plain_assert fails with another signature: "
        "AssertionError: assert 1 == 2 (listed : 1 == 2)"
    ]


def test_a_failed_row_is_not_hidden_behind_a_listed_error_row_of_the_same_test() -> (
    None
):
    failures = judge.parse_failures(
        "=== short test summary info ===\n"
        "FAILED t.py::x - KeyError: body\n"
        "ERROR t.py::x - RuntimeError: teardown\n"
    )
    listed_error = entry("t.py::x", "RuntimeError", "teardown", outcome="error")
    errors, notices = judge.judge(failures, [listed_error], "3.10")
    assert errors == ["unlisted failure t.py::x: KeyError: body"]
    assert notices == ["expected failure t.py::x (error): D-1"]
    both = [listed_error, entry("t.py::x", "KeyError", "body")]
    assert judge.judge(failures, both, "3.10") == (
        [],
        ["expected failure t.py::x: D-1", "expected failure t.py::x (error): D-1"],
    )


def test_an_entry_scoped_to_one_python_is_judged_only_on_that_python() -> None:
    failures = judge.parse_failures(
        "=== short test summary info ===\nFAILED t.py::x - KeyError: only 3.14\n"
    )
    scoped = [entry("t.py::x", "KeyError", "only 3.14", python=["3.14"])]
    assert judge.judge(failures, scoped, "3.14") == (
        [],
        ["expected failure t.py::x: D-1"],
    )
    assert judge.judge(failures, scoped, "3.10") == (
        ["unlisted failure t.py::x: KeyError: only 3.14"],
        [],
    )
    assert judge.judge({}, scoped, "3.10") == ([], [])
    assert judge.judge({}, scoped, "3.14") == (
        ["listed test t.py::x no longer fails (D-1)"],
        [],
    )


def test_two_entries_for_one_test_on_one_python_are_an_error() -> None:
    failures = judge.parse_failures(
        "=== short test summary info ===\nFAILED t.py::x - KeyError: k\n"
    )
    twice = [
        entry("t.py::x", "KeyError", "k", python=["3.10", "3.14"]),
        entry("t.py::x", "KeyError", "k", python=["3.14"]),
    ]
    assert judge.judge(failures, twice, "3.10")[0] == []
    errors, _ = judge.judge(failures, twice, "3.14")
    assert errors == ["duplicate entry for t.py::x on Python 3.14"]


def test_a_listed_test_that_passes_is_an_error() -> None:
    failures = judge.parse_failures(PYTEST_OUTPUT)
    expected = [entry("tests/test_gone.py::test_fixed", "Boom", "x", "D-4")]
    errors, _ = judge.judge(failures, expected, "3.10")
    assert "listed test tests/test_gone.py::test_fixed no longer fails (D-4)" in errors


def test_a_missing_file_is_an_empty_list(tmp_path: Path) -> None:
    assert judge.load_expected(tmp_path / "absent.json") == []


def test_an_entry_missing_a_key_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "x.json"
    path.write_text(json.dumps([{"test": "t", "exception": "E", "message": "m"}]))
    with pytest.raises(ValueError, match="reason"):
        judge.load_expected(path)


@pytest.mark.parametrize(
    ("scope", "match"),
    [
        ({"python": "3.14"}, "python is not a list"),
        ({"python": [3.14]}, "python is not a list"),
        ({"outcome": "skipped"}, "outcome is not one of"),
    ],
)
def test_an_entry_with_a_bad_scope_is_rejected(
    tmp_path: Path, scope: dict[str, object], match: str
) -> None:
    path = tmp_path / "x.json"
    path.write_text(json.dumps([{**entry("t", "E", "m"), **scope}]))
    with pytest.raises(ValueError, match=match):
        judge.load_expected(path)


def test_scoped_entries_load(tmp_path: Path) -> None:
    path = tmp_path / "x.json"
    scoped = [entry("t", "E", "m", python=["3.14"], outcome="error")]
    path.write_text(json.dumps(scoped))
    assert judge.load_expected(path) == scoped


def test_main_exit_codes_and_annotations(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    output = tmp_path / "out.txt"
    output.write_text(PYTEST_OUTPUT)
    expected = tmp_path / "x.json"
    expected.write_text(json.dumps(all_listed()))
    assert judge.main(["j", str(output), str(expected), "3.10"]) == 0
    assert "::notice::expected failure" in capsys.readouterr().out
    assert judge.main(["j", str(output), str(tmp_path / "none.json"), "3.10"]) == 1
    assert "::error::unlisted failure" in capsys.readouterr().out
    assert judge.main(["j", str(output), str(expected)]) == 2
    assert "<python-version>" in capsys.readouterr().out
