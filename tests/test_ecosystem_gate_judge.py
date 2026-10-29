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
    test: str, exception: str, message: str, reason: str = "D-1"
) -> dict[str, str]:
    return {"test": test, "exception": exception, "message": message, "reason": reason}


def test_failures_are_read_from_the_short_summary_only() -> None:
    failures = judge.parse_failures(PYTEST_OUTPUT)
    assert sorted(failures) == [
        "tests/test_a.py::test_one",
        "tests/test_a.py::test_two[a b]",
        "tests/test_b.py::test_three",
        "tests/test_d.py::test_bare_exception",
        "tests/test_d.py::test_plain_assert",
    ]
    plain = failures["tests/test_d.py::test_plain_assert"]
    assert (plain.exception, plain.message) == ("", "assert 1 == 2")
    assert failures["tests/test_d.py::test_bare_exception"].exception == "KeyError"
    assert failures["tests/test_a.py::test_one"].exception == "AttributeError"
    assert failures["tests/test_b.py::test_three"].message == ""


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
        entry("tests/test_b.py::test_three", "", ""),
        entry("tests/test_d.py::test_plain_assert", "", "assert 1 == 2"),
        entry("tests/test_d.py::test_bare_exception", "KeyError", ""),
    ]
    errors, notices = judge.judge(failures, expected)
    assert errors == []
    assert "expected failure tests/test_a.py::test_one: D-9" in notices


def test_an_unlisted_failure_is_an_error() -> None:
    failures = judge.parse_failures(PYTEST_OUTPUT)
    errors, _ = judge.judge(failures, [])
    assert len(errors) == 5
    assert all(error.startswith("unlisted failure") for error in errors)


def test_a_listed_test_failing_with_another_signature_is_an_error() -> None:
    failures = judge.parse_failures(PYTEST_OUTPUT)
    expected = [
        entry("tests/test_a.py::test_one", "TypeError", "no attribute 'lstrip'"),
        entry("tests/test_a.py::test_two[a b]", "AssertionError", "something else"),
        entry("tests/test_b.py::test_three", "", ""),
        entry("tests/test_d.py::test_plain_assert", "", "assert 1 == 2"),
        entry("tests/test_d.py::test_bare_exception", "KeyError", ""),
    ]
    errors, notices = judge.judge(failures, expected)
    assert len(errors) == 2
    assert all("another signature" in error for error in errors)
    assert len(notices) == 3


def test_a_qualified_exception_name_matches_its_short_listed_name() -> None:
    failures = judge.parse_failures(
        "=== short test summary info ===\n"
        "FAILED t.py::x - pydantic_core._pydantic_core.ValidationError: 1 error\n"
    )
    errors, _ = judge.judge(failures, [entry("t.py::x", "ValidationError", "1 error")])
    assert errors == []


def test_a_listed_test_that_passes_is_an_error() -> None:
    failures = judge.parse_failures(PYTEST_OUTPUT)
    expected = [entry("tests/test_gone.py::test_fixed", "Boom", "x", "D-4")]
    errors, _ = judge.judge(failures, expected)
    assert "listed test tests/test_gone.py::test_fixed no longer fails (D-4)" in errors


def test_a_missing_file_is_an_empty_list(tmp_path: Path) -> None:
    assert judge.load_expected(tmp_path / "absent.json") == []


def test_an_entry_missing_a_key_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "x.json"
    path.write_text(json.dumps([{"test": "t", "exception": "E", "message": "m"}]))
    with pytest.raises(ValueError, match="reason"):
        judge.load_expected(path)


def test_main_exit_codes_and_annotations(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    output = tmp_path / "out.txt"
    output.write_text(PYTEST_OUTPUT)
    expected = tmp_path / "x.json"
    expected.write_text(
        json.dumps(
            [
                entry("tests/test_a.py::test_one", "AttributeError", "lstrip"),
                entry("tests/test_a.py::test_two[a b]", "AssertionError", "1 == 2"),
                entry("tests/test_b.py::test_three", "", ""),
                entry("tests/test_d.py::test_plain_assert", "", "1 == 2"),
                entry("tests/test_d.py::test_bare_exception", "KeyError", ""),
            ]
        )
    )
    assert judge.main(["j", str(output), str(expected)]) == 0
    assert "::notice::expected failure" in capsys.readouterr().out
    assert judge.main(["j", str(output), str(tmp_path / "none.json")]) == 1
    assert "::error::unlisted failure" in capsys.readouterr().out
    assert judge.main(["j"]) == 2
