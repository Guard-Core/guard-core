from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import NamedTuple

SUMMARY_START = re.compile(r"^=+ short test summary info =+$")
SECTION_END = re.compile(r"^=+.*=+$")
FAILED_ENTRY = re.compile(r"^(?:FAILED|ERROR) (.+)$")
EXCEPTION_DETAIL = re.compile(r"([A-Za-z_][\w.]*)(?:: (.*))?", re.DOTALL)
REQUIRED_KEYS = ("test", "exception", "message", "reason")


class Failure(NamedTuple):
    test: str
    exception: str
    message: str


def parse_failures(pytest_output: str) -> dict[str, Failure]:
    failures: dict[str, Failure] = {}
    in_summary = False
    for line in pytest_output.splitlines():
        if SUMMARY_START.match(line):
            in_summary = True
            continue
        if in_summary and SECTION_END.match(line):
            in_summary = False
        entry = FAILED_ENTRY.match(line) if in_summary else None
        if entry is None:
            continue
        test, _, detail = entry.group(1).partition(" - ")
        # A bare assert prints no exception type: the detail is the message.
        typed = EXCEPTION_DETAIL.fullmatch(detail.strip())
        exception, message = typed.groups(default="") if typed else ("", detail)
        failures[test] = Failure(test, exception, message.strip())
    return failures


def load_expected(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    entries = json.loads(path.read_text(encoding="utf-8"))
    for entry in entries:
        missing = [key for key in REQUIRED_KEYS if key not in entry]
        if missing:
            raise ValueError(f"{path}: entry {entry!r} lacks {missing}")
    return list(entries)


def _signature_matches(entry: dict[str, str], failure: Failure) -> bool:
    exception = failure.exception
    exception_ok = exception == entry["exception"] or exception.endswith(
        "." + entry["exception"]
    )
    return exception_ok and entry["message"] in failure.message


def judge(
    failures: dict[str, Failure], expected: list[dict[str, str]]
) -> tuple[list[str], list[str]]:
    errors: list[str] = []
    notices: list[str] = []
    listed = {entry["test"]: entry for entry in expected}
    for test, failure in failures.items():
        entry = listed.get(test)
        if entry is None:
            errors.append(
                f"unlisted failure {test}: {failure.exception}: {failure.message}"
            )
        elif _signature_matches(entry, failure):
            notices.append(f"expected failure {test}: {entry['reason']}")
        else:
            errors.append(
                f"listed test {test} fails with another signature: "
                f"{failure.exception}: {failure.message} "
                f"(listed {entry['exception']}: {entry['message']})"
            )
    for test, entry in listed.items():
        if test not in failures:
            errors.append(f"listed test {test} no longer fails ({entry['reason']})")
    return errors, notices


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print("usage: ecosystem_gate_judge.py <pytest-output> <expected.json>")
        return 2
    failures = parse_failures(Path(argv[1]).read_text(encoding="utf-8"))
    errors, notices = judge(failures, load_expected(Path(argv[2])))
    for notice in notices:
        print(f"::notice::{notice}")
    for error in errors:
        print(f"::error::{error}")
    print(
        f"Expected-failures judging: {len(failures)} failing, "
        f"{len(notices)} expected, {len(errors)} not accepted"
    )
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
