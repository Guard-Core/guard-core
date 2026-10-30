from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import NamedTuple, TypedDict

SUMMARY_START = re.compile(r"^=+ short test summary info =+$")
SECTION_END = re.compile(r"^=+.*=+$")
FAILED_ENTRY = re.compile(r"^(FAILED|ERROR) (.+)$")
EXCEPTION_DETAIL = re.compile(r"([A-Za-z_][\w.]*)(?:: (.*))?", re.DOTALL)
REQUIRED_KEYS = ("test", "exception", "message", "reason")
OUTCOMES = ("failed", "error")


class _RequiredEntry(TypedDict):
    test: str
    exception: str
    message: str
    reason: str


class Entry(_RequiredEntry, total=False):
    # Scopes the entry to these Python versions; absent means every version.
    python: list[str]
    # "error" for a setup or teardown ERROR row; absent means the FAILED row.
    outcome: str
    # True when the failure text must equal ``message``; absent means it must start
    # with it (a message is never matched anywhere inside a longer one).
    exact: bool


class Failure(NamedTuple):
    test: str
    outcome: str
    exception: str
    message: str


def parse_failures(pytest_output: str) -> dict[tuple[str, str], Failure]:
    failures: dict[tuple[str, str], Failure] = {}
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
        outcome = entry.group(1).lower()
        test, _, detail = entry.group(2).partition(" - ")
        detail = detail.strip()
        typed = EXCEPTION_DETAIL.fullmatch(detail)
        if typed:
            exception, message = typed.groups(default="")
        elif detail.startswith("assert "):
            # pytest prints a bare assert without its exception type.
            exception, message = "AssertionError", detail
        else:
            exception, message = "", detail
        failures[(test, outcome)] = Failure(test, outcome, exception, message.strip())
    return failures


def load_expected(path: Path) -> list[Entry]:
    if not path.exists():
        return []
    entries = json.loads(path.read_text(encoding="utf-8"))
    for entry in entries:
        missing = [key for key in REQUIRED_KEYS if key not in entry]
        if missing:
            raise ValueError(f"{path}: entry {entry!r} lacks {missing}")
        python = entry.get("python", [])
        if not isinstance(python, list) or not all(
            isinstance(version, str) for version in python
        ):
            raise ValueError(
                f"{path}: entry {entry!r} python is not a list of versions"
            )
        if entry.get("outcome", "failed") not in OUTCOMES:
            raise ValueError(
                f"{path}: entry {entry!r} outcome is not one of {OUTCOMES}"
            )
    return list(entries)


def _entries_for_python(
    expected: list[Entry], python: str
) -> tuple[dict[tuple[str, str], Entry], list[str]]:
    listed: dict[tuple[str, str], Entry] = {}
    duplicates: list[str] = []
    for entry in expected:
        if python not in entry.get("python", [python]):
            continue
        key = (entry["test"], entry.get("outcome", "failed"))
        if key in listed:
            duplicates.append(f"duplicate entry for {_label(key)} on Python {python}")
        listed[key] = entry
    return listed, duplicates


def _label(key: tuple[str, str]) -> str:
    test, outcome = key
    return test if outcome == "failed" else f"{test} ({outcome})"


def _signature_matches(entry: Entry, failure: Failure) -> bool:
    exception = failure.exception
    exception_ok = exception == entry["exception"] or exception.endswith(
        "." + entry["exception"]
    )
    if entry.get("exact", False):
        message_ok = failure.message == entry["message"]
    else:
        message_ok = failure.message.startswith(entry["message"])
    return exception_ok and message_ok


def judge(
    failures: dict[tuple[str, str], Failure], expected: list[Entry], python: str
) -> tuple[list[str], list[str]]:
    listed, errors = _entries_for_python(expected, python)
    notices: list[str] = []
    for key, failure in failures.items():
        test = _label(key)
        entry = listed.get(key)
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
    for key, entry in listed.items():
        if key not in failures:
            errors.append(
                f"listed test {_label(key)} no longer fails ({entry['reason']})"
            )
    return errors, notices


def main(argv: list[str]) -> int:
    if len(argv) != 4:
        print(
            "usage: ecosystem_gate_judge.py <pytest-output> <expected.json> "
            "<python-version>"
        )
        return 2
    failures = parse_failures(Path(argv[1]).read_text(encoding="utf-8"))
    errors, notices = judge(failures, load_expected(Path(argv[2])), argv[3])
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
