import re
import subprocess
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parent.parent
_MARKER = re.compile(r"^(<<<<<<< |=======$|>>>>>>> )", re.MULTILINE)


def _tracked_files() -> list[Path]:
    listing = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=_REPO_ROOT,
        capture_output=True,
        check=True,
    ).stdout.decode("utf-8")
    return [_REPO_ROOT / name for name in listing.split("\0") if name]


def _marker_lines(text: str) -> list[int]:
    return [text.count("\n", 0, match.start()) + 1 for match in _MARKER.finditer(text)]


def test_marker_pattern_finds_a_conflict_block() -> None:
    block = "a\n<<<<<<< HEAD\nb\n=======\nc\n>>>>>>> 0a1b2c3 (msg)\nd\n"

    assert _marker_lines(block) == [2, 4, 6]


def test_marker_pattern_ignores_text_that_only_resembles_one() -> None:
    assert _marker_lines("x <<<<<<< y\n==== \n========\n") == []


def test_no_tracked_text_file_holds_a_merge_conflict_marker() -> None:
    found: list[str] = []
    for path in _tracked_files():
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        found.extend(
            f"{path.relative_to(_REPO_ROOT)}:{line}" for line in _marker_lines(text)
        )

    assert found == []


@pytest.mark.parametrize("name", ["CHANGELOG.md", "docs/release-notes.md"])
def test_the_release_notes_files_hold_no_marker(name: str) -> None:
    text = (_REPO_ROOT / name).read_text(encoding="utf-8")

    assert _marker_lines(text) == []
