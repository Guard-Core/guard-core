import os
import re
import subprocess
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parent.parent
_MARKER = re.compile(r"^(<<<<<<< |=======$|>>>>>>> )", re.MULTILINE)


_NOT_A_REPOSITORY = ("not a git repository", "does not point to a valid repository")


def _inside_a_work_tree(root: Path = _REPO_ROOT) -> bool:
    probe = subprocess.run(
        ["git", "rev-parse", "--is-inside-work-tree"],
        cwd=root,
        capture_output=True,
        text=True,
        env={**os.environ, "LC_ALL": "C", "LANGUAGE": ""},
    )
    if probe.returncode == 0:
        return probe.stdout.strip() == "true"
    if probe.returncode == 128 and any(m in probe.stderr for m in _NOT_A_REPOSITORY):
        return False
    raise RuntimeError(f"git rev-parse failed ({probe.returncode}): {probe.stderr}")


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
    if not _inside_a_work_tree():
        pytest.skip("needs a git work tree to list the tracked files")
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


def _fake_git(
    monkeypatch: pytest.MonkeyPatch, returncode: int, stdout: str, stderr: str
) -> None:
    def run(command: list[str], **_: object) -> "subprocess.CompletedProcess[str]":
        return subprocess.CompletedProcess(command, returncode, stdout, stderr)

    monkeypatch.setattr(subprocess, "run", run)


@pytest.mark.parametrize(
    ("returncode", "stdout", "stderr", "expected"),
    [
        (0, "true\n", "", True),
        (0, "false\n", "", False),
        (128, "", "fatal: not a git repository (or any parent): .git\n", False),
    ],
)
def test_the_work_tree_probe_answers_only_for_a_clear_git_verdict(
    monkeypatch: pytest.MonkeyPatch,
    returncode: int,
    stdout: str,
    stderr: str,
    expected: bool,
) -> None:
    _fake_git(monkeypatch, returncode, stdout, stderr)

    assert _inside_a_work_tree() is expected


def test_the_work_tree_probe_raises_on_any_other_git_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _fake_git(monkeypatch, 128, "", "fatal: detected dubious ownership\n")

    with pytest.raises(RuntimeError, match="dubious ownership"):
        _inside_a_work_tree()


def test_a_plain_directory_is_not_a_work_tree(tmp_path: Path) -> None:
    assert _inside_a_work_tree(tmp_path) is False


def test_a_gitfile_pointing_at_a_missing_path_is_not_a_work_tree(
    tmp_path: Path,
) -> None:
    (tmp_path / ".git").write_text("gitdir: /nonexistent/x\n", encoding="utf-8")

    assert _inside_a_work_tree(tmp_path) is False
