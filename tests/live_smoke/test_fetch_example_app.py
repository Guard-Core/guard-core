import subprocess
from pathlib import Path

import pytest

from tests.live_smoke import fetch_example_app


def _git_repo_without_example(path: Path) -> Path:
    path.mkdir()
    subprocess.run(["git", "init", "-q", "-b", "main", str(path)], check=True)
    (path / "README.md").write_text("no example here\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(path), "add", "."], check=True)
    subprocess.run(
        [
            "git",
            "-C",
            str(path),
            "-c",
            "user.name=Renn F",
            "-c",
            "user.email=rennf93@users.noreply.github.com",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-q",
            "-m",
            "init",
        ],
        check=True,
    )
    return path


def test_a_ref_that_does_not_exist_fails_with_the_instruction(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = _git_repo_without_example(tmp_path / "origin")
    monkeypatch.setattr(fetch_example_app, "REPO_URL", str(repo))

    with pytest.raises(fetch_example_app.ExampleUnavailable) as raised:
        fetch_example_app.fetch(ref="v9.0.0")

    assert "v9.0.0 does not exist" in str(raised.value)
    assert "LIVE_SMOKE_FASTAPI_GUARD_LOCAL" in str(raised.value)


def test_a_ref_without_the_example_app_fails_with_the_instruction(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = _git_repo_without_example(tmp_path / "origin")
    monkeypatch.setattr(fetch_example_app, "REPO_URL", str(repo))

    with pytest.raises(fetch_example_app.ExampleUnavailable) as raised:
        fetch_example_app.fetch(ref="main")

    assert "examples/advanced_app/app not found" in str(raised.value)
    assert "LIVE_SMOKE_FASTAPI_GUARD_REF" in str(raised.value)
