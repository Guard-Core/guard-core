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
    monkeypatch.delenv("LIVE_SMOKE_FASTAPI_GUARD_LOCAL", raising=False)

    with pytest.raises(fetch_example_app.ExampleUnavailable) as raised:
        fetch_example_app.fetch(ref="v9.0.0")

    assert "v9.0.0 does not exist" in str(raised.value)
    assert "LIVE_SMOKE_FASTAPI_GUARD_LOCAL" in str(raised.value)


def test_a_ref_without_the_example_app_fails_with_the_instruction(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = _git_repo_without_example(tmp_path / "origin")
    monkeypatch.setattr(fetch_example_app, "REPO_URL", str(repo))
    monkeypatch.delenv("LIVE_SMOKE_FASTAPI_GUARD_LOCAL", raising=False)

    with pytest.raises(fetch_example_app.ExampleUnavailable) as raised:
        fetch_example_app.fetch(ref="main")

    assert "examples/advanced_app/app not found" in str(raised.value)
    assert "LIVE_SMOKE_FASTAPI_GUARD_REF" in str(raised.value)


def _git_repo_with_example(path: Path, tag: str) -> Path:
    repo = _git_repo_without_example(path)
    app = repo / "examples" / "advanced_app" / "app"
    app.mkdir(parents=True)
    (app / "main.py").write_text("app = None\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
    identity = [
        "-c",
        "user.name=Renn F",
        "-c",
        "user.email=rennf93@users.noreply.github.com",
        "-c",
        "commit.gpgsign=false",
        "-c",
        "tag.gpgsign=false",
    ]
    subprocess.run(
        ["git", "-C", str(repo), *identity, "commit", "-q", "-m", "example"],
        check=True,
    )
    subprocess.run(["git", "-C", str(repo), *identity, "tag", tag], check=True)
    return repo


def test_a_baseline_tag_wins_over_the_ref_and_drops_the_guard_core_wheel(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = _git_repo_with_example(tmp_path / "origin", "v8.0.2")
    stack = tmp_path / "stack"
    (stack / "wheels").mkdir(parents=True)
    stale = stack / "wheels" / "guard_core-5.0.0-py3-none-any.whl"
    stale.write_bytes(b"")
    built: list[Path] = []
    monkeypatch.setattr(fetch_example_app, "REPO_URL", str(repo))
    monkeypatch.setattr(fetch_example_app, "STACK_DIR", stack)
    monkeypatch.setattr(fetch_example_app, "DEST", stack / "app")
    monkeypatch.setattr(fetch_example_app, "build_wheel", built.append)
    monkeypatch.delenv("LIVE_SMOKE_FASTAPI_GUARD_LOCAL", raising=False)
    monkeypatch.setenv("LIVE_SMOKE_BASELINE", "v8.0.2")
    monkeypatch.setenv("LIVE_SMOKE_FASTAPI_GUARD_REF", "v9.0.0")

    assert fetch_example_app.fetch() == "v8.0.2"

    assert (stack / "app" / "main.py").is_file()
    assert not stale.exists()
    assert len(built) == 1


def test_a_baseline_tag_that_does_not_exist_fails_with_the_instruction(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = _git_repo_with_example(tmp_path / "origin", "v8.0.2")
    monkeypatch.setattr(fetch_example_app, "REPO_URL", str(repo))
    monkeypatch.delenv("LIVE_SMOKE_FASTAPI_GUARD_LOCAL", raising=False)
    monkeypatch.setenv("LIVE_SMOKE_BASELINE", "v0.0.0")

    with pytest.raises(fetch_example_app.ExampleUnavailable) as raised:
        fetch_example_app.fetch()

    assert "v0.0.0 does not exist" in str(raised.value)
