import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

STACK_DIR = Path(__file__).resolve().parent / "stack"
DEST = STACK_DIR / "app"
REPO_URL = "https://github.com/Guard-Core/fastapi-guard.git"


def _version_key(tag: str) -> tuple[int, ...] | tuple[int]:
    parts = tag.split(".")
    if not all(part.isdigit() for part in parts):
        return (0,)
    return tuple(int(part) for part in parts)


def latest_tag() -> str:
    result = subprocess.run(
        ["git", "ls-remote", "--tags", "--refs", REPO_URL],
        capture_output=True,
        text=True,
        check=True,
    )
    tags = [line.rsplit("refs/tags/", 1)[-1] for line in result.stdout.splitlines()]
    if not tags:
        raise RuntimeError(f"No tags found on {REPO_URL}")
    return max(tags, key=_version_key)


def copy_example_app(source_repo: Path) -> None:
    example = source_repo / "examples" / "advanced_app"
    if not example.is_dir():
        raise RuntimeError(f"examples/advanced_app not found under {source_repo}")
    if DEST.exists():
        shutil.rmtree(DEST)
    shutil.copytree(example / "app", DEST)


def fetch(ref: str | None = None, local_repo: str | None = None) -> str:
    local_repo = local_repo or os.environ.get("LIVE_SMOKE_FASTAPI_GUARD_LOCAL")
    if local_repo:
        repo_path = Path(local_repo)
        copy_example_app(repo_path)
        return subprocess.run(
            ["git", "describe", "--tags", "--abbrev=0"],
            cwd=repo_path,
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()

    ref = ref or os.environ.get("LIVE_SMOKE_FASTAPI_GUARD_REF") or latest_tag()
    with tempfile.TemporaryDirectory() as tmp:
        clone_dir = Path(tmp) / "fastapi-guard"
        subprocess.run(
            [
                "git",
                "clone",
                "--depth",
                "1",
                "--branch",
                ref,
                REPO_URL,
                str(clone_dir),
            ],
            check=True,
        )
        copy_example_app(clone_dir)
    return ref


def main() -> int:
    ref = fetch()
    print(f"fetched examples/advanced_app/app from fastapi-guard@{ref} -> {DEST}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
