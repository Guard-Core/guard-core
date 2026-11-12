import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

STACK_DIR = Path(__file__).resolve().parent / "stack"
DEST = STACK_DIR / "app"
REPO_URL = "https://github.com/Guard-Core/fastapi-guard.git"
# The 5.0.0 smoke runs fastapi-guard 9.0.0's example. Until that tag exists,
# set LIVE_SMOKE_FASTAPI_GUARD_LOCAL to a checkout.
EXAMPLE_REF = "v9.0.0"


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
        subprocess.run(
            [
                "uv",
                "build",
                "--wheel",
                "--out-dir",
                str(STACK_DIR / "wheels"),
                str(repo_path),
            ],
            check=True,
        )
        return subprocess.run(
            ["git", "describe", "--tags", "--abbrev=0"],
            cwd=repo_path,
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()

    ref = ref or os.environ.get("LIVE_SMOKE_FASTAPI_GUARD_REF") or EXAMPLE_REF
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
