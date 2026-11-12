import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

STACK_DIR = Path(__file__).resolve().parent / "stack"
DEST = STACK_DIR / "app"
REPO_URL = os.environ.get(
    "LIVE_SMOKE_FASTAPI_GUARD_REPO", "https://github.com/Guard-Core/fastapi-guard.git"
)
# The 5.0.0 smoke runs fastapi-guard 9.0.0's example. Until that tag exists,
# set LIVE_SMOKE_FASTAPI_GUARD_LOCAL to a checkout.
EXAMPLE_REF = "v9.0.0"
BASELINE_DATE_FILE = "baseline-date.txt"


class ExampleUnavailable(RuntimeError):
    pass


def copy_example_app(source_repo: Path) -> None:
    example = source_repo / "examples" / "advanced_app"
    if not (example / "app").is_dir():
        raise ExampleUnavailable(
            f"examples/advanced_app/app not found under {source_repo}; set "
            "LIVE_SMOKE_FASTAPI_GUARD_LOCAL or LIVE_SMOKE_FASTAPI_GUARD_REF to a "
            "fastapi-guard tree that has it"
        )
    if DEST.exists():
        shutil.rmtree(DEST)
    shutil.copytree(example / "app", DEST)


def build_wheel(source_repo: Path) -> None:
    wheels = STACK_DIR / "wheels"
    for stale in wheels.glob("fastapi_guard-*.whl"):
        stale.unlink()
    subprocess.run(
        ["uv", "build", "--wheel", "--out-dir", str(wheels), str(source_repo)],
        check=True,
    )


def _use_checkout(source_repo: Path) -> None:
    wheels = STACK_DIR / "wheels"
    cutoff = wheels / BASELINE_DATE_FILE
    cutoff.unlink(missing_ok=True)
    if os.environ.get("LIVE_SMOKE_BASELINE"):
        # a baseline runs the tag's own guard-core, resolved from PyPI as of the tag's
        # commit date; the date travels in a file next to the wheels (COPY wheels/
        # already ships it, so compose and the workflow need no new plumbing)
        for stale in wheels.glob("guard_core-*.whl"):
            stale.unlink()
        cutoff.write_text(
            subprocess.run(
                ["git", "-C", str(source_repo), "log", "-1", "--format=%cI", "HEAD"],
                capture_output=True,
                text=True,
                check=True,
            ).stdout.strip()
            + "\n",
            encoding="utf-8",
        )
    copy_example_app(source_repo)
    build_wheel(source_repo)


def _clone(ref: str, destination: Path) -> None:
    result = subprocess.run(
        ["git", "clone", "--depth", "1", "--branch", ref, REPO_URL, str(destination)],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise ExampleUnavailable(
            f"fastapi-guard ref {ref} does not exist "
            f"({result.stderr.strip().splitlines()[-1]}); "
            "set LIVE_SMOKE_FASTAPI_GUARD_LOCAL or LIVE_SMOKE_FASTAPI_GUARD_REF"
        )


def fetch(ref: str | None = None, local_repo: str | None = None) -> str:
    (STACK_DIR / "wheels").mkdir(exist_ok=True)
    local_repo = local_repo or os.environ.get("LIVE_SMOKE_FASTAPI_GUARD_LOCAL")
    if local_repo:
        repo_path = Path(local_repo)
        _use_checkout(repo_path)
        return subprocess.run(
            ["git", "describe", "--tags", "--abbrev=0"],
            cwd=repo_path,
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()

    ref = (
        ref
        or os.environ.get("LIVE_SMOKE_BASELINE")
        or os.environ.get("LIVE_SMOKE_FASTAPI_GUARD_REF")
        or EXAMPLE_REF
    )
    with tempfile.TemporaryDirectory() as tmp:
        clone_dir = Path(tmp) / "fastapi-guard"
        _clone(ref, clone_dir)
        _use_checkout(clone_dir)
    return ref


def main() -> int:
    try:
        ref = fetch()
    except ExampleUnavailable as error:
        print(error, file=sys.stderr)
        return 1
    print(f"fetched examples/advanced_app/app from fastapi-guard@{ref} -> {DEST}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
