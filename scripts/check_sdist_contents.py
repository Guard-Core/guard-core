#!/usr/bin/env python3
import sys
import tarfile
from pathlib import Path

ROOT_FILES = {"LICENSE", "README.md", "pyproject.toml", "PKG-INFO"}
HATCHLING_ALWAYS_SHIPS = {".gitignore"}
REQUIRED = ROOT_FILES | {"guard_core/py.typed", "guard_core/sync/__init__.py"}


def sdist_members(path: Path) -> set[str]:
    with tarfile.open(path) as archive:
        return {
            member.name.split("/", 1)[1]
            for member in archive.getmembers()
            if member.isfile() and "/" in member.name
        }


def unexpected(members: set[str]) -> list[str]:
    return sorted(
        name
        for name in members
        if not (
            name.startswith("guard_core/")
            or name in ROOT_FILES
            or name in HATCHLING_ALWAYS_SHIPS
        )
    )


def main() -> int:
    path = Path(sys.argv[1])
    members = sdist_members(path)
    extra = unexpected(members)
    missing = sorted(REQUIRED - members)
    for name in extra:
        print(f"unexpected in the sdist: {name}")
    for name in missing:
        print(f"missing from the sdist: {name}")
    if extra or missing:
        return 1
    print(
        f"{path.name}: {len(members)} files, all guard_core/**, "
        f"{sorted(ROOT_FILES)} or hatchling's own .gitignore"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
