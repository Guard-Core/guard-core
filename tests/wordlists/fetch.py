#!/usr/bin/env python3
"""Fetch every SecLists file named in SOURCES.json at the pinned commit.

Usage (from the repository root): python -m tests.wordlists.fetch <directory>

Each file is downloaded from raw.githubusercontent.com at the pinned commit and
refused unless its git blob SHA (the SHA-1 of ``blob <size>\\0<content>``) equals the
one pinned in SOURCES.json, so a 404 page or a moved file can never stand in for a
list. The vendored files are checked against the copies under tests/wordlists too.
"""

import hashlib
import json
import sys
from pathlib import Path

import httpx

HERE = Path(__file__).resolve().parent


def git_blob_sha(content: bytes) -> str:
    header = f"blob {len(content)}\0".encode()
    return hashlib.sha1(header + content, usedforsecurity=False).hexdigest()


def main() -> int:
    target = Path(sys.argv[1])
    target.mkdir(parents=True, exist_ok=True)
    sources = json.loads((HERE / "SOURCES.json").read_text())
    failures = []
    for local, meta in sorted(sources["files"].items()):
        url = (
            "https://raw.githubusercontent.com/danielmiessler/SecLists/"
            f"{sources['commit']}/{meta['path']}"
        )
        content = httpx.get(url, timeout=120).raise_for_status().content
        if git_blob_sha(content) != meta["git_blob_sha"]:
            failures.append(f"{local}: blob SHA mismatch for {url}")
            continue
        (target / local).write_bytes(content)
        print(f"ok {local} {len(content)} bytes {meta['git_blob_sha']}")
    for failure in failures:
        print(failure, file=sys.stderr)
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
