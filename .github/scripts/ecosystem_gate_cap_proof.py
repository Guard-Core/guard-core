from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import urllib.request
from collections.abc import Callable, Sequence
from pathlib import Path

from packaging.requirements import Requirement
from packaging.specifiers import SpecifierSet
from packaging.version import InvalidVersion, Version

ENGINE = "guard-core"
PYPI_VERSION_JSON = "https://pypi.org/pypi/{dist}/{version}/json"
PYPI_PROJECT_JSON = "https://pypi.org/pypi/{dist}/json"
MAX_HISTORY_LOOKUPS = 40
CAPPED_AND_PROVEN = 3

FetchJson = Callable[[str], dict[str, object]]
Compile = Callable[[Sequence[str], str, Sequence[str]], tuple[int, str]]


def fetch_json(url: str) -> dict[str, object]:
    with urllib.request.urlopen(url, timeout=30) as response:
        payload: dict[str, object] = json.load(response)
    return payload


def engine_specifier(requires_dist: Sequence[str]) -> SpecifierSet | None:
    specs = [
        requirement.specifier
        for requirement in map(Requirement, requires_dist)
        if requirement.name == ENGINE
        and (requirement.marker is None or requirement.marker.evaluate({"extra": ""}))
    ]
    if not specs:
        return None
    combined = SpecifierSet()
    for spec in specs:
        combined &= spec
    return combined


def published_requires(dist: str, version: str, fetch: FetchJson) -> list[str]:
    info = fetch(PYPI_VERSION_JSON.format(dist=dist, version=version))["info"]
    assert isinstance(info, dict)
    return list(info.get("requires_dist") or [])


def admits(spec: SpecifierSet | None, version: str) -> bool:
    return spec is None or spec.contains(version, prereleases=True)


def find_uncapped_release(dist: str, pr_version: str, fetch: FetchJson) -> str | None:
    releases = fetch(PYPI_PROJECT_JSON.format(dist=dist))["releases"]
    assert isinstance(releases, dict)
    candidates: list[Version] = []
    for name, files in releases.items():
        try:
            version = Version(name)
        except InvalidVersion:
            continue
        if files and not version.is_prerelease and not all(f["yanked"] for f in files):
            candidates.append(version)
    for version in sorted(candidates, reverse=True)[:MAX_HISTORY_LOOKUPS]:
        requires = published_requires(dist, str(version), fetch)
        spec = engine_specifier(requires)
        if spec is not None and admits(spec, pr_version):
            return str(version)
    return None


def uv_compile(
    requirements: Sequence[str], python_version: str, find_links: Sequence[str]
) -> tuple[int, str]:
    with tempfile.TemporaryDirectory() as scratch:
        source = Path(scratch) / "requirements.in"
        source.write_text("\n".join(requirements) + "\n", encoding="utf-8")
        command = [
            "uv",
            "pip",
            "compile",
            str(source),
            "--python-version",
            python_version,
        ]
        for location in find_links:
            command += ["--find-links", location]
        done = subprocess.run(command, capture_output=True, text=True, check=False)
    return done.returncode, done.stdout + done.stderr


def prove_cap(
    dist: str,
    tag_version: str,
    pr_version: str,
    find_links: Sequence[str],
    python_version: str,
    tag_requires: Sequence[str],
    fetch: FetchJson = fetch_json,
    resolve: Compile = uv_compile,
) -> tuple[str, list[str]]:
    """Return ("admitted" | "capped", errors). Errors fail the gate job."""
    published = engine_specifier(published_requires(dist, tag_version, fetch))
    if admits(published, pr_version):
        return "admitted", []
    errors: list[str] = []
    tagged = engine_specifier(tag_requires)
    if (
        tagged is None
        or published is None
        or set(map(str, tagged)) != set(map(str, published))
    ):
        errors.append(
            f"{dist}=={tag_version}: the tag's pyproject range ({tagged}) "
            f"disagrees with PyPI's ({published})"
        )
    code, output = resolve(
        [f"{dist}=={tag_version}", f"{ENGINE}=={pr_version}"],
        python_version,
        find_links,
    )
    if code == 0 or "no solution found" not in output.lower():
        errors.append(
            f"{dist}=={tag_version} caps {ENGINE} below {pr_version} but "
            f"`uv pip compile` did not report it unsatisfiable (exit {code}): "
            f"{output.strip()[-400:]}"
        )
    control = find_uncapped_release(dist, pr_version, fetch)
    if control is None:
        errors.append(f"no uncapped {dist} release in PyPI history for the control")
    else:
        code, output = resolve(
            [f"{dist}=={control}", f"{ENGINE}=={pr_version}"],
            python_version,
            find_links,
        )
        if code != 0:
            errors.append(
                f"negative control {dist}=={control} + {ENGINE}=={pr_version} "
                f"did not resolve (exit {code}): {output.strip()[-400:]}"
            )
    return "capped", errors


def main(argv: list[str]) -> int:
    if len(argv) != 7:
        print(
            "usage: ecosystem_gate_cap_proof.py <dist> <tag-version> <pr-version> "
            "<wheel-dir> <python-version> <tag-requires-file>"
        )
        return 2
    dist, tag_version, pr_version, wheel_dir, python_version, requires_file = argv[1:]
    tag_requires = Path(requires_file).read_text(encoding="utf-8").splitlines()
    outcome, errors = prove_cap(
        dist, tag_version, pr_version, [wheel_dir], python_version, tag_requires
    )
    for error in errors:
        print(f"::error::{error}")
    if outcome == "capped" and not errors:
        print(f"::notice::{dist}=={tag_version} cap on {ENGINE} proven unsatisfiable")
    print(f"cap-proof: {outcome}")
    if errors:
        return 1
    return CAPPED_AND_PROVEN if outcome == "capped" else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
