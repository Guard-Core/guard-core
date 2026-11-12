import re
from pathlib import Path

STACK = Path(__file__).resolve().parent / "stack"
WORKFLOW = Path(__file__).resolve().parents[2] / ".github" / "workflows"
PINNED = re.compile(r"^\S+:\d\S*@sha256:[0-9a-f]{64}$")


def _image_references() -> list[tuple[str, str]]:
    references = []
    for line in (STACK / "Dockerfile").read_text(encoding="utf-8").splitlines():
        parts = line.split()
        if parts and parts[0].upper() == "FROM":
            references.append(("Dockerfile", parts[1]))
        if parts and parts[0].upper() == "COPY":
            references += [
                ("Dockerfile", p[7:]) for p in parts if p.startswith("--from=")
            ]
    for line in (STACK / "compose.yml").read_text(encoding="utf-8").splitlines():
        if line.strip().startswith("image:"):
            references.append(("compose.yml", line.split("image:")[1].strip()))
    for line in (WORKFLOW / "live-smoke.yml").read_text(encoding="utf-8").splitlines():
        if line.strip().startswith("image:"):
            references.append(("live-smoke.yml", line.split("image:")[1].strip()))
    return references


def test_every_live_smoke_image_is_a_version_tag_plus_a_digest() -> None:
    references = _image_references()
    assert len(references) >= 6
    unpinned = [r for r in references if r[1] != "uv" and not PINNED.match(r[1])]
    assert not unpinned


def test_the_uv_image_is_a_named_stage_so_dependabot_tracks_it() -> None:
    dockerfile = (STACK / "Dockerfile").read_text(encoding="utf-8")
    assert re.search(
        r"^FROM ghcr\.io/astral-sh/uv:\S+@sha256:\S+ AS uv$", dockerfile, re.M
    )
    assert "COPY --from=uv /uv /usr/local/bin/uv" in dockerfile
