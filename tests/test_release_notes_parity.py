import re
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
_CHANGELOG = _REPO_ROOT / "CHANGELOG.md"
_RELEASE_NOTES = _REPO_ROOT / "docs" / "release-notes.md"
_ENTRY_LEAD = re.compile(r"^- (\*\*.+?\*\*)", re.MULTILINE)


def unreleased_entry_leads(text: str, heading: str) -> set[str]:
    section = text.split(f"\n{heading}\n", 1)[1].split("\n___\n", 1)[0]
    return set(_ENTRY_LEAD.findall(section))


def _both_sets() -> tuple[set[str], set[str]]:
    return (
        unreleased_entry_leads(_CHANGELOG.read_text(encoding="utf-8"), "[Unreleased]"),
        unreleased_entry_leads(
            _RELEASE_NOTES.read_text(encoding="utf-8"), "Unreleased"
        ),
    )


def test_unreleased_sections_hold_the_same_entries() -> None:
    changelog, release_notes = _both_sets()
    assert changelog, "CHANGELOG.md Unreleased section has no entries"
    assert changelog - release_notes == set(), "only in CHANGELOG.md"
    assert release_notes - changelog == set(), "only in docs/release-notes.md"


def test_parity_check_fails_when_one_entry_is_removed_from_one_file() -> None:
    text = _CHANGELOG.read_text(encoding="utf-8")
    first = _ENTRY_LEAD.search(text.split("\n[Unreleased]\n", 1)[1])
    assert first is not None
    removed_line = next(
        line for line in text.splitlines() if line.startswith(f"- {first.group(1)}")
    )
    trimmed = text.replace(removed_line + "\n", "", 1)
    _, release_notes = _both_sets()
    assert unreleased_entry_leads(trimmed, "[Unreleased]") != release_notes
