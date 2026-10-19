#!/usr/bin/env python3
"""Classify the script names of the public backdoor lists and (re)generate the rows.

Usage:
  python -m tests.wordlists.classify write <heavy lists directory>
      write classification.json and the module
  python -m tests.wordlists.classify check <heavy lists directory>
      fail unless both reproduce byte for byte

Run from the repository root.

The heavy lists (raft-large-files, the trickest drupal, joomla and tomcat lists, the
SVNDigger language lists) stay out of the repository: tests/wordlists/fetch.py
downloads them at the pinned SecLists commit and refuses any file whose git blob
SHA differs from SOURCES.json. A missing or altered file stops this script with a
message; it never falls back and never passes silently. CI does not run it (it has
no heavy lists); CI runs tests/test_detection/test_probe_name_rows.py, which
checks the committed table against the committed rows.

Name universe, in this order: (a) a backdoor_list.txt entry is taken only if its
extension is one the source-extension row or the recon extension row treats as a
script; the four CommonBackdoors lists are added with the same filter; (b) exact
basenames only, whitespace collapsed the way the engine sees it. A name matches at any
depth unless it is in the platform benign sets (PHP: wordpress.fuzz, trickest drupal and
joomla; ASP, ASPX, JSP and PL: SVNDigger language lists and trickest tomcat), in
raft-large-files, in Common-PHP-Filenames, or has a purely numeric stem; those match
only under an upload-like directory. A name a decision fixed at any depth keeps it.
"""

import json
import re
import sys
import unicodedata
from pathlib import Path

from tests.wordlists.fetch import git_blob_sha
from tests.wordlists.probe_regex import any_depth_regex, upload_only_regex

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
SCRIPT_EXTENSIONS = frozenset(
    "ts tsx jsx py rb java go rs php pl sh sql asp aspx jsp jsa jhtml shtml cfm cgi "
    "do action lua inc woa nsf esp".split()
)
PHP_FAMILY = frozenset({"php", "php3", "php4", "php5", "phtml", "phps", "pht", "inc"})
ASP_FAMILY = frozenset({"asp", "aspx", "ashx", "asmx", "ascx", "asa", "asax", "cer"})
JSP_FAMILY = frozenset({"jsp", "jspx"})
PERL_FAMILY = frozenset({"pl", "cgi"})
FIXED_ANY_DEPTH = frozenset({"c99.php", "r57.php"})
VENDORED = (
    "backdoor_list.txt",
    "CommonBackdoors-PHP.fuzz.txt",
    "CommonBackdoors-ASP.fuzz.txt",
    "CommonBackdoors-JSP.fuzz.txt",
    "CommonBackdoors-PL.fuzz.txt",
    "wordpress.fuzz.txt",
    "Common-PHP-Filenames.txt",
)
HEAVY = (
    "raft-large-files.txt",
    "trickest-drupal-all-levels.txt",
    "trickest-joomla-all-levels.txt",
    "trickest-tomcat-all-levels.txt",
    "svndigger-asp.txt",
    "svndigger-aspx.txt",
    "svndigger-jsp.txt",
    "svndigger-pl.txt",
)
TABLE_PATH = HERE / "classification.json"
MODULE_PATH = REPO / "guard_core" / "handlers" / "_suspatterns_probe_names.py"


def fail(message: str) -> None:
    raise SystemExit(f"classify.py: {message}")


def read_list(sources: dict, local: str, directory: Path) -> list[str]:
    path = directory / local
    if not path.is_file():
        fail(f"{path} is missing; run python -m tests.wordlists.fetch {directory}")
    content = path.read_bytes()
    if git_blob_sha(content) != sources["files"][local]["git_blob_sha"]:
        fail(f"{path} does not match the blob SHA pinned in SOURCES.json")
    return content.decode("utf-8").splitlines()


def engine_name(name: str) -> str:
    from guard_core.detection_engine.preprocessor import ContentPreprocessor

    folded = ContentPreprocessor().normalize_unicode(name)
    return re.sub(r"\s+", " ", folded).strip()


def extension(name: str) -> str:
    return name.rsplit(".", 1)[1].lower() if "." in name else ""


def basenames(lines: list[str]) -> set[str]:
    return {engine_name(line.strip().split("/")[-1]).lower() for line in lines}


def platform_sets(lists: dict[str, list[str]]) -> dict[str, set[str]]:
    php = (
        basenames(lists["wordpress.fuzz.txt"])
        | basenames(lists["trickest-drupal-all-levels.txt"])
        | basenames(lists["trickest-joomla-all-levels.txt"])
    )
    java_and_dotnet = basenames(lists["trickest-tomcat-all-levels.txt"])
    for key in ("svndigger-asp.txt", "svndigger-aspx.txt", "svndigger-jsp.txt"):
        java_and_dotnet |= basenames(lists[key])
    perl = basenames(lists["svndigger-pl.txt"])
    return {"php": php, "asp_jsp": java_and_dotnet, "perl": perl}


def restricting_lists(name: str, benign: dict[str, set[str]]) -> list[str]:
    key = name.lower()
    ext = extension(name)
    reasons = []
    if ext in PHP_FAMILY and key in benign["php"]:
        reasons.append("platform:php")
    if (ext in ASP_FAMILY or ext in JSP_FAMILY) and key in benign["asp_jsp"]:
        reasons.append("platform:asp_jsp")
    if ext in PERL_FAMILY and key in benign["perl"]:
        reasons.append("platform:perl")
    if key in benign["raft"]:
        reasons.append("raft-large-files.txt")
    if key in benign["cpf"]:
        reasons.append("Common-PHP-Filenames.txt")
    if re.fullmatch(r"\d+", key.rsplit(".", 1)[0]):
        reasons.append("numeric stem")
    return reasons


def universe(lists: dict[str, list[str]]) -> dict[str, dict]:
    found: dict[str, dict] = {}
    for local in VENDORED[:5]:
        for line in lists[local]:
            if not line.strip() or extension(line.strip()) not in SCRIPT_EXTENSIONS:
                continue
            name = engine_name(line)
            entry = found.setdefault(name.lower(), {"name": name, "lists": []})
            if local not in entry["lists"]:
                entry["lists"].append(local)
    return found


def classify(lists: dict[str, list[str]]) -> list[dict]:
    benign = platform_sets(lists)
    benign["raft"] = basenames(lists["raft-large-files.txt"])
    benign["cpf"] = basenames(lists["Common-PHP-Filenames.txt"])
    rows = []
    for key, entry in sorted(universe(lists).items()):
        reasons = restricting_lists(entry["name"], benign)
        mode = "upload_only" if reasons and key not in FIXED_ANY_DEPTH else "any_depth"
        rows.append(
            {
                "name": entry["name"],
                "mode": mode,
                "restricted_by": reasons,
                "lists": sorted(entry["lists"]),
            }
        )
    return rows


def render_table(sources: dict, rows: list[dict]) -> str:
    table = {
        "generator": "tests/wordlists/classify.py",
        "seclists_commit": sources["commit"],
        "blob_shas": {
            local: sources["files"][local]["git_blob_sha"]
            for local in (*VENDORED, *HEAVY)
        },
        "fixed_any_depth": sorted(FIXED_ANY_DEPTH),
        "names": rows,
    }
    return json.dumps(table, indent=1, ensure_ascii=False, sort_keys=True) + "\n"


def display_width(text: str) -> int:
    return sum(2 if unicodedata.east_asian_width(char) in "WF" else 1 for char in text)


def quoted(text: str) -> str:
    return json.dumps(text, ensure_ascii=False)


def literal_lines(value: str, width: int = 78) -> str:
    pieces: list[str] = []
    current = ""
    for char in value:
        if display_width(quoted(current + char)) > width:
            pieces.append(quoted(current))
            current = ""
        current += char
    pieces.append(quoted(current))
    return "(\n" + "".join(f"    {piece}\n" for piece in pieces) + ")"


def render_module(rows: list[dict]) -> str:
    any_depth = [row["name"] for row in rows if row["mode"] == "any_depth"]
    upload_only = [row["name"] for row in rows if row["mode"] == "upload_only"]
    return (
        "# Generated by tests/wordlists/classify.py from the public backdoor lists of\n"
        "# SecLists at commit 60e43f4d2b0251330ff18ea4fa76aabec0515dcb (MIT). Do not\n"
        "# edit by hand: tests/test_detection/test_probe_name_rows.py rebuilds these\n"
        "# strings from tests/wordlists/classification.json and fails on any drift.\n\n"
        f"SCRIPT_NAMES_ANY_DEPTH_RE = {literal_lines(any_depth_regex(any_depth))}\n\n"
        "SCRIPT_NAMES_UPLOAD_ONLY_RE = "
        f"{literal_lines(upload_only_regex(upload_only))}\n"
    )


def load_lists(sources: dict, heavy_directory: Path) -> dict[str, list[str]]:
    lists = {local: read_list(sources, local, HERE) for local in VENDORED}
    lists.update({local: read_list(sources, local, heavy_directory) for local in HEAVY})
    return lists


def main() -> int:
    if len(sys.argv) != 3 or sys.argv[1] not in {"write", "check"}:
        fail("usage: classify.py write|check <heavy lists directory>")
    sources = json.loads((HERE / "SOURCES.json").read_text())
    lists = load_lists(sources, Path(sys.argv[2]))
    rows = classify(lists)
    table = render_table(sources, rows)
    if sys.argv[1] == "write":
        TABLE_PATH.write_text(table, encoding="utf-8")
        module = render_module(rows)
        MODULE_PATH.write_text(module, encoding="utf-8")
        print(f"wrote {TABLE_PATH.name} ({len(rows)} names) and {MODULE_PATH.name}")
        return 0
    if TABLE_PATH.read_text(encoding="utf-8") != table:
        fail("classification.json differs from the regenerated table")
    if MODULE_PATH.read_text(encoding="utf-8") != render_module(rows):
        fail("the generated module differs from the regenerated one")
    print(f"classification.json and {MODULE_PATH.name} reproduce byte for byte")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
