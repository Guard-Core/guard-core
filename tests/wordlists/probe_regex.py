"""Regexes of the named script rows, built from the committed classification table.

The same functions generate guard_core/handlers/_suspatterns_probe_names.py (through
classify.py) and check it (tests/test_detection/test_probe_name_rows.py), so the table
and the rows cannot drift.
"""

import re

PATH_CHAR = r"[\w.\-~%]"
PATH_SEP = r"[/\\]"
PATH_SUFFIX = rf"(?:{PATH_SEP}{PATH_CHAR}*)*(?:\?\S*)?\s*\Z"
UPLOAD_DIRECTORIES = r"(?:uploads?|files|images|media|tmp)"


def _trie(names: list[str]) -> dict:
    root: dict = {}
    for name in names:
        node = root
        for char in name:
            node = node.setdefault(char, {})
        node[""] = {}
    return root


def _render(node: dict) -> str:
    branches = []
    ends_here = "" in node
    for char in sorted(key for key in node if key != ""):
        branches.append(re.escape(char) + _render(node[char]))
    if not branches:
        return ""
    body = branches[0] if len(branches) == 1 else "(?:" + "|".join(branches) + ")"
    return f"(?:{body})?" if ends_here else body


def factored_alternation(names: list[str]) -> str:
    return "(?:" + _render(_trie(sorted({name.lower() for name in names}))) + ")"


def _extension_gate(names: list[str]) -> str:
    extensions = sorted({name.rsplit(".", 1)[1].lower() for name in names})
    return rf"(?=[^?]*\.(?:{'|'.join(extensions)}))"


def any_depth_regex(names: list[str]) -> str:
    return (
        rf"\A{PATH_SEP}?{_extension_gate(names)}(?:{PATH_CHAR}+{PATH_SEP})*"
        rf"{factored_alternation(names)}{PATH_SUFFIX}"
    )


def upload_only_regex(names: list[str]) -> str:
    return (
        rf"\A{PATH_SEP}{_extension_gate(names)}(?:{PATH_CHAR}+{PATH_SEP})*"
        rf"{UPLOAD_DIRECTORIES}{PATH_SEP}(?:{PATH_CHAR}+{PATH_SEP})*"
        rf"{factored_alternation(names)}{PATH_SUFFIX}"
    )
