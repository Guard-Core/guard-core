import re
from collections.abc import Iterator

from guard_core.detection_engine.scan_window import bounded_finditer
from guard_core.handlers._suspatterns_xml_xxe import (
    _xml_internal_entity_finditer,
    _xml_system_finditer,
)

_SCAN_WINDOW_BOUND_SOURCES: dict[str, tuple[tuple[str, str], ...]] = {
    r"<script[^>]*>[^<]*<\/script\s*>": ((r"<script", r"<\/script\s*>"),),
    (
        r"(?:<[A-Za-z/][^<>]*style\s*=\s{0,20}[\"']?[^<>\"']*"
        r"(?:expression|behavior|url)\s*\([^)]*\))"
    ): ((r"<[A-Za-z/][^<>]*style\s*=", r"\)"),),
    r"(?:<object[^>]*>[\s\S]*<\/object\s*>)": ((r"<object", r"<\/object\s*>"),),
    r"(?:<embed[^>]*>[\s\S]*<\/embed\s*>)": ((r"<embed", r"<\/embed\s*>"),),
    r"(?:<applet[^>]*>[\s\S]*<\/applet\s*>)": ((r"<applet", r"<\/applet\s*>"),),
    r"\.\.;[^/\\]*[/\\]": ((r"\.\.;", r"[/\\]"),),
    (
        r"=(?:https?|ftp):\/\/[^\s'\"<>]+\/[^\s'\"<>\/]*"
        r"\.(?:phtml|php[3-5]?|phar|jsp|aspx?|pl|py|txt|inc)(?![a-zA-Z0-9])"
    ): (
        (
            r"=(?:https?|ftp):\/\/",
            r"\.(?:phtml|php\d*|phar|jsp|aspx?|pl|py|txt|inc)[a-zA-Z0-9]*",
        ),
    ),
    r"<!(?:ENTITY|DOCTYPE)[^>]+SYSTEM[^>]+>": ((r"<!(?:ENTITY|DOCTYPE)", r">"),),
    r"(?:<!\[CDATA\[.*?\]\]>)": ((r"<!\[CDATA\[", r"\]\]>"),),
    r"<!DOCTYPE[^>\[]*\[[\s\S]*?<!ENTITY": ((r"<!DOCTYPE", r"<!ENTITY"),),
}

_SCAN_WINDOW_PATTERNS: dict[str, tuple[tuple[re.Pattern, re.Pattern], ...]] = {
    source: tuple(
        (re.compile(prefix, re.IGNORECASE), re.compile(terminator, re.IGNORECASE))
        for prefix, terminator in pairs
    )
    for source, pairs in _SCAN_WINDOW_BOUND_SOURCES.items()
}


def _iter_scan_window_matches(
    content: str,
    pattern: re.Pattern,
    bounds: tuple[tuple[re.Pattern, re.Pattern], ...],
) -> Iterator[re.Match]:
    if pattern.pattern == r"<!(?:ENTITY|DOCTYPE)[^>]+SYSTEM[^>]+>":
        yield from _xml_system_finditer(content)
        return
    if pattern.pattern == r"<!DOCTYPE[^>\[]*\[[\s\S]*?<!ENTITY":
        yield from _xml_internal_entity_finditer(content)
        return
    for prefix, terminator in bounds:
        yield from bounded_finditer(content, pattern, prefix, terminator)
