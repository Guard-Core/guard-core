import itertools
import re

import pytest

from guard_core.sync.handlers._suspatterns_sources import (
    _PATH_ONLY_CHAR_RE,
    _PATH_ONLY_SEP_RE,
    _PATH_ONLY_SUFFIX_RE,
    _RECON_EXTENSION_PATH_RE,
    _SENSITIVE_SOURCE_EXTENSION_PATH_RE,
)

_FLAGS = re.IGNORECASE | re.MULTILINE
_CASES = ("", ".", "..", "a", "a.b", "foo.ts", "foo.asp", "foo.js")
_SEPARATORS = ("/", "\\")
_TAILS = ("", "/", "//", "?x=1", "?x y", " ", "\t")
_PATTERNS = (
    (
        "sensitive_file",
        rf"{_PATH_ONLY_CHAR_RE}*\.(?:ts|tsx|jsx|py|rb|java|go|rs|php|pl|sh|sql)",
        _SENSITIVE_SOURCE_EXTENSION_PATH_RE,
    ),
    (
        "recon",
        rf"{_PATH_ONLY_CHAR_RE}*\.(?:asp|aspx|jsp|jsa|jhtml|shtml|cfm|cgi|do|action|lua|inc|woa|nsf|esp)",
        _RECON_EXTENSION_PATH_RE,
    ),
)


def _generated_paths() -> list[str]:
    paths = {
        "/.ts",
        "/foo.ts/bar",
        "/foo.asp/bar",
        "/a.b/c.d.ts",
        "/a.b\\c.d.aspx",
        "foo.ts?x=1",
        "foo.asp xyz",
        "foo.js!",
    }
    for size in range(1, 4):
        for segments in itertools.product(_CASES, repeat=size):
            for separator in _SEPARATORS:
                path = separator.join(segments)
                for leading in ("", "/", "\\"):
                    for tail in _TAILS:
                        paths.add(leading + path + tail)
    return sorted(paths)


@pytest.mark.parametrize("_category,required,current", _PATTERNS)
def test_extension_path_regex_matches_previous_language(
    _category: str, required: str, current: str
) -> None:
    previous = re.compile(
        rf"\A{_PATH_ONLY_SEP_RE}?"
        rf"(?:(?!{required}(?:{_PATH_ONLY_SEP_RE}|\Z))"
        rf"{_PATH_ONLY_CHAR_RE}+{_PATH_ONLY_SEP_RE})*"
        rf"{required}{_PATH_ONLY_SUFFIX_RE}",
        _FLAGS,
    )
    optimized = re.compile(current, _FLAGS)

    for path in _generated_paths():
        previous_match = previous.search(path)
        optimized_match = optimized.search(path)
        assert (previous_match is not None) == (optimized_match is not None), (
            f"language changed for {path!r}: {previous.pattern!r} vs "
            f"{optimized.pattern!r}"
        )
