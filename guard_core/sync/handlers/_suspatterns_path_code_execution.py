import re

from guard_core._lazy_patterns import LazyPatterns, module_attribute_lookup
from guard_core.sync.handlers._suspatterns_linear_path_source import flattened
from guard_core.sync.handlers._suspatterns_pattern_table import BACKTICK_WHOLE_VALUE_RE
from guard_core.sync.handlers._suspatterns_shell_sources import (
    _GLUED_BACKTICK_CANDIDATE_RE,
)
from guard_core.sync.handlers._suspatterns_shell_validators import (
    _glued_backtick_pair_is_injection,
    _shell_token_is_command_with_arguments_or_known,
    _whole_value_backtick_pairs_are_injection,
    shell_dash_c_argument_is_dangerous,
)
from guard_core.sync.handlers._suspatterns_sources import (
    _source_extension_path_is_probe,
)

_PATTERNS = LazyPatterns(
    {
        "_GLUED_BACKTICK_CANDIDATE_COMPILED_RE": (
            flattened(_GLUED_BACKTICK_CANDIDATE_RE),
            0,
        ),
        "_BACKTICK_WHOLE_VALUE_COMPILED_RE": (flattened(BACKTICK_WHOLE_VALUE_RE), 0),
        "_DASH_C_COMPILED_RE": (r"(?:ba|z|da|k)?sh\s+-c\b", 0),
        "_SEPARATED_DASH_C_COMPILED_RE": (r"\s+-c\b", 0),
        "_DOCROOT_WEB_ASSET_RE": (
            r"\A\s*/var/www/html/(?:[^/\s.][^/\s]*/)*[^/\s.][^/\s]*"
            r"\.(?:html?|css|js|png|jpe?g|gif|svg|ico)\s*\Z",
            re.IGNORECASE,
        ),
        "_WINDOWS_USER_DOCUMENT_RE": (
            r"\A\s*[a-z]:[/\\]users[/\\][^/\\\s.][^/\\\s]*[/\\]"
            r"(?:documents|desktop|downloads|pictures|music|videos)[/\\]"
            r"(?:[^/\\\s.][^/\\\s]*[/\\])*[^/\\\s.][^/\\\s]*\s*\Z",
            re.IGNORECASE,
        ),
    }
)
_lookup = module_attribute_lookup(_PATTERNS)


def __getattr__(name: str) -> re.Pattern[str]:
    return _lookup(name)


def _backtick_pair_is_a_whole_path_segment(match: re.Match) -> bool:
    content = match.string
    return (match.start() == 0 or content[match.start() - 1] == "/") and (
        match.end() == len(content) or content[match.end()] == "/"
    )


def _path_backtick_pair_is_injection(match: re.Match, context: str) -> bool:
    content = match.string
    whole = _PATTERNS["_BACKTICK_WHOLE_VALUE_COMPILED_RE"].match(content)
    if whole and _whole_value_backtick_pairs_are_injection(whole, context):
        return True
    if _backtick_pair_is_a_whole_path_segment(
        match
    ) and _shell_token_is_command_with_arguments_or_known(match.group()[1:-1]):
        return True
    glued = _PATTERNS["_GLUED_BACKTICK_CANDIDATE_COMPILED_RE"].match(
        content, match.start()
    )
    return glued is not None and _glued_backtick_pair_is_injection(glued, context)


def path_code_execution_is_injection(match: re.Match, context: str) -> bool:
    if not context.startswith("url_path"):
        return False
    if match.group().startswith("`"):
        return _path_backtick_pair_is_injection(match, context)
    if _PATTERNS["_DASH_C_COMPILED_RE"].fullmatch(match.group()):
        return shell_dash_c_argument_is_dangerous(match.string, match.end())
    return True


def path_separator_command_is_injection(match: re.Match, _context: str) -> bool:
    dash_c = _PATTERNS["_SEPARATED_DASH_C_COMPILED_RE"].match(match.string, match.end())
    return not dash_c or shell_dash_c_argument_is_dangerous(match.string, dash_c.end())


def absolute_path_value_is_probe(match: re.Match, context: str) -> bool:
    return _source_extension_path_is_probe(context) and not (
        _PATTERNS["_DOCROOT_WEB_ASSET_RE"].match(match.string)
        or _PATTERNS["_WINDOWS_USER_DOCUMENT_RE"].match(match.string)
    )
