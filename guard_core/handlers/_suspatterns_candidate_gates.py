import re
from collections.abc import Callable
from functools import partial

from guard_core.handlers._suspatterns_ldap_ipv4 import (
    _LEGACY_IPV4_HOST_RE,
    _ldap_paren_conjunction_is_injection,
    _ldap_wildcard_chain_is_injection,
    _legacy_ipv4_match_is_blocked,
)
from guard_core.handlers._suspatterns_matchers import (
    _brace_expansion_is_dangerous_command,
)
from guard_core.handlers._suspatterns_named_floor import (
    NAMED_FLOOR_TOKEN_SOURCES,
    absolute_path_is_a_probe,
    named_floor_row_is_not_the_apps_own_route,
    named_probe_row_is_not_the_apps_own_route,
    recon_path_is_a_probe,
    source_path_is_a_probe,
)
from guard_core.handlers._suspatterns_path_code_execution import (
    absolute_path_value_is_probe,
    path_code_execution_is_injection,
    path_separator_command_is_injection,
)
from guard_core.handlers._suspatterns_path_row_clearing import (
    path_row_match_is_cleared,
)
from guard_core.handlers._suspatterns_pattern_table import (
    _ABSOLUTE_PATH_VALUE_RE,
    _CMD_PATH_CODE_EXECUTION_RE,
    _CMD_PATH_SEPARATOR_COMMAND_RE,
    BACKTICK_WHOLE_VALUE_RE,
)
from guard_core.handlers._suspatterns_pickle import (
    _pickle_global_candidate_is_injection,
)
from guard_core.handlers._suspatterns_probe_chains import (
    PROBE_CHAIN_ROW,
    chain_row_tail_is_query_or_space,
)
from guard_core.handlers._suspatterns_shell_sources import (
    _BRACE_EXPANSION_COMMAND_RE,
    _GLOB_WILDCARD_ATOM_RE,
    _GLUED_BACKTICK_CANDIDATE_RE,
    _GLUED_DOLLAR_SUBSTITUTION_CANDIDATE_RE,
    _QUOTE_SPLICE_CANDIDATE_RE,
)
from guard_core.handlers._suspatterns_shell_validators import (
    _dollar_substitution_pair_is_injection,
    _glob_wildcard_token_is_dangerous_command,
    _glued_backtick_pair_is_injection,
    _quote_splice_token_is_dangerous_command,
    _whole_value_backtick_pairs_are_injection,
)
from guard_core.handlers._suspatterns_sources import (
    _DESERIALIZATION_PICKLE_GLOBAL_GENERIC_RE,
    _LDAP_PAREN_BREAKOUT_RE,
    _LDAP_PAREN_CONJUNCTION_RE,
    _LDAP_WILDCARD_CHAIN_RE,
    _LDAP_WILDCARD_EQUALS_RE,
    _MAP_FILE_PATH_RE,
    _RECON_EXTENSION_PATH_RE,
    _SENSITIVE_SOURCE_EXTENSION_PATH_RE,
    _SYSTEM_LOG_PATH_RE,
    _VERSION_ROOT_PATH_RE,
    path_only_extension_tail_is_valid,
)

_CANDIDATE_REJECTION_VALIDATORS: tuple[
    tuple[str, Callable[[re.Match, str], bool]], ...
] = (
    *(
        (source, partial(named_floor_row_is_not_the_apps_own_route, source))
        for source in NAMED_FLOOR_TOKEN_SOURCES
    ),
    (_LEGACY_IPV4_HOST_RE, lambda m, _c: _legacy_ipv4_match_is_blocked(m)),
    (_LDAP_WILDCARD_CHAIN_RE, lambda m, _c: _ldap_wildcard_chain_is_injection(m)),
    (_LDAP_WILDCARD_EQUALS_RE, lambda m, _c: _ldap_wildcard_chain_is_injection(m)),
    (_LDAP_PAREN_BREAKOUT_RE, lambda m, _c: _ldap_wildcard_chain_is_injection(m)),
    (
        _LDAP_PAREN_CONJUNCTION_RE,
        lambda m, _c: _ldap_paren_conjunction_is_injection(m),
    ),
    (_GLUED_BACKTICK_CANDIDATE_RE, _glued_backtick_pair_is_injection),
    (BACKTICK_WHOLE_VALUE_RE, _whole_value_backtick_pairs_are_injection),
    (_CMD_PATH_CODE_EXECUTION_RE, path_code_execution_is_injection),
    (_CMD_PATH_SEPARATOR_COMMAND_RE, path_separator_command_is_injection),
    (
        _ABSOLUTE_PATH_VALUE_RE,
        lambda m, context: (
            absolute_path_value_is_probe(m, context)
            and absolute_path_is_a_probe(context)
        ),
    ),
    (
        _SENSITIVE_SOURCE_EXTENSION_PATH_RE,
        lambda m, context: (
            path_only_extension_tail_is_valid(m) and source_path_is_a_probe(m, context)
        ),
    ),
    (_MAP_FILE_PATH_RE, source_path_is_a_probe),
    (
        _RECON_EXTENSION_PATH_RE,
        lambda m, context: (
            path_only_extension_tail_is_valid(m) and recon_path_is_a_probe(m, context)
        ),
    ),
    (
        _VERSION_ROOT_PATH_RE,
        lambda _m, context: named_probe_row_is_not_the_apps_own_route(
            "version", context
        ),
    ),
    (
        _SYSTEM_LOG_PATH_RE,
        lambda _m, context: named_probe_row_is_not_the_apps_own_route(
            "system/log", context
        ),
    ),
    (PROBE_CHAIN_ROW, lambda m, _c: chain_row_tail_is_query_or_space(m)),
    (_GLUED_DOLLAR_SUBSTITUTION_CANDIDATE_RE, _dollar_substitution_pair_is_injection),
    (
        _BRACE_EXPANSION_COMMAND_RE,
        lambda m, _c: _brace_expansion_is_dangerous_command(m),
    ),
    (
        _QUOTE_SPLICE_CANDIDATE_RE,
        lambda m, _c: _quote_splice_token_is_dangerous_command(m),
    ),
    (
        _GLOB_WILDCARD_ATOM_RE,
        _glob_wildcard_token_is_dangerous_command,
    ),
    (_DESERIALIZATION_PICKLE_GLOBAL_GENERIC_RE, _pickle_global_candidate_is_injection),
)


_CONTEXT_SENSITIVE_ROW_SOURCES = frozenset(
    source for source, _validator in _CANDIDATE_REJECTION_VALIDATORS
)


def _candidate_passes_the_route_gates(
    pattern: re.Pattern, match: re.Match, context: str
) -> bool:
    for candidate, is_valid_threat in _CANDIDATE_REJECTION_VALIDATORS:
        if pattern.pattern == candidate and not is_valid_threat(match, context):
            return False
    return not path_row_match_is_cleared(pattern, match, context)
