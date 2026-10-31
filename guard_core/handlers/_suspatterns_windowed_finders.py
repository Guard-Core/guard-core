import re
from collections.abc import Callable, Iterator

from guard_core._lazy_patterns import module_attribute_lookup
from guard_core.handlers._suspatterns_matchers import _PATTERNS as _MATCHERS_PATTERNS
from guard_core.handlers._suspatterns_matchers import (
    _cmd_injection_shell_dash_c_finditer,
    _ldap_null_byte_attr_finditer,
    _pickle_global_generic_finditer,
    _quote_splice_finditer,
)
from guard_core.handlers._suspatterns_scan_windows import _SCAN_WINDOW_PATTERNS
from guard_core.handlers._suspatterns_shell_sources import (
    _PATTERN_SCAN_WINDOW_MATCHERS,
    _QUOTE_SPLICE_CANDIDATE_RE,
)
from guard_core.handlers._suspatterns_shell_sources import (
    _PATTERNS as _SHELL_SOURCES_PATTERNS,
)
from guard_core.handlers._suspatterns_sources import (
    _CMD_INJECTION_NEWLINE_SHELL_DASH_C_RE,
    _DESERIALIZATION_PICKLE_GLOBAL_GENERIC_RE,
    _LDAP_NULL_BYTE_ATTR_RE,
    _LDAP_NULL_BYTE_DECODED_ATTR_RE,
    _XML_XXE_PUBLIC_EXTERNAL_DTD_RE,
)
from guard_core.handlers._suspatterns_sources import _PATTERNS as _SOURCES_PATTERNS
from guard_core.handlers._suspatterns_xml_xxe import _PATTERNS as _XML_XXE_PATTERNS
from guard_core.handlers._suspatterns_xml_xxe import (
    _xml_xxe_public_external_dtd_finditer,
)

_WINDOWED_PATTERN_FINDERS: dict[str, Callable[[str], Iterator[re.Match]]] = {
    _CMD_INJECTION_NEWLINE_SHELL_DASH_C_RE: lambda text: (
        _cmd_injection_shell_dash_c_finditer(
            text, _MATCHERS_PATTERNS["_CMD_INJECTION_NEWLINE_SHELL_DASH_C_COMPILED_RE"]
        )
    ),
    _LDAP_NULL_BYTE_ATTR_RE: lambda text: _ldap_null_byte_attr_finditer(
        text,
        _SOURCES_PATTERNS["_LDAP_NULL_BYTE_ATTR_COMPILED_RE"],
        _SOURCES_PATTERNS["_LDAP_NULL_BYTE_TAIL_RE"],
    ),
    _LDAP_NULL_BYTE_DECODED_ATTR_RE: lambda text: _ldap_null_byte_attr_finditer(
        text,
        _SOURCES_PATTERNS["_LDAP_NULL_BYTE_DECODED_ATTR_COMPILED_RE"],
        _SOURCES_PATTERNS["_LDAP_NULL_BYTE_DECODED_TAIL_RE"],
    ),
    _QUOTE_SPLICE_CANDIDATE_RE: lambda text: _quote_splice_finditer(
        text, _SHELL_SOURCES_PATTERNS["_QUOTE_SPLICE_CANDIDATE_COMPILED_RE"]
    ),
    _DESERIALIZATION_PICKLE_GLOBAL_GENERIC_RE: lambda text: (
        _pickle_global_generic_finditer(
            text,
            _MATCHERS_PATTERNS["_DESERIALIZATION_PICKLE_GLOBAL_GENERIC_COMPILED_RE"],
        )
    ),
    _XML_XXE_PUBLIC_EXTERNAL_DTD_RE: lambda text: _xml_xxe_public_external_dtd_finditer(
        text, _XML_XXE_PATTERNS["_XML_XXE_PUBLIC_EXTERNAL_DTD_COMPILED_RE"]
    ),
}


_LITERAL_EXCLUDED_SOURCES = (
    frozenset(_WINDOWED_PATTERN_FINDERS)
    | frozenset(_PATTERN_SCAN_WINDOW_MATCHERS)
    | frozenset(_SCAN_WINDOW_PATTERNS)
)


__getattr__ = module_attribute_lookup(
    _MATCHERS_PATTERNS, _SHELL_SOURCES_PATTERNS, _SOURCES_PATTERNS, _XML_XXE_PATTERNS
)
