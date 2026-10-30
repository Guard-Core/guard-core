import ipaddress
import re

from guard_core.handlers._suspatterns_sources import (
    _LDAP_BREAKOUT_ATTACK_TOKEN_RE,
    _LDAP_BREAKOUT_BACKWARD_BOUNDARY_CHARS,
    _LDAP_BREAKOUT_FORWARD_BOUNDARY_CHARS,
    _LDAP_BREAKOUT_LOCAL_SCAN_CHARS,
    _LDAP_BREAKOUT_WILDCARD_CLAUSE_END_RE,
    _LDAP_FILTER_EXPRESSION_STRUCTURE_RE,
    _LDAP_PAREN_CONJUNCTION_FOLLOWUP_ATTR_RE,
    _LDAP_PAREN_CONJUNCTION_FOLLOWUP_SYMBOL_RE,
)

_LOG4SHELL_JNDI_LOOKUP_RE = (
    r"(?i)\$\{(?:jndi:(?:ldap|rmi|dns)://"
    r"|\$?\{?(?:lower|upper):j\}ndi"
    r"|::-j\}ndi)"
)

_LOG4J_LOOKUP_FORMS_RE = (
    r"(?i)\$\{(?:(?:jndi|env|sys|ctx|java|bundle|main|date|base64|lower|upper"
    r"|marker|sd|map|k8s|docker|spring|web|log4j):"
    r"|[a-z0-9_.-]{0,16}\$\{[a-z0-9]{0,12}:)"
)

ALWAYS_SCAN_HEADER_PATTERNS: frozenset[re.Pattern] = frozenset(
    {re.compile(_LOG4SHELL_JNDI_LOOKUP_RE), re.compile(_LOG4J_LOOKUP_FORMS_RE)}
)


_LEGACY_IPV4_PART_RE = r"(?:0[xX][0-9a-fA-F]+|0[0-7]+|[1-9]\d*|0)"
_LEGACY_IPV4_HOST_RE = (
    r"://(?:[^/@\s]*@)?("
    + _LEGACY_IPV4_PART_RE
    + r"(?:\."
    + _LEGACY_IPV4_PART_RE
    + r"){0,3})(?=[:/\s]|$)"
)

_LEGACY_IPV4_BLOCKED_NETWORKS: tuple[ipaddress.IPv4Network, ...] = tuple(
    ipaddress.IPv4Network(cidr)
    for cidr in (
        "0.0.0.0/8",
        "127.0.0.0/8",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "169.254.0.0/16",
        "100.100.100.200/32",
    )
)


def _decode_legacy_ipv4_part(part: str) -> int | None:
    if part.startswith(("0x", "0X")):
        digits = part[2:]
        return int(digits, 16) if digits else None
    if part.startswith("0") and len(part) > 1:
        digits = part[1:]
        return int(digits, 8) if all(ch in "01234567" for ch in digits) else None
    return int(part, 10) if part.isascii() and part.isdigit() else None


_MIN_BARE_DECIMAL_LEGACY_IPV4 = 1 << 24


def _is_bare_decimal_legacy_ipv4_part(part: str) -> bool:
    return part == "0" or part[0] != "0"


def _is_ambiguous_bare_decimal_port(parts: list[str], decoded: list[int]) -> bool:
    if len(decoded) != 1 or decoded[0] == 0:
        return False
    is_small_value = decoded[0] < _MIN_BARE_DECIMAL_LEGACY_IPV4
    is_bare_decimal = _is_bare_decimal_legacy_ipv4_part(parts[0])
    return is_small_value and is_bare_decimal


def _decode_legacy_ipv4_host(host: str) -> int | None:
    parts = host.split(".")
    if not 1 <= len(parts) <= 4:
        return None
    decoded: list[int] = []
    for part in parts:
        value = _decode_legacy_ipv4_part(part)
        if value is None:
            return None
        decoded.append(value)
    if _is_ambiguous_bare_decimal_port(parts, decoded):
        return None
    for value in decoded[:-1]:
        if value > 255:
            return None
    remaining_bits = 8 * (5 - len(decoded))
    if decoded[-1] >= (1 << remaining_bits):
        return None
    result = 0
    for value in decoded[:-1]:
        result = (result << 8) | value
    return (result << remaining_bits) | decoded[-1]


def _is_blocked_legacy_ipv4(ip_int: int) -> bool:
    address = ipaddress.IPv4Address(ip_int)
    return any(address in network for network in _LEGACY_IPV4_BLOCKED_NETWORKS)


def _legacy_ipv4_match_is_blocked(match: re.Match) -> bool:
    ip_int = _decode_legacy_ipv4_host(match.group(1))
    return ip_int is not None and _is_blocked_legacy_ipv4(ip_int)


def _ldap_breakout_backward_window(
    text: str, close_paren_pos: int
) -> tuple[str, int, bool]:
    depth = 0
    backward_start = max(0, close_paren_pos - _LDAP_BREAKOUT_LOCAL_SCAN_CHARS)
    position = close_paren_pos - 1
    while (
        position >= backward_start
        and text[position] not in _LDAP_BREAKOUT_BACKWARD_BOUNDARY_CHARS
    ):
        if text[position] == ")":
            depth -= 1
        elif text[position] == "(":
            depth += 1
        position -= 1
    backward_window = text[position + 1 : close_paren_pos]
    depth_unresolved = backward_start > 0 and position < backward_start
    return backward_window, depth, depth_unresolved


def _ldap_next_candidate_scan_limit(match: re.Match, after: int) -> int:
    next_match = match.re.search(match.string, after)
    return next_match.end() if next_match else len(match.string)


def _ldap_filter_expression_forward_extent(
    text: str, start: int, scan_limit: int
) -> int:
    position = start
    depth = 0
    while True:
        boundary = _LDAP_FILTER_EXPRESSION_STRUCTURE_RE.search(
            text, position, scan_limit
        )
        if boundary is None:
            return scan_limit
        char = boundary.group()
        if char in _LDAP_BREAKOUT_FORWARD_BOUNDARY_CHARS:
            return boundary.start()
        if char == "(":
            depth += 1
        elif depth == 0:
            return boundary.start()
        else:
            depth -= 1
        position = boundary.end()


def _ldap_breakout_forward_window(match: re.Match, close_paren_pos: int) -> str:
    text: str = match.string
    scan_limit = _ldap_next_candidate_scan_limit(match, match.end())
    extent = _ldap_filter_expression_forward_extent(
        text, close_paren_pos + 1, scan_limit
    )
    return text[close_paren_pos:extent]


def _ldap_wildcard_chain_is_injection(match: re.Match) -> bool:
    text = match.string
    close_paren_pos = match.start() + match.group().index(")")

    backward_window, depth, depth_unresolved = _ldap_breakout_backward_window(
        text, close_paren_pos
    )
    forward_window = _ldap_breakout_forward_window(match, close_paren_pos)

    wildcard_adjacent = match.group().startswith("*")
    depth_proves_breakout = depth <= 0 and (wildcard_adjacent or not depth_unresolved)
    depth_or_wildcard_clause = depth_proves_breakout or bool(
        _LDAP_BREAKOUT_WILDCARD_CLAUSE_END_RE.search(backward_window)
    )
    if not depth_or_wildcard_clause:
        return False
    return bool(
        _LDAP_BREAKOUT_ATTACK_TOKEN_RE.search(backward_window)
        or _LDAP_BREAKOUT_ATTACK_TOKEN_RE.search(forward_window)
    )


def _ldap_paren_conjunction_is_injection(match: re.Match) -> bool:
    text = match.string
    scan_limit = _ldap_next_candidate_scan_limit(match, match.end())
    tail_end = _ldap_filter_expression_forward_extent(text, match.end(), scan_limit)
    tail = text[match.end() : tail_end]
    if _LDAP_PAREN_CONJUNCTION_FOLLOWUP_SYMBOL_RE.match(tail):
        return True
    return "=" in tail and bool(_LDAP_PAREN_CONJUNCTION_FOLLOWUP_ATTR_RE.match(tail))
