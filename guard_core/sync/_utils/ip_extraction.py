import logging
from collections.abc import Sequence
from functools import lru_cache
from ipaddress import (
    IPv4Address,
    IPv4Network,
    IPv6Address,
    IPv6Network,
    ip_address,
    ip_network,
)

from guard_core.sync._utils.agent_events import send_agent_event
from guard_core.sync._utils.forwarded_config import ForwardedForConfig
from guard_core.sync._utils.logging_utils import _sanitize_for_log
from guard_core.sync._utils.nat64 import (
    _decoded_nat64_embedded_ipv4,
    _unwrap_nat64,
    _warn_non_global_embedded_once_a_minute,
)
from guard_core.sync._utils.sampling import CountedKeys, PerApp, observe_counted_key
from guard_core.sync._utils.whitelist_match import is_listed
from guard_core.sync.protocols.agent_protocol import SyncAgentHandlerProtocol
from guard_core.sync.protocols.request_protocol import SyncGuardRequest

logger = logging.getLogger("guard_core")

UNKNOWN_CLIENT_IDENTITY = "unknown"
MALFORMED_FORWARDED_FOR_PREFIX = "malformed-xff@"

_PER_ADDRESS_IDENTITY_NETWORKS = (
    ip_network("2001::/32"),
    ip_network("64:ff9b::/96"),
    ip_network("64:ff9b:1::/48"),
)
_SIX_TO_FOUR_NETWORK = ip_network("2002::/16")
_SIX_TO_FOUR_IDENTITY_PREFIX_LENGTH = 48


def _peer_address_for_matching(value: str) -> IPv4Address | IPv6Address | None:
    candidate = value.strip()
    if candidate.startswith("[") and candidate.endswith("]"):
        candidate = candidate[1:-1]
    try:
        addr = ip_address(candidate.partition("%")[0])
    except ValueError:
        return None
    if isinstance(addr, IPv6Address) and addr.ipv4_mapped is not None:
        return addr.ipv4_mapped
    if isinstance(addr, IPv6Address):
        return _unwrap_nat64(addr) or addr
    return addr


def _is_trusted_proxy(connecting_ip: str, trusted_proxies: Sequence[str]) -> bool:
    peer_address = _peer_address_for_matching(connecting_ip)
    if peer_address is None:
        return False
    try:
        return is_listed(peer_address, peer_address, trusted_proxies, "proxy")
    except ValueError:
        return False


def _canonical_ip_address(addr: IPv4Address | IPv6Address) -> IPv4Address | IPv6Address:
    if isinstance(addr, IPv6Address) and addr.scope_id is None:
        if addr.ipv4_mapped is not None:
            return addr.ipv4_mapped
        return _unwrap_nat64(addr) or addr
    return addr


def _canonical_ip_text(addr: IPv4Address | IPv6Address) -> str:
    return str(_canonical_ip_address(addr))


def _strip_ip_brackets(value: str) -> str:
    if value.startswith("[") and value.endswith("]"):
        return value[1:-1]
    return value


def _strip_forwarded_entry_port(value: str) -> str:
    if value.startswith("["):
        closing = value.find("]")
        if closing == -1:
            return value
        remainder = value[closing + 1 :]
        if remainder and not (remainder.startswith(":") and remainder[1:].isdigit()):
            return value
        return value[1:closing]
    if value.count(":") == 1:
        host, _, port = value.partition(":")
        if port.isdigit():
            return host
    return value


def _strip_zone_id(value: str) -> str:
    return value.partition("%")[0] if ":" in value else value


_IDENTITY_CACHE_ENTRIES = 4096


@lru_cache(maxsize=_IDENTITY_CACHE_ENTRIES)
def _canonical_ip_text_and_nat64_warning(
    value: str,
) -> tuple[str, IPv4Address | None]:
    try:
        addr = ip_address(_strip_zone_id(_strip_ip_brackets(value)))
    except ValueError:
        return value, None
    if isinstance(addr, IPv6Address):
        if addr.ipv4_mapped is not None:
            return str(addr.ipv4_mapped), None
        embedded = _decoded_nat64_embedded_ipv4(addr)
        if embedded is not None and embedded.is_global:
            return str(embedded), None
        if embedded is not None:
            return str(addr), embedded
    return str(addr), None


@lru_cache(maxsize=_IDENTITY_CACHE_ENTRIES)
def _parsed_ip_or_none(text: str) -> IPv4Address | IPv6Address | None:
    try:
        return ip_address(text)
    except ValueError:
        return None


def _canonicalize_ip(value: str) -> str:
    text, non_global_embedded = _canonical_ip_text_and_nat64_warning(value)
    if non_global_embedded is not None:
        _warn_non_global_embedded_once_a_minute(non_global_embedded)
    return text


def _is_per_address_identity(addr: IPv6Address) -> bool:
    return any(addr in network for network in _PER_ADDRESS_IDENTITY_NETWORKS)


def _identity_group_prefix_length(addr: IPv6Address, prefix_length: int) -> int:
    if addr in _SIX_TO_FOUR_NETWORK:
        return _SIX_TO_FOUR_IDENTITY_PREFIX_LENGTH
    return prefix_length


def _whitelist_entry_network(
    whitelist_entry: str | None, addr: IPv4Address | IPv6Address
) -> IPv4Network | IPv6Network | None:
    if whitelist_entry is None:
        return None
    entry = ip_network(whitelist_entry, strict=False)
    if addr not in entry:
        raise ValueError(f"{whitelist_entry} does not contain {addr}")
    return entry


def _network_text(addr: IPv6Address, prefix_length: int) -> str:
    shift = 128 - prefix_length
    return str(IPv6Network(((int(addr) >> shift) << shift, prefix_length)))


@lru_cache(maxsize=_IDENTITY_CACHE_ENTRIES)
def _client_identity(
    address: str, prefix_length: int, whitelist_entry: str | None = None
) -> str:
    try:
        parsed = ip_address(_strip_zone_id(_strip_ip_brackets(address)))
    except ValueError:
        return address
    addr = _canonical_ip_address(parsed)
    canonical = str(addr)
    if prefix_length == 128:
        return canonical
    if isinstance(addr, IPv4Address) or _is_per_address_identity(addr):
        return canonical
    entry = _whitelist_entry_network(whitelist_entry, addr)
    group_length = _identity_group_prefix_length(addr, prefix_length)
    if entry is not None and entry.prefixlen >= group_length:
        return str(entry)
    return _network_text(addr, group_length)


def _forwarded_header_candidate_has_metachar(candidate: str) -> bool:
    return any(metachar in candidate for metachar in ("*", "?", "[", "]", "\\"))


def _forwarded_header_candidate(forwarded_for: str, proxy_depth: int) -> str | None:
    ips = [ip.strip() for ip in forwarded_for.split(",")]
    if len(ips) < proxy_depth:
        return None
    return _strip_forwarded_entry_port(ips[-proxy_depth])


def _forwarded_header_candidate_addr(
    candidate: str,
) -> IPv4Address | IPv6Address | None:
    try:
        return ip_address(_strip_zone_id(candidate))
    except ValueError:
        return None


def _extract_from_forwarded_header(forwarded_for: str, proxy_depth: int) -> str | None:
    if not forwarded_for:
        return None

    candidate = _forwarded_header_candidate(forwarded_for, proxy_depth)
    if candidate is None:
        return None

    addr = _forwarded_header_candidate_addr(candidate)
    if addr is None:
        return None

    if _forwarded_header_candidate_has_metachar(candidate):
        return None

    return _canonical_ip_text(addr)


def _forwarded_header_ips(forwarded_for: str) -> list[str]:
    return [_strip_forwarded_entry_port(ip.strip()) for ip in forwarded_for.split(",")]


def _forwarded_header_right_side_unlisted_count(
    ips: list[str], proxy_depth: int, trusted_proxies: Sequence[str]
) -> int:
    right_side = ips[len(ips) - proxy_depth + 1 :]
    return sum(
        1
        for entry in right_side
        if not _is_trusted_proxy(_canonicalize_ip(entry), trusted_proxies)
    )


class _MalformedForwardedEntry(Exception):
    pass


def _resolve_forwarded_chain_right_to_left(
    ips: list[str], trusted_proxies: Sequence[str]
) -> str | None:
    for entry in reversed(ips):
        if _is_trusted_proxy(_canonicalize_ip(entry), trusted_proxies):
            continue
        addr = _forwarded_header_candidate_addr(entry)
        if addr is None or _forwarded_header_candidate_has_metachar(entry):
            raise _MalformedForwardedEntry
        return _canonical_ip_text(addr)
    return None


def _is_private_or_loopback(ip: str) -> bool:
    try:
        addr = ip_address(ip)
    except ValueError:
        return False
    return addr.is_private or addr.is_loopback or addr.is_link_local


_forwarded_header_preemption_warned = False


def _warn_forwarded_header_preempted(
    connecting_ip: str, forwarded_for: str | None
) -> None:
    global _forwarded_header_preemption_warned
    if _forwarded_header_preemption_warned or not forwarded_for:
        return

    entries = [ip.strip() for ip in forwarded_for.split(",")]
    if connecting_ip not in entries:
        return

    _forwarded_header_preemption_warned = True
    logger.warning(
        "The connecting IP (%s) already appears inside its own "
        "X-Forwarded-For chain: the application server resolved the client "
        "from that header before guard-core ran, most likely because the "
        "server's own forwarded-header handling is enabled (uvicorn "
        "defaults to proxy_headers=True). While it is, the address "
        "guard-core sees is whatever the client claimed, so a rotating "
        "X-Forwarded-For defeats rate limiting and IP banning. To make "
        "guard-core the single authority, disable the server's handling "
        "(`uvicorn --no-proxy-headers`, or `proxy_headers=False` in "
        "uvicorn.run; gunicorn/hypercorn/WSGI servers have equivalent "
        "settings) AND declare the proxy via trusted_proxies / "
        "trusted_proxy_depth so guard-core resolves the real client itself. "
        "Disabling proxy_headers alone is not enough: if you also use "
        "enforce_https, set trust_x_forwarded_proto=True with the same "
        "trusted_proxies, otherwise the server stops forwarding the URL "
        "scheme and HTTPS detection breaks (infinite redirect loop) on "
        "TLS-terminating hosts such as Render or Heroku. This warning is "
        "logged once.",
        _sanitize_for_log(connecting_ip),
    )


MAX_INSPECTED_FORWARDED_ENTRIES = 32


def _bounded_forwarded_entries(value: str) -> tuple[list[str], int]:
    """The first MAX_INSPECTED_FORWARDED_ENTRIES entries of an X-Forwarded-For
    value and how many more it holds, bounded before any entry is parsed: a 16 KiB
    header has about 2,000 entries and parsing them all costs milliseconds."""
    parts = value.split(",", MAX_INSPECTED_FORWARDED_ENTRIES)
    if len(parts) <= MAX_INSPECTED_FORWARDED_ENTRIES:
        return parts, 0
    return parts[:-1], parts[-1].count(",") + 1


def _display_forwarded_chain(value: str) -> str:
    parts, more = _bounded_forwarded_entries(value)
    displayed = []
    for part in parts:
        candidate = _strip_forwarded_entry_port(part.strip())
        if _forwarded_header_candidate_addr(candidate) is not None:
            displayed.append(part)
        else:
            displayed.append("[REDACTED]")
    suffix = f", ... and {more} more" if more else ""
    return ",".join(displayed) + suffix


_UNTRUSTED_XFF_WINDOW_SECONDS = 60
_MAX_TRACKED_UNTRUSTED_PEERS = 10_000
_untrusted_peers: PerApp[CountedKeys] = PerApp("untrusted_peers", CountedKeys)


def _observe_untrusted_forwarded_for(config: object, peer: str) -> tuple[bool, int]:
    """Count one X-Forwarded-For request from an untrusted peer.

    Returns ``(sampled, suppressed_count)``. ``sampled`` is true at most once per
    peer per ``_UNTRUSTED_XFF_WINDOW_SECONDS``, so a peer that sends an
    X-Forwarded-For on every request (an unlisted CDN does) is logged and reported
    once a minute instead of once per request; ``suppressed_count`` is how many
    requests of that peer were not sampled since its last sampled one. The header
    value is never stored or compared: a rotating value is not a ban signal, only
    an X-Forwarded-For that claims a whitelisted or trusted-proxy address is. At
    most ``_MAX_TRACKED_UNTRUSTED_PEERS`` peers are tracked and the oldest is
    evicted; its pending count is kept for the next event sent. The table is the
    one of the app of ``config``: another app's sample of the same peer does not
    suppress this app's.
    """
    peers = _untrusted_peers.for_app(config)
    sampled, suppressed, evicted_pending = observe_counted_key(
        peers.entries,
        peers.lock,
        peer,
        window=_UNTRUSTED_XFF_WINDOW_SECONDS,
        max_tracked=_MAX_TRACKED_UNTRUSTED_PEERS,
    )
    if evicted_pending:
        with peers.evicted_lock:
            peers.evicted_pending += evicted_pending
    return sampled, suppressed


def _take_evicted_suppressed_count(config: object) -> int:
    return _untrusted_peers.for_app(config).take_evicted_pending()


def forwarded_for_addresses(forwarded_for: str) -> list[IPv4Address | IPv6Address]:
    addresses = []
    for entry in _bounded_forwarded_entries(forwarded_for)[0]:
        address = _peer_address_for_matching(_strip_forwarded_entry_port(entry.strip()))
        if address is not None:
            addresses.append(address)
    return addresses


def _agent_open_to_suspicious_requests(
    config: ForwardedForConfig, agent_handler: SyncAgentHandlerProtocol | None
) -> SyncAgentHandlerProtocol | None:
    from guard_core.sync.core.events.event_types import EVENT_SUSPICIOUS_REQUEST

    if (
        not config.agent_enable_events
        or EVENT_SUSPICIOUS_REQUEST in config.muted_event_types
    ):
        return None
    return agent_handler


def _handle_untrusted_proxy(
    request: SyncGuardRequest,
    connecting_ip: str,
    canonical_connecting_ip: str,
    forwarded_for: str | None,
    agent_handler: SyncAgentHandlerProtocol | None,
    config: ForwardedForConfig,
) -> str:
    if forwarded_for:
        _warn_forwarded_header_preempted(connecting_ip, forwarded_for)
        peer_is_public = not _is_private_or_loopback(connecting_ip)
        sampled, suppressed_count = _observe_untrusted_forwarded_for(
            config, canonical_connecting_ip
        )
        if peer_is_public:
            request.state.untrusted_forwarded_for = forwarded_for
        log_this_request = (
            sampled if peer_is_public else logger.isEnabledFor(logging.DEBUG)
        )
        agent = (
            _agent_open_to_suspicious_requests(config, agent_handler)
            if sampled
            else None
        )
        if not (log_this_request or agent):
            return canonical_connecting_ip
        display_forwarded_for = _display_forwarded_chain(forwarded_for)
        if log_this_request:
            (logger.warning if peer_is_public else logger.debug)(
                f"Potential IP spoof attempt: X-Forwarded-For header "
                f"({_sanitize_for_log(display_forwarded_for)}) received from "
                f"untrusted IP {_sanitize_for_log(connecting_ip)}"
            )
        if agent:
            from guard_core.sync.core.events.event_types import EVENT_SUSPICIOUS_REQUEST

            send_agent_event(
                agent,
                EVENT_SUSPICIOUS_REQUEST,
                canonical_connecting_ip,
                "spoofing_detected",
                "Potential IP spoof attempt: X-Forwarded-For header "
                f"{display_forwarded_for}",
                request,
                metadata={
                    "suppressed_count": suppressed_count,
                    "suppressed_evicted_count": _untrusted_peers.for_app(
                        config
                    ).take_evicted_pending(),
                },
            )
    return canonical_connecting_ip


_forwarded_header_chain_too_short_warned = False


def _warn_forwarded_header_chain_too_short(
    forwarded_for: str, chain_length: int
) -> None:
    global _forwarded_header_chain_too_short_warned
    if _forwarded_header_chain_too_short_warned:
        return
    _forwarded_header_chain_too_short_warned = True
    logger.warning(
        "The X-Forwarded-For chain has only %d entries, fewer than the "
        "configured trusted_proxy_depth; chain was %s; falling back to the "
        "connecting peer as the client. This warning is logged once.",
        chain_length,
        _sanitize_for_log(_display_forwarded_chain(forwarded_for)),
    )


_forwarded_header_selected_entry_trusted_proxy_warned = False


def _warn_forwarded_header_selected_entry_trusted_proxy(entry: str) -> None:
    global _forwarded_header_selected_entry_trusted_proxy_warned
    if _forwarded_header_selected_entry_trusted_proxy_warned:
        return
    _forwarded_header_selected_entry_trusted_proxy_warned = True
    logger.warning(
        "trusted_proxy_depth selected %s from the X-Forwarded-For chain, "
        "but that address is itself listed in trusted_proxies; the chain "
        "likely has more proxy hops than trusted_proxy_depth accounts for. "
        "This warning is logged once.",
        _sanitize_for_log(entry),
    )


_forwarded_header_depth_overcounts_hops_warned = False


def _warn_forwarded_header_depth_overcounts_hops(
    unlisted_right_entries: int, forwarded_for: str
) -> None:
    global _forwarded_header_depth_overcounts_hops_warned
    if _forwarded_header_depth_overcounts_hops_warned:
        return
    _forwarded_header_depth_overcounts_hops_warned = True
    logger.warning(
        "trusted_proxy_depth selected an entry from the X-Forwarded-For "
        "chain with %d entry/entries to its right that are not listed in "
        "trusted_proxies; chain was %s; the declared depth over-counts the "
        "real proxy hops. Set trusted_proxy_depth to the number of proxies "
        "that append to X-Forwarded-For. This warning is logged once.",
        unlisted_right_entries,
        _sanitize_for_log(_display_forwarded_chain(forwarded_for)),
    )


def _resolve_client_ip_from_forwarded_chain(
    canonical_connecting_ip: str,
    forwarded_for: str | None,
    proxy_depth: int,
    trusted_proxies: Sequence[str],
) -> str:
    try:
        if not forwarded_for:
            return canonical_connecting_ip

        ips = _forwarded_header_ips(forwarded_for)
        chain_length = len(ips)

        if chain_length < proxy_depth:
            _warn_forwarded_header_chain_too_short(forwarded_for, chain_length)
            return canonical_connecting_ip

        if trusted_proxies:
            unlisted_right_entries = _forwarded_header_right_side_unlisted_count(
                ips, proxy_depth, trusted_proxies
            )
            if unlisted_right_entries:
                _warn_forwarded_header_depth_overcounts_hops(
                    unlisted_right_entries, forwarded_for
                )
                resolved = _resolve_forwarded_chain_right_to_left(ips, trusted_proxies)
                return resolved if resolved is not None else canonical_connecting_ip

        client_ip = _extract_from_forwarded_header(forwarded_for, proxy_depth)
        if not client_ip:
            raise _MalformedForwardedEntry
        if _is_trusted_proxy(client_ip, trusted_proxies):
            _warn_forwarded_header_selected_entry_trusted_proxy(client_ip)
        return client_ip
    except (ValueError, IndexError) as e:
        logger.warning(f"Error processing client IP: {str(e)}")

    return canonical_connecting_ip


def _malformed_forwarded_for_identity(
    request: SyncGuardRequest,
    peer: str,
    forwarded_for: str | None,
    agent_handler: SyncAgentHandlerProtocol | None,
    config: ForwardedForConfig,
) -> str:
    peers = _untrusted_peers.for_app(config)
    if observe_counted_key(
        peers.entries,
        peers.lock,
        f"malformed:{peer}",
        window=_UNTRUSTED_XFF_WINDOW_SECONDS,
        max_tracked=_MAX_TRACKED_UNTRUSTED_PEERS,
    )[0]:
        display = _sanitize_for_log(_display_forwarded_chain(forwarded_for or ""))
        logger.warning(
            "The X-Forwarded-For entry selected by trusted_proxy_depth is empty or "
            "not an IP address (chain %s) from trusted proxy %s; the request is "
            "attributed to the identity %s%s. Logged once a minute per peer.",
            display,
            _sanitize_for_log(peer),
            MALFORMED_FORWARDED_FOR_PREFIX,
            _sanitize_for_log(peer),
        )
        from guard_core.sync.core.events.event_types import EVENT_SUSPICIOUS_REQUEST

        send_agent_event(
            _agent_open_to_suspicious_requests(config, agent_handler),
            EVENT_SUSPICIOUS_REQUEST,
            peer,
            "malformed_forwarded_for",
            f"Malformed X-Forwarded-For entry from trusted proxy: {display}",
            request,
        )
    return f"{MALFORMED_FORWARDED_FOR_PREFIX}{peer}"


def extract_client_ip(
    request: SyncGuardRequest,
    config: ForwardedForConfig,
    agent_handler: SyncAgentHandlerProtocol | None = None,
) -> str:
    cached_ip: str | None = getattr(request.state, "client_ip", None)
    if cached_ip:
        return cached_ip

    if not request.client_host:
        if "unix" in config.trusted_proxies:
            forwarded_for = request.headers.get("X-Forwarded-For")
            try:
                return _resolve_client_ip_from_forwarded_chain(
                    UNKNOWN_CLIENT_IDENTITY,
                    forwarded_for,
                    config.trusted_proxy_depth,
                    config.trusted_proxies,
                )
            except _MalformedForwardedEntry:
                return _malformed_forwarded_for_identity(
                    request,
                    UNKNOWN_CLIENT_IDENTITY,
                    forwarded_for,
                    agent_handler,
                    config,
                )
        return UNKNOWN_CLIENT_IDENTITY

    connecting_ip = request.client_host
    canonical_connecting_ip = _canonicalize_ip(connecting_ip)
    forwarded_for = request.headers.get("X-Forwarded-For")

    if not config.trusted_proxies:
        _warn_forwarded_header_preempted(connecting_ip, forwarded_for)
        return canonical_connecting_ip

    is_trusted = _is_trusted_proxy(connecting_ip, config.trusted_proxies)

    if not is_trusted:
        return _handle_untrusted_proxy(
            request,
            connecting_ip,
            canonical_connecting_ip,
            forwarded_for,
            agent_handler,
            config,
        )

    try:
        return _resolve_client_ip_from_forwarded_chain(
            canonical_connecting_ip,
            forwarded_for,
            config.trusted_proxy_depth,
            config.trusted_proxies,
        )
    except _MalformedForwardedEntry:
        return _malformed_forwarded_for_identity(
            request, canonical_connecting_ip, forwarded_for, agent_handler, config
        )
