from collections.abc import Sequence
from typing import Any

from guard_core.sync._utils.ip_extraction import _is_trusted_proxy
from guard_core.sync.protocols.request_protocol import SyncGuardRequest

_UNIX_PEER_TOKEN = "unix"


def _peer_is_trusted(client_host: str | None, trusted_proxies: Sequence[str]) -> bool:
    if not client_host:
        return _UNIX_PEER_TOKEN in trusted_proxies
    return _is_trusted_proxy(client_host, trusted_proxies)


def forwarded_proto_is_https(header_value: str | None, proxy_depth: int) -> bool:
    if not header_value:
        return False
    entries = header_value.split(",")
    entry = entries[-proxy_depth] if len(entries) >= proxy_depth else entries[0]
    return entry.strip().lower() == "https"


def request_is_https(request: SyncGuardRequest, config: Any) -> bool:
    if request.url_scheme == "https":
        return True
    if not (config.trust_x_forwarded_proto and config.trusted_proxies):
        return False
    if not _peer_is_trusted(request.client_host, config.trusted_proxies):
        return False
    return forwarded_proto_is_https(
        request.headers.get("X-Forwarded-Proto"), config.trusted_proxy_depth
    )
