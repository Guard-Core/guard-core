from typing import TYPE_CHECKING

from guard_core.exceptions import GuardRedisError
from guard_core.protocols.response_protocol import GuardResponse
from guard_core.sync.core.checks._ban_flow import BanFlow
from guard_core.sync.handlers._ipban_lookup import PendingKeysRead
from guard_core.sync.protocols.request_protocol import SyncGuardRequest

if TYPE_CHECKING:
    from guard_core.sync.core.checks._ip_ban_read import IpBanReadMixin
    from guard_core.sync.core.checks._rate_limit_ban_first import PendingRate


class PendingBan:
    """The ban read IpSecurityCheck left for a later check: the lookup has no
    local answer and the IP lists allow the request, so the read waits for the
    first check that needs it and shares its round trip."""

    def __init__(
        self, check: "IpBanReadMixin", client_ip: str, read: PendingKeysRead
    ) -> None:
        self.check = check
        self.client_ip = client_ip
        self.read = read
        self.rate: PendingRate | None = None


def resolve_pending_ban(
    request: SyncGuardRequest, category: str | None = None
) -> GuardResponse | None:
    """Read the pending ban, if any, recording the strike of ``category`` in the
    same round trip. Returns the banned response when the client is banned, so the
    caller returns it before any log, event or counter of its own."""
    flow = getattr(request.state, "guard_ban_flow", None)
    if not isinstance(flow, BanFlow) or flow.pending is None:
        return None
    pending, flow.pending = flow.pending, None
    try:
        return _resolve(flow, request, pending, category)
    except GuardRedisError as error:
        error.guard_check = pending.rate.check if pending.rate else pending.check
        raise


def _resolve(
    flow: BanFlow, request: SyncGuardRequest, pending: PendingBan, category: str | None
) -> GuardResponse | None:
    rate = pending.rate
    if rate is not None:
        from guard_core.sync.core.checks._rate_limit_ban_first import (
            resolve_ban_and_rate,
        )

        return resolve_ban_and_rate(request, pending, rate, category)
    response = pending.check.resolve_ban_read(request, pending, category)
    if response is not None:
        flow.banned_by = pending.check
    return response
