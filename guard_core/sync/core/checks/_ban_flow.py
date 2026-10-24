from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from guard_core.sync.core.checks._pending_ban import PendingBan
    from guard_core.sync.core.checks._shared_strikes import FusedStrike
    from guard_core.sync.core.checks.base import SecurityCheck


class BanFlow:
    """What one request carries from the IP check to the checks after it: the ban
    read left pending, the strike a script already recorded, the check whose ban
    response a later check returns, whether this request read the ban, and the
    list verdict the IP check computed early. One object on the request state
    replaces five attributes whose probing the state wrapper charges per access."""

    __slots__ = ("pending", "fused", "banned_by", "read_done", "denied_access")

    def __init__(self) -> None:
        self.pending: PendingBan | None = None
        self.fused: FusedStrike | None = None
        self.banned_by: SecurityCheck | None = None
        self.read_done = False
        self.denied_access: Any = None
