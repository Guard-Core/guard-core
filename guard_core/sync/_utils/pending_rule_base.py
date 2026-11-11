from copy import deepcopy
from typing import TYPE_CHECKING

from guard_core._parked_records import PENDING_RULE_BASE_RECORD
from guard_core._security_config_batch import apply_config_batch

if TYPE_CHECKING:
    from guard_core.models import SyncSecurityConfig


def record_pending_rule_base(config: object, base: dict[str, object]) -> None:
    """A release that could not withdraw the applied rules (an apply held the lock)
    leaves them on the config; its true base waits here for the config's next
    initialization."""
    try:
        object.__setattr__(config, PENDING_RULE_BASE_RECORD, base)
    except (AttributeError, TypeError):
        return


def revert_pending_rule_base(config: "SyncSecurityConfig") -> None:
    """Put the config back on the base recorded by a release that skipped the
    withdrawal, before anything of the next initialization reads it."""
    try:
        base = config.__dict__.pop(PENDING_RULE_BASE_RECORD, None)
    except AttributeError:
        return
    if base is not None:
        apply_config_batch(config, deepcopy(base))
