from guard_core.models import SecurityConfig
from guard_core.sync.protocols.request_protocol import SyncGuardRequest


def async_tree(config: SecurityConfig) -> None:
    return None


async_tree(SecurityConfig[SyncGuardRequest]())
