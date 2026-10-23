from guard_core.models import SecurityConfig
from guard_core.sync.protocols.request_protocol import SyncGuardRequest


def sync_tree(config: SecurityConfig[SyncGuardRequest]) -> None:
    return None


plain = SecurityConfig()
sync_tree(plain)
