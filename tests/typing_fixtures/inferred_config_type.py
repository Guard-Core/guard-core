from typing_extensions import reveal_type

from guard_core.models import SecurityConfig
from guard_core.protocols.response_protocol import GuardResponse
from guard_core.sync.protocols.request_protocol import SyncGuardRequest


def sync_check_on_the_sync_request(request: SyncGuardRequest) -> GuardResponse | None:
    return None


inferred = SecurityConfig(custom_request_check=sync_check_on_the_sync_request)
reveal_type(inferred)
