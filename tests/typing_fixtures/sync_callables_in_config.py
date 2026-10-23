from guard_core.models import SecurityConfig
from guard_core.protocols.request_protocol import GuardRequest
from guard_core.protocols.response_protocol import GuardResponse
from guard_core.sync.protocols.request_protocol import SyncGuardRequest


def sync_check_on_the_guard_request(request: GuardRequest) -> GuardResponse | None:
    return None


def sync_check_on_the_sync_request(request: SyncGuardRequest) -> GuardResponse | None:
    return None


async def async_check(request: GuardRequest) -> GuardResponse | None:
    return None


def sync_modifier(response: GuardResponse) -> GuardResponse:
    return response


async def async_modifier(response: GuardResponse) -> GuardResponse:
    return response


sync_config = SecurityConfig(
    custom_request_check=sync_check_on_the_guard_request,
    custom_response_modifier=sync_modifier,
)
sync_request_config = SecurityConfig[SyncGuardRequest](
    custom_request_check=sync_check_on_the_sync_request
)
async_config = SecurityConfig(
    custom_request_check=async_check, custom_response_modifier=async_modifier
)
