from guard_core.models import SecurityConfig
from guard_core.protocols.request_protocol import GuardRequest
from guard_core.protocols.response_protocol import GuardResponse
from guard_core.sync.protocols.request_protocol import SyncGuardRequest


async def async_check(request: GuardRequest) -> GuardResponse | None:
    return None


def sync_check_on_the_sync_request(request: SyncGuardRequest) -> GuardResponse | None:
    return None


async def async_verifier(request: GuardRequest, credential: str) -> str | None:
    return None


def sync_verifier(request: SyncGuardRequest, credential: str) -> str | None:
    return None


def async_tree(config: SecurityConfig) -> None:
    return None


def sync_tree(config: SecurityConfig[SyncGuardRequest]) -> None:
    return None


plain = SecurityConfig(custom_request_check=async_check, auth_verifier=async_verifier)
async_tree(plain)

wsgi = SecurityConfig[SyncGuardRequest](
    custom_request_check=sync_check_on_the_sync_request, auth_verifier=sync_verifier
)
sync_tree(wsgi)
