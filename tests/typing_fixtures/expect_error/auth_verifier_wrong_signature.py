from guard_core.models import SecurityConfig
from guard_core.protocols.request_protocol import GuardRequest


def one_argument_verifier(request: GuardRequest) -> str | None:
    return None


config = SecurityConfig(auth_verifier=one_argument_verifier)
