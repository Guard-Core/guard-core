from unittest.mock import MagicMock, Mock

import pytest
from pydantic import ValidationError

from guard_core.models import SecurityConfig
from guard_core.sync.protocols.geo_ip_protocol import SyncGeoIPHandler


class _DuckTypedGeoHandler:
    is_initialized = True

    def initialize(self) -> None: ...

    def initialize_redis(self, redis_handler: object) -> None: ...

    def initialize_agent(self, agent_handler: object) -> None: ...

    def get_country(self, ip: str) -> str | None:
        return None

    def refresh(self) -> None: ...

    def close(self) -> None: ...


@pytest.mark.parametrize(
    "handler",
    [
        _DuckTypedGeoHandler(),
        Mock(),
        MagicMock(),
        MagicMock(spec=SyncGeoIPHandler),
    ],
    ids=["duck-typed", "mock", "magic-mock", "spec-mock"],
)
def test_geo_ip_handler_with_every_member_is_accepted_on_every_interpreter(
    handler: object,
) -> None:
    config = SecurityConfig(enable_redis=False, geo_ip_handler=handler)

    assert config.geo_ip_handler is handler


@pytest.mark.parametrize("member", ["get_country", "close", "refresh"])
def test_geo_ip_handler_with_a_missing_method_is_refused(member: str) -> None:
    handler = _DuckTypedGeoHandler()
    setattr(handler, member, None)

    with pytest.raises(ValidationError, match="instance of SyncGeoIPHandler"):
        SecurityConfig(enable_redis=False, geo_ip_handler=handler)


def test_geo_ip_handler_without_the_members_is_refused() -> None:
    with pytest.raises(ValidationError, match="instance of SyncGeoIPHandler"):
        SecurityConfig(enable_redis=False, geo_ip_handler=object())
