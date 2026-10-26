from typing import TypeGuard

from pydantic_core import PydanticCustomError

from guard_core.protocols.cloud_ip_store_protocol import CloudIpStoreProtocol

_CLOUD_IP_STORE_MEMBERS = tuple(
    name for name in vars(CloudIpStoreProtocol) if not name.startswith("_")
)


def _has_every_cloud_ip_store_member(value: object) -> TypeGuard[CloudIpStoreProtocol]:
    # The isinstance check of a runtime_checkable Protocol looks members up with
    # hasattr on 3.10 and 3.11 and with getattr_static from 3.12, which rejects an
    # object that serves its members from __getattr__. One hasattr check keeps
    # every interpreter on the 3.10 verdict.
    return all(
        getattr(value, name, None) is not None for name in _CLOUD_IP_STORE_MEMBERS
    )


def _validate_cloud_ip_store_value(value: object) -> CloudIpStoreProtocol:
    if not _has_every_cloud_ip_store_member(value):
        raise PydanticCustomError(
            "is_instance_of", "Input should be an instance of CloudIpStoreProtocol"
        )
    return value
