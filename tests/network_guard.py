import ipaddress
import socket
import traceback
from typing import Any

import pytest

_LOOPBACK_NAMES = frozenset({"localhost", "localhost.localdomain"})
_STACK_FRAMES = 12


class NetworkAccessError(OSError):
    pass


_violations: list[str] = []
_real_connect = socket.socket.connect
_real_connect_ex = socket.socket.connect_ex


def _host_is_loopback(host: str) -> bool:
    if host in _LOOPBACK_NAMES:
        return True
    try:
        address = ipaddress.ip_address(host.split("%", 1)[0])
    except ValueError:
        return False
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        return address.ipv4_mapped.is_loopback
    return address.is_loopback


def is_allowed(family: int, address: Any) -> bool:
    if family == socket.AF_UNIX:
        return True
    if isinstance(address, tuple) and address and isinstance(address[0], str):
        return _host_is_loopback(address[0])
    return False


def _record(address: Any) -> NetworkAccessError:
    frames = "".join(traceback.format_stack(limit=_STACK_FRAMES + 2)[:-2])
    _violations.append(f"connect to {address!r}\n{frames}")
    return NetworkAccessError(f"tests must not reach the network: {address!r}")


def _guarded_connect(self: socket.socket, address: Any) -> None:
    if not is_allowed(self.family, address):
        raise _record(address)
    _real_connect(self, address)


def _guarded_connect_ex(self: socket.socket, address: Any) -> int:
    if not is_allowed(self.family, address):
        raise _record(address)
    return _real_connect_ex(self, address)


_installer = pytest.MonkeyPatch()


def install() -> None:
    # Not unittest.mock.patch: a test that calls patch.stopall() would lift it.
    _installer.setattr(socket.socket, "connect", _guarded_connect)
    _installer.setattr(socket.socket, "connect_ex", _guarded_connect_ex)


def reset() -> None:
    _violations.clear()


def drain() -> list[str]:
    drained = list(_violations)
    _violations.clear()
    return drained
