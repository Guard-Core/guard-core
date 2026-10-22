import socket
from unittest.mock import patch

import pytest

from tests import network_guard


def test_non_loopback_connect_is_refused_and_recorded() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        with pytest.raises(network_guard.NetworkAccessError):
            sock.connect(("203.0.113.7", 443))
    assert len(network_guard.drain()) == 1


def test_non_loopback_connect_ex_is_refused_and_recorded() -> None:
    with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as sock:
        with pytest.raises(network_guard.NetworkAccessError):
            sock.connect_ex(("2001:db8::1", 443, 0, 0))
    assert len(network_guard.drain()) == 1


def test_guard_survives_patch_stopall() -> None:
    patch.stopall()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        with pytest.raises(network_guard.NetworkAccessError):
            sock.connect(("203.0.113.7", 443))
    assert len(network_guard.drain()) == 1


def test_loopback_connect_is_allowed() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
            client.connect(server.getsockname())
    assert network_guard.drain() == []


@pytest.mark.parametrize(
    ("family", "address", "allowed"),
    [
        (socket.AF_INET6, ("::1", 80, 0, 0), True),
        (socket.AF_INET6, ("::ffff:127.0.0.1", 80, 0, 0), True),
        (socket.AF_INET, ("localhost", 80), True),
        (socket.AF_UNIX, "/tmp/any.sock", True),
        (socket.AF_INET, ("143.204.55.127", 443), False),
        (socket.AF_INET, ("example.com", 443), False),
        (socket.AF_INET6, ("2001:db8::1", 443, 0, 0), False),
    ],
)
def test_is_allowed_decision(family: int, address: object, allowed: bool) -> None:
    assert network_guard.is_allowed(family, address) is allowed
