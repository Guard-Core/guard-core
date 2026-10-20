import errno
import gc
import importlib
import socket
import ssl
import struct
import sys
import threading
import time
import weakref
from collections.abc import Callable, Generator, Iterator
from contextlib import AbstractContextManager, ExitStack, contextmanager
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import OpenSSL.SSL
import pytest
from urllib3.connection import HTTPConnection, HTTPSConnection
from urllib3.connectionpool import HTTPConnectionPool
from urllib3.contrib.pyopenssl import WrappedSocket
from urllib3.util.ssl_ import ssl_wrap_socket
from urllib3.util.ssltransport import SSLTransport

from guard_core.sync.handlers._ipinfo_download_cut import (
    DownloadCut,
    RecordingAdapter,
    _close_sockets_ssl_create_left_open,
)
from guard_core.sync.handlers.ipinfo_handler import IPInfoManager
from tests.geo_fixture import (
    HOST,
    GeoDownloadServer,
    connect_proxy_server,
    count_connections,
    make_tls_material,
    slow_handshake_server,
    socks5_proxy_server,
    stalling_server,
    tls_server_context,
    trickling_server,
)

READ_BOUND = 0.4
CONNECT_BOUND_LARGER_THAN_THE_TIME_LEFT = 3.0
TOTAL_BOUND = 1.0
MARGIN = 0.5
WORKER = "geo-connect"
DNS_STALL = 10.0
UNRESOLVABLE = "geo.example.com"


@pytest.fixture(autouse=True)
def _bounded_downloads(
    monkeypatch: pytest.MonkeyPatch,
) -> Generator[None, None, None]:
    IPInfoManager._instance = None
    monkeypatch.setattr(IPInfoManager, "_sleep", lambda self, seconds: None)
    monkeypatch.setattr(IPInfoManager, "_download_connect_timeout", READ_BOUND)
    monkeypatch.setattr(IPInfoManager, "_download_read_timeout", READ_BOUND)
    monkeypatch.setattr(IPInfoManager, "_download_total_timeout", TOTAL_BOUND)
    for name in (
        *("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY"),
        *("http_proxy", "https_proxy", "all_proxy", "no_proxy"),
    ):
        monkeypatch.delenv(name, raising=False)
    yield
    IPInfoManager._instance = None


@pytest.fixture(autouse=True)
def _no_exception_in_any_thread(
    monkeypatch: pytest.MonkeyPatch,
) -> Generator[None, None, None]:
    errors: list[str] = []
    monkeypatch.setattr(
        threading,
        "excepthook",
        lambda args: errors.append(f"{args.exc_type.__name__}: {args.exc_value}"),
    )
    yield
    _wait_for_the_setup_workers_to_end()
    assert errors == []


@pytest.fixture(scope="module")
def tls_material(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, Path]:
    return make_tls_material(tmp_path_factory.mktemp("geo-setup-tls"))


@pytest.fixture
def trusted_tls(
    tls_material: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch
) -> tuple[Path, Path]:
    monkeypatch.setenv("REQUESTS_CA_BUNDLE", str(tls_material[0]))
    return tls_material


def _manager(url: str, tmp_path: Path) -> IPInfoManager:
    manager = IPInfoManager(token="tok", db_path=tmp_path / "geo.mmdb")
    manager._download_url = url
    manager._download_retries = 1
    return manager


def _seconds_until_the_attempt_fails(manager: IPInfoManager) -> float:
    started = time.monotonic()
    with pytest.raises(TimeoutError):
        manager._fetch_and_store_database()
    return time.monotonic() - started


def _setup_workers() -> list[threading.Thread]:
    return [t for t in threading.enumerate() if t.name == WORKER]


def _wait_for_the_setup_workers_to_end(seconds: float = 2.0) -> None:
    end = time.monotonic() + seconds
    while _setup_workers() and time.monotonic() < end:
        time.sleep(0.02)


def _port(server: GeoDownloadServer) -> str:
    return server.url.split(":")[2].split("/")[0]


@contextmanager
def _stalled_setup(
    cell: str, trusted_tls: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch
) -> Iterator[str]:
    context = tls_server_context(*trusted_tls)
    proxy_url = {"http": "http://127.0.0.1:{}", "https": "https://127.0.0.1:{}"}
    proxy_scheme, _, stage = cell.partition("-")
    server: AbstractContextManager[GeoDownloadServer]
    if cell == "direct-handshake":
        server = slow_handshake_server(context, via_proxy=False)
    elif stage == "tunnel":
        proxy_tls = context if proxy_scheme == "https" else None
        server = stalling_server("header", keep_alive=True, tls=proxy_tls)
    elif stage == "handshake":
        proxy_tls = context if proxy_scheme == "https" else None
        server = slow_handshake_server(context, True, proxy_tls)
    else:
        server = connect_proxy_server("header", context, proxy_tls=context)
    with server as running:
        if cell == "direct-handshake":
            yield f"https://127.0.0.1:{_port(running)}/db"
            return
        monkeypatch.setenv(
            "HTTPS_PROXY", proxy_url[proxy_scheme].format(_port(running))
        )
        yield f"https://{HOST}/db"


SETUP_CELLS = [
    "http-tunnel",
    "https-tunnel",
    "https-handshake",
    "http-handshake",
    "direct-handshake",
    "https-origin-header",
]


@pytest.mark.parametrize("cell", SETUP_CELLS)
def test_a_stalled_connection_setup_ends_at_the_total_bound(
    cell: str,
    trusted_tls: tuple[Path, Path],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        IPInfoManager,
        "_download_connect_timeout",
        CONNECT_BOUND_LARGER_THAN_THE_TIME_LEFT,
    )
    with _stalled_setup(cell, trusted_tls, monkeypatch) as url:
        elapsed = _seconds_until_the_attempt_fails(_manager(url, tmp_path))

    assert TOTAL_BOUND <= elapsed < TOTAL_BOUND + MARGIN
    assert not (tmp_path / "geo.mmdb").exists()


def test_the_setup_worker_of_an_abandoned_tunnel_ends_soon_after_the_caller_gives_up(
    trusted_tls: tuple[Path, Path], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with _stalled_setup("http-tunnel", trusted_tls, monkeypatch) as url:
        _seconds_until_the_attempt_fails(_manager(url, tmp_path))
        _wait_for_the_setup_workers_to_end(0.5)

    assert _setup_workers() == []


@contextmanager
def _blackhole_addresses(
    monkeypatch: pytest.MonkeyPatch, addresses: list[str]
) -> Iterator[None]:
    real_getaddrinfo = socket.getaddrinfo
    real_connect = socket.socket.connect
    test_is_over = threading.Event()

    def getaddrinfo(host: Any, port: Any, *args: Any, **kwargs: Any) -> Any:
        if host != UNRESOLVABLE:
            return real_getaddrinfo(host, port, *args, **kwargs)
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, int(port)))
            for address in addresses
        ]

    def connect(sock: socket.socket, address: Any) -> None:
        if address[0] not in addresses:
            return real_connect(sock, address)
        test_is_over.wait(sock.gettimeout() or 0)
        raise TimeoutError("timed out")

    monkeypatch.setattr(socket, "getaddrinfo", getaddrinfo)
    monkeypatch.setattr(socket.socket, "connect", connect)
    try:
        yield
    finally:
        test_is_over.set()


def test_blackhole_addresses_with_a_larger_connect_bound_end_at_the_total_bound(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        IPInfoManager,
        "_download_connect_timeout",
        CONNECT_BOUND_LARGER_THAN_THE_TIME_LEFT,
    )
    with _blackhole_addresses(monkeypatch, ["192.0.2.1", "192.0.2.2"]):
        elapsed = _seconds_until_the_attempt_fails(
            _manager(f"http://{UNRESOLVABLE}/db", tmp_path)
        )

    assert TOTAL_BOUND <= elapsed < TOTAL_BOUND + MARGIN


def test_the_second_address_is_tried_when_the_first_refuses(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    refusing = socket.create_server(("127.0.0.1", 0))
    refused_port = refusing.getsockname()[1]
    refusing.close()
    real_getaddrinfo = socket.getaddrinfo
    with trickling_server(gap=0.01, pieces=3) as server:
        served_port = int(_port(server))

        def getaddrinfo(host: Any, port: Any, *args: Any, **kwargs: Any) -> Any:
            if host != UNRESOLVABLE:
                return real_getaddrinfo(host, port, *args, **kwargs)
            return [
                (
                    socket.AF_INET,
                    socket.SOCK_STREAM,
                    6,
                    "",
                    ("127.0.0.1", refused_port),
                ),
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", served_port)),
            ]

        monkeypatch.setattr(socket, "getaddrinfo", getaddrinfo)
        manager = _manager(f"http://{UNRESOLVABLE}:{served_port}/db", tmp_path)
        manager._fetch_and_store_database()

    assert manager.db_path.exists()


class _StubResolver:
    """A resolver that never answers: patched lookups, or a UDP stub the libc uses."""

    def __init__(self) -> None:
        self.released = threading.Event()

    def lookup(self, host: Any, *args: Any, **kwargs: Any) -> Any:
        self.released.wait(DNS_STALL)
        raise socket.gaierror(socket.EAI_NONAME, "the stalled resolver gave up")


@pytest.fixture(params=["patched", "udp-stub"])
def silent_resolver(
    request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch
) -> Generator[None, None, None]:
    resolver = _StubResolver()
    stop = threading.Event()
    swallower: threading.Thread | None = None
    if request.param == "patched":
        real_getaddrinfo = socket.getaddrinfo

        def getaddrinfo(host: Any, *args: Any, **kwargs: Any) -> Any:
            if host == "127.0.0.1":
                return real_getaddrinfo(host, *args, **kwargs)
            return resolver.lookup(host)

        monkeypatch.setattr(socket, "getaddrinfo", getaddrinfo)
        monkeypatch.setattr(socket, "gethostbyname", resolver.lookup)
    else:
        udp = _bind_the_stub_resolver_the_libc_uses()
        swallower = threading.Thread(target=_swallow_queries, args=(udp, stop))
        swallower.start()
    yield
    resolver.released.set()
    stop.set()
    if swallower is not None:
        swallower.join()


def _bind_the_stub_resolver_the_libc_uses() -> socket.socket:
    try:
        resolv = Path("/etc/resolv.conf").read_text()
    except OSError:
        pytest.skip("no /etc/resolv.conf")
    if "nameserver 127.0.0.1" not in resolv.split("\n"):
        pytest.skip("the libc resolver is not pointed at 127.0.0.1 (--dns 127.0.0.1)")
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        udp.bind(("127.0.0.1", 53))
    except OSError:
        udp.close()
        pytest.skip("UDP port 53 on 127.0.0.1 is not available")
    return udp


def _swallow_queries(udp: socket.socket, stop: threading.Event) -> None:
    with udp:
        udp.settimeout(0.1)
        while not stop.is_set():
            try:
                udp.recvfrom(4096)
            except TimeoutError:
                continue


DNS_CELLS = ["origin", "http-proxy-host", "socks5h-proxy-host", "socks5-local", "hop"]


@pytest.mark.usefixtures("silent_resolver")
@pytest.mark.parametrize("cell", DNS_CELLS)
def test_a_silent_resolver_ends_every_lookup_at_the_total_bound(
    cell: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        IPInfoManager,
        "_download_connect_timeout",
        CONNECT_BOUND_LARGER_THAN_THE_TIME_LEFT,
    )
    url = f"http://{UNRESOLVABLE}/db"
    if cell == "http-proxy-host":
        monkeypatch.setenv("HTTP_PROXY", "http://proxy.example.com:3128")
    elif cell == "socks5h-proxy-host":
        monkeypatch.setenv("HTTP_PROXY", "socks5h://socks.example.com:1080")
    if cell == "socks5-local":
        with socks5_proxy_server("gzip") as proxy:
            monkeypatch.setenv("HTTP_PROXY", f"socks5://127.0.0.1:{_port(proxy)}")
            elapsed = _seconds_until_the_attempt_fails(_manager(url, tmp_path))
    elif cell == "hop":
        with _redirecting_server(url) as origin:
            elapsed = _seconds_until_the_attempt_fails(_manager(origin.url, tmp_path))
    else:
        elapsed = _seconds_until_the_attempt_fails(_manager(url, tmp_path))

    assert TOTAL_BOUND <= elapsed < TOTAL_BOUND + MARGIN


def _redirecting_server(location: str) -> GeoDownloadServer:
    response = (
        f"HTTP/1.1 302 Found\r\nLocation: {location}\r\n"
        "Content-Length: 0\r\nConnection: keep-alive\r\n\r\n"
    ).encode()
    return GeoDownloadServer(lambda conn, attempt: conn.sendall(response))


def test_a_redirect_to_an_origin_that_stalls_ends_at_the_total_bound_on_two_connections(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    connections = count_connections(monkeypatch)
    with stalling_server("trickle", keep_alive=True) as stalling:
        with _redirecting_server(stalling.url) as origin:
            elapsed = _seconds_until_the_attempt_fails(_manager(origin.url, tmp_path))

    assert TOTAL_BOUND <= elapsed < TOTAL_BOUND + MARGIN
    assert len(connections) == 2


def test_the_outcome_at_the_total_bound_is_a_timeout_error_even_if_the_cut_is_late(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(DownloadCut, "fire", lambda cut: None)
    monkeypatch.setattr(IPInfoManager, "_download_read_timeout", TOTAL_BOUND)
    with stalling_server("idle", keep_alive=True) as server:
        elapsed = _seconds_until_the_attempt_fails(_manager(server.url, tmp_path))

    assert TOTAL_BOUND <= elapsed < TOTAL_BOUND + MARGIN


@pytest.fixture
def socket_closes(
    monkeypatch: pytest.MonkeyPatch,
) -> Generator[list[str], None, None]:
    """Closes by another thread of a socket the setup worker made, worker alive."""
    created_by: weakref.WeakKeyDictionary[socket.socket, str] = (
        weakref.WeakKeyDictionary()
    )
    foreign: list[str] = []
    init, close = socket.socket.__init__, socket.socket.close

    def tracking_init(sock: socket.socket, *args: Any, **kwargs: Any) -> None:
        init(sock, *args, **kwargs)
        created_by[sock] = threading.current_thread().name

    def tracking_close(sock: socket.socket) -> None:
        closer = threading.current_thread().name
        if created_by.get(sock) == WORKER and closer != WORKER and _setup_workers():
            foreign.append(f"{type(sock).__name__} closed by {closer}, worker alive")
        close(sock)

    monkeypatch.setattr(socket.socket, "__init__", tracking_init)
    monkeypatch.setattr(socket.socket, "close", tracking_close)
    yield foreign


UNWIND_SECONDS = 0.3


def _make_the_setup_worker_unwind_slowly(monkeypatch: pytest.MonkeyPatch) -> None:
    """The worker still holds its socket when urllib3's error path closes it."""

    def slowly(connect: Callable[[Any], None]) -> Callable[[Any], None]:
        def connecting(connection: Any) -> None:
            try:
                connect(connection)
            finally:
                time.sleep(UNWIND_SECONDS)

        return connecting

    for connection_class in (HTTPConnection, HTTPSConnection):
        monkeypatch.setattr(
            connection_class, "connect", slowly(connection_class.connect)
        )


@pytest.mark.parametrize(
    "cell", ["http-tunnel", "https-tunnel", "https-handshake", "blackholes"]
)
def test_no_socket_is_closed_by_another_thread_while_its_setup_worker_lives(
    cell: str,
    socket_closes: list[str],
    trusted_tls: tuple[Path, Path],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    unraisable: list[str] = []
    monkeypatch.setattr(
        sys, "unraisablehook", lambda args: unraisable.append(str(args.exc_value))
    )
    _make_the_setup_worker_unwind_slowly(monkeypatch)
    monkeypatch.setattr(
        IPInfoManager,
        "_download_connect_timeout",
        CONNECT_BOUND_LARGER_THAN_THE_TIME_LEFT,
    )
    if cell == "blackholes":
        with _blackhole_addresses(monkeypatch, ["192.0.2.1", "192.0.2.2"]):
            _seconds_until_the_attempt_fails(
                _manager(f"http://{UNRESOLVABLE}/db", tmp_path)
            )
            _wait_for_the_setup_workers_to_end()
    else:
        with _stalled_setup(cell, trusted_tls, monkeypatch) as url:
            _seconds_until_the_attempt_fails(_manager(url, tmp_path))
            _wait_for_the_setup_workers_to_end()
    gc.collect()

    assert socket_closes == []
    assert unraisable == []


@pytest.fixture
def open_sockets() -> Generator[ExitStack, None, None]:
    with ExitStack() as stack:
        yield stack


def _pair(stack: ExitStack) -> socket.socket:
    local, remote = socket.socketpair()
    stack.enter_context(remote)
    return stack.enter_context(local)


def _tls_pair(stack: ExitStack, trusted_tls: tuple[Path, Path]) -> socket.socket:
    local, remote = socket.socketpair()
    context = tls_server_context(*trusted_tls)
    server = threading.Thread(
        target=lambda: stack.enter_context(
            context.wrap_socket(remote, server_side=True)
        ),
        daemon=True,
    )
    server.start()
    stack.callback(server.join)
    return stack.enter_context(local)


def _wrapper_and_its_os_socket(
    kind: str, stack: ExitStack, trusted_tls: tuple[Path, Path]
) -> tuple[Any, socket.socket]:
    client_context = ssl.create_default_context(cafile=str(trusted_tls[0]))
    if kind == "socket":
        sock = _pair(stack)
        return sock, sock
    if kind == "ssl-socket":
        wrapped = stack.enter_context(
            client_context.wrap_socket(
                _tls_pair(stack, trusted_tls), server_hostname=HOST
            )
        )
        return wrapped, wrapped
    if kind == "ssl-transport":
        sock = _tls_pair(stack, trusted_tls)
        return SSLTransport(sock, client_context, server_hostname=HOST), sock
    if kind == "pyopenssl":
        sock = _pair(stack)
        context = OpenSSL.SSL.Context(OpenSSL.SSL.TLS_CLIENT_METHOD)
        return WrappedSocket(OpenSSL.SSL.Connection(context, sock), sock), sock
    sock = stack.enter_context(importlib.import_module("socks").socksocket())
    return sock, sock


@pytest.mark.parametrize(
    "kind", ["socket", "ssl-socket", "ssl-transport", "pyopenssl", "socksocket"]
)
def test_every_wrapper_type_yields_its_one_os_socket_to_the_cut(
    kind: str,
    open_sockets: ExitStack,
    trusted_tls: tuple[Path, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    wrapper, os_socket = _wrapper_and_its_os_socket(kind, open_sockets, trusted_tls)
    shut_down: list[socket.socket] = []
    shutdown = socket.socket.shutdown

    def spy(sock: socket.socket, how: int) -> None:
        shut_down.append(sock)
        shutdown(sock, how)

    monkeypatch.setattr(socket.socket, "shutdown", spy)
    cut = DownloadCut(total=60)
    cut.record(wrapper)
    cut.fire()

    assert len(shut_down) == 1
    assert shut_down[0] is os_socket
    cut.stop()


def _wrapped_in(levels: int, stack: ExitStack) -> Any:
    wrapper: Any = _pair(stack)
    for _ in range(levels):
        wrapper = SimpleNamespace(socket=wrapper)
    return wrapper


def test_a_wrapper_four_levels_above_the_os_socket_is_followed(
    open_sockets: ExitStack,
) -> None:
    cut = DownloadCut(total=60)
    cut.record(_wrapped_in(4, open_sockets))
    assert cut.stop() is False


@pytest.mark.parametrize("levels", [0, 5])
def test_a_wrapper_with_no_os_socket_within_four_levels_is_a_type_error(
    levels: int, open_sockets: ExitStack
) -> None:
    wrapper = _wrapped_in(levels, open_sockets) if levels else SimpleNamespace()
    with pytest.raises(TypeError, match="no OS socket under SimpleNamespace"):
        DownloadCut(total=60).record(wrapper)


def test_a_connection_that_exposes_no_os_socket_fails_in_the_connecting_thread(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(HTTPConnection, "_new_conn", lambda self: SimpleNamespace())
    with pytest.raises(TypeError, match="no OS socket under SimpleNamespace"):
        _manager(f"http://{HOST}/db", tmp_path)._fetch_and_store_database()


def test_wrapping_a_cached_proxy_manager_again_leaves_one_recording_layer() -> None:
    adapter = RecordingAdapter(DownloadCut(total=60))
    for _ in range(3):
        manager = adapter.proxy_manager_for("http://127.0.0.1:1")

    for scheme_pool in manager.pool_classes_by_scheme.values():
        pool_class = cast(type[HTTPConnectionPool], scheme_pool)
        layers = [
            c
            for c in pool_class.ConnectionCls.__mro__
            if c.__name__ == "RecordingConnection"
        ]
        assert len(layers) == 1


def _reset_after_the_tunnel_is_up(conn: socket.socket, attempt: int) -> None:
    conn.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    conn.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
    conn.close()


def test_a_peer_that_resets_after_the_tunnel_is_up_leaves_no_unclosed_ssl_socket(
    trusted_tls: tuple[Path, Path], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    unraisable: list[str] = []
    monkeypatch.setattr(
        sys, "unraisablehook", lambda args: unraisable.append(str(args.exc_value))
    )
    real_wrap = ssl_wrap_socket

    def wrap_after_the_reset_arrived(*args: Any, **kwargs: Any) -> Any:
        time.sleep(0.3)
        return real_wrap(*args, **kwargs)

    monkeypatch.setattr(
        "urllib3.connection.ssl_wrap_socket", wrap_after_the_reset_arrived
    )
    with GeoDownloadServer(_reset_after_the_tunnel_is_up) as server:
        monkeypatch.setenv("HTTPS_PROXY", f"http://127.0.0.1:{_port(server)}")
        with pytest.raises(Exception) as failure:
            _manager(f"https://{HOST}/db", tmp_path)._fetch_and_store_database()
    failure_type = failure.type.__name__
    del failure  # its traceback would keep the half-built socket alive
    _wait_for_the_setup_workers_to_end()
    gc.collect()

    assert unraisable == []
    assert failure_type == "ConnectionError"


def test_after_the_cut_a_tunnel_that_ends_by_eof_never_reaches_the_tls_wrap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    wraps: list[object] = []
    created: list[object] = []
    real_create = cast(Any, ssl.SSLSocket)._create.__func__

    def spy_wrap(*args: Any, **kwargs: Any) -> None:
        wraps.append(args)

    def spy_create(cls: Any, *args: Any, **kwargs: Any) -> Any:
        created.append(args)
        return real_create(cls, *args, **kwargs)

    monkeypatch.setattr("urllib3.connection.ssl_wrap_socket", spy_wrap)
    monkeypatch.setattr(ssl.SSLSocket, "_create", classmethod(spy_create))
    with stalling_server("header", keep_alive=True) as server:
        monkeypatch.setenv("HTTPS_PROXY", f"http://127.0.0.1:{_port(server)}")
        _seconds_until_the_attempt_fails(_manager(f"https://{HOST}/db", tmp_path))
        _wait_for_the_setup_workers_to_end()

    assert wraps == []
    assert created == []


def _half_built_socket_in(error: BaseException) -> ssl.SSLSocket:
    trace = error.__traceback__
    while trace is not None:
        if trace.tb_frame.f_code.co_name == "_create":
            return cast(ssl.SSLSocket, trace.tb_frame.f_locals["self"])
        trace = trace.tb_next
    raise AssertionError("the failure did not pass through SSLSocket._create")


def _wrap_that_fails_in_getpeername(monkeypatch: pytest.MonkeyPatch) -> OSError:
    def refusing(sock: ssl.SSLSocket) -> None:
        raise OSError(errno.EINVAL, "Invalid argument")

    monkeypatch.setattr(ssl.SSLSocket, "getpeername", refusing)
    local, remote = socket.socketpair()
    with local, remote:
        with pytest.raises(OSError) as failure:
            ssl.create_default_context().wrap_socket(local, server_hostname=HOST)
    return failure.value


def test_the_socket_the_stdlib_wrap_left_half_built_is_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    error = _wrap_that_fails_in_getpeername(monkeypatch)
    half_built = _half_built_socket_in(error)

    _close_sockets_ssl_create_left_open(error)

    assert half_built.fileno() == -1


def test_the_half_built_socket_is_found_through_the_cause_and_context_chain(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    error = _wrap_that_fails_in_getpeername(monkeypatch)
    half_built = _half_built_socket_in(error)
    try:
        try:
            raise error
        except OSError as original:
            raise RuntimeError("setup failed") from original
    except RuntimeError as outer:
        _close_sockets_ssl_create_left_open(outer)

    assert half_built.fileno() == -1


def test_a_socket_that_another_frame_owns_is_left_open(
    open_sockets: ExitStack, trusted_tls: tuple[Path, Path]
) -> None:
    owned = _pair(open_sockets)
    try:
        raise OSError("failed elsewhere")
    except OSError as error:
        _close_sockets_ssl_create_left_open(error)

    assert owned.fileno() != -1
