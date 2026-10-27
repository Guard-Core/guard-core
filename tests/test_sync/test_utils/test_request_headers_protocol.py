from collections.abc import Iterator
from typing import overload

from guard_core.models import SyncSecurityConfig
from guard_core.sync.handlers.cors_handler import CorsHandler, is_preflight
from guard_core.sync.utils import detect_penetration_attempt
from tests.test_sync.conftest import SyncMockGuardRequest


class PairIterationHeaders:
    """The shape of Werkzeug ``EnvironHeaders``: not a Mapping, iterates pairs."""

    def __init__(self, pairs: list[tuple[str, str]]) -> None:
        self._pairs = pairs

    def __iter__(self) -> Iterator[tuple[str, str]]:
        return iter(self._pairs)

    def __contains__(self, key: str) -> bool:
        return any(name.lower() == key.lower() for name, _ in self._pairs)

    def __getitem__(self, key: str) -> str:
        for name, value in self._pairs:
            if name.lower() == key.lower():
                return value
        raise KeyError(key)

    @overload
    def get(self, key: str, /) -> str | None: ...

    @overload
    def get(self, key: str, default: str, /) -> str: ...

    def get(self, key: str, default: str | None = None, /) -> str | None:
        try:
            return self[key]
        except KeyError:
            return default

    def keys(self) -> Iterator[str]:
        return (name for name, _ in self._pairs)

    def items(self) -> Iterator[tuple[str, str]]:
        return iter(self._pairs)


class PairIterationRequest:
    def __init__(self, pairs: list[tuple[str, str]], method: str = "GET") -> None:
        self._inner = SyncMockGuardRequest(method=method)
        self._pair_headers = PairIterationHeaders(pairs)

    @property
    def url_path(self) -> str:
        return self._inner.url_path

    @property
    def url_scheme(self) -> str:
        return self._inner.url_scheme

    @property
    def url_full(self) -> str:
        return self._inner.url_full

    def url_replace_scheme(self, scheme: str) -> str:
        return self._inner.url_replace_scheme(scheme)

    @property
    def method(self) -> str:
        return self._inner.method

    @property
    def client_host(self) -> str | None:
        return self._inner.client_host

    @property
    def headers(self) -> PairIterationHeaders:
        return self._pair_headers

    @property
    def query_params(self) -> dict[str, str]:
        return self._inner.query_params

    def body(self) -> bytes:
        return self._inner.body()

    @property
    def state(self) -> object:
        return self._inner.state

    @property
    def scope(self) -> dict[str, object]:
        return self._inner.scope


def test_a_header_attack_is_detected_through_a_pair_iterating_container() -> None:
    request = PairIterationRequest(
        [("host", "example.com"), ("x-note", "<script>alert(1)</script>")]
    )

    result = detect_penetration_attempt(request, SyncSecurityConfig())

    assert result.is_threat is True


def test_clean_headers_pass_through_a_pair_iterating_container() -> None:
    request = PairIterationRequest([("host", "example.com"), ("accept", "text/html")])

    result = detect_penetration_attempt(request, SyncSecurityConfig())

    assert result.is_threat is False


def test_a_preflight_is_read_through_a_pair_iterating_container() -> None:
    pairs = [("Origin", "https://a.test"), ("Access-Control-Request-Method", "GET")]

    assert is_preflight("OPTIONS", PairIterationHeaders(pairs)) is True
    assert is_preflight("GET", PairIterationHeaders(pairs)) is False


def test_the_preflight_answer_is_built_from_a_pair_iterating_container() -> None:
    pairs = [("Origin", "https://a.test"), ("Access-Control-Request-Method", "GET")]
    config = SyncSecurityConfig(enable_cors=True, cors_allow_origins=["https://a.test"])

    response = CorsHandler(config).build_preflight_response(PairIterationHeaders(pairs))

    assert response.status_code == 200
