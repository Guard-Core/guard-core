import logging
from typing import Any, cast

from guard_core._security_config_fields import CustomResponseModifier
from guard_core.models import SyncSecurityConfig
from guard_core.protocols.response_protocol import GuardResponse
from guard_core.sync.core.responses import reads_response_body
from guard_core.sync.core.responses.context import ResponseContext
from guard_core.sync.core.responses.factory import ErrorResponseFactory


class _Metrics:
    def collect_request_metrics(self, *args: object, **kwargs: object) -> None:
        return None


class _Request:
    def __init__(self, method: str = "GET") -> None:
        self.url_path = "/api"
        self.method = method
        self.headers: dict[str, str] = {}
        self.state = type("State", (), {})()


class _Response:
    """An adapter response whose body is already in memory."""

    def __init__(self, body: bytes, materialized: object = True) -> None:
        self.status_code = 200
        self.headers = {"Content-Length": str(len(body))}
        self._body = body
        self._materialized = materialized
        self.capability_reads = 0
        self.prefix_reads = 0

    @property
    def body(self) -> bytes:
        return self._body

    @property
    def body_is_materialized(self) -> object:
        self.capability_reads += 1
        return self._materialized

    def read_body_prefix(self, max_bytes: int) -> bytes:
        self.prefix_reads += 1
        return self._body[:max_bytes]


class _Seen:
    def __init__(self) -> None:
        self.calls = 0
        self.response: object = None
        self.body: bytes | None = None
        self.refused = False


def _modifier(seen: _Seen, marked: bool = False) -> CustomResponseModifier:
    def modifier(response: GuardResponse) -> GuardResponse:
        seen.calls += 1
        seen.response = response
        try:
            seen.body = response.body
        except AttributeError:
            seen.refused = True
        response.headers["X-Mod"] = "1"
        return response

    return reads_response_body(modifier) if marked else modifier


def _process(modifier: CustomResponseModifier, response: _Response) -> GuardResponse:
    config = SyncSecurityConfig(enable_redis=False)
    config.custom_response_modifier = modifier
    factory = ErrorResponseFactory(
        ResponseContext(
            config=config,
            logger=logging.getLogger("guard_core.test_materialized"),
            metrics_collector=cast(Any, _Metrics()),
            response_factory=None,
        )
    )
    return factory.process_response(
        cast(Any, _Request()), cast(GuardResponse, response), 0.0, None
    )


def test_materialized_body_reader_gets_the_real_response_in_one_call() -> None:
    seen = _Seen()
    response = _Response(b"hello")
    result = _process(_modifier(seen), response)
    assert seen.response is response
    assert cast(object, result) is response
    assert seen.body == b"hello"
    assert (seen.calls, response.prefix_reads) == (1, 0)
    assert response.headers["X-Mod"] == "1"


def test_materialized_body_above_the_cap_comes_back_whole() -> None:
    seen = _Seen()
    body = b"z" * (262144 * 3)
    response = _Response(body)
    _process(_modifier(seen), response)
    assert seen.body == body
    assert (seen.calls, response.prefix_reads) == (1, 0)


def test_materialized_marked_modifier_is_one_direct_call() -> None:
    seen = _Seen()
    response = _Response(b"hello")
    _process(_modifier(seen, marked=True), response)
    assert seen.response is response
    assert seen.body == b"hello"
    assert (seen.calls, response.prefix_reads) == (1, 0)


def test_the_capability_is_read_once_per_response() -> None:
    response = _Response(b"hello")
    _process(_modifier(_Seen()), response)
    assert response.capability_reads == 1
