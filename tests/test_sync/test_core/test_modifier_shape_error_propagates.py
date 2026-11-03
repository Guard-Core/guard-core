import logging
from typing import Any, cast

import pytest

from guard_core._security_config_fields import CustomResponseModifier
from guard_core.exceptions import CallableShapeError
from guard_core.models import SyncSecurityConfig
from guard_core.protocols.response_protocol import GuardResponse
from guard_core.sync.core.responses import reads_response_body
from guard_core.sync.core.responses.context import ResponseContext
from guard_core.sync.core.responses.factory import ErrorResponseFactory


class _Metrics:
    def collect_request_metrics(self, *args: object, **kwargs: object) -> None:
        return None


class _Request:
    def __init__(self) -> None:
        self.url_path = "/api"
        self.method = "GET"
        self.headers: dict[str, str] = {}
        self.state = type("State", (), {})()


class _StreamedResponse:
    """An adapter response whose body is not in memory, so the bounded read runs."""

    def __init__(self, body: bytes) -> None:
        self.status_code = 200
        self.headers = {"Content-Length": str(len(body))}
        self._body = body

    def read_body_prefix(self, max_bytes: int) -> bytes:
        return self._body[:max_bytes]


def _process(modifier: CustomResponseModifier) -> GuardResponse:
    config = SyncSecurityConfig(enable_redis=False)
    config.custom_response_modifier = modifier
    factory = ErrorResponseFactory(
        ResponseContext(
            config=config,
            logger=logging.getLogger("guard_core.test_shape_error"),
            metrics_collector=cast(Any, _Metrics()),
            response_factory=None,
        )
    )
    return factory.process_response(
        cast(Any, _Request()),
        cast(GuardResponse, _StreamedResponse(b"hello")),
        0.0,
        None,
    )


def test_a_marked_modifier_that_raises_a_shape_error_is_not_swallowed() -> None:
    def modifier(response: GuardResponse) -> GuardResponse:
        raise CallableShapeError("custom_response_modifier")

    with pytest.raises(CallableShapeError):
        _process(reads_response_body(modifier))
