from typing import Any
from unittest.mock import MagicMock

import pytest

from guard_core.models import SecurityConfig
from guard_core.sync.core.checks.factory import build_default_pipeline
from guard_core.sync.core.validation.context import ValidationContext
from guard_core.sync.core.validation.validator import RequestValidator
from guard_core.sync.decorators import SecurityDecorator
from tests.test_sync.conftest import SyncMockGuardRequest
from tests.test_sync.test_core.conftest import LOGGER, build_middleware


def _config(**settings: Any) -> SecurityConfig:
    return SecurityConfig(
        enable_redis=False,
        enable_penetration_detection=False,
        enable_rate_limiting=False,
        enforce_https=True,
        trust_x_forwarded_proto=True,
        **{"trusted_proxies": ["10.0.0.5"], **settings},
    )


def _status(
    config: SecurityConfig, client_host: str | None, forwarded_proto: str | None
) -> int | None:
    pipeline = build_default_pipeline(
        build_middleware(config, SecurityDecorator(config))
    )
    headers = {} if forwarded_proto is None else {"X-Forwarded-Proto": forwarded_proto}
    request = SyncMockGuardRequest(
        path="/x", scheme="http", client_host=client_host, headers=headers
    )
    response = pipeline.execute(request)
    return None if response is None else response.status_code


def _validator(config: SecurityConfig) -> RequestValidator:
    return RequestValidator(
        ValidationContext(config=config, logger=LOGGER, event_bus=MagicMock())
    )


def test_a_trusted_proxy_forwarding_https_is_https() -> None:
    assert _status(_config(), "10.0.0.5", "https") is None


def test_a_mapped_ipv4_peer_is_the_trusted_proxy() -> None:
    assert _status(_config(), "::ffff:10.0.0.5", "https") is None


def test_a_unix_socket_peer_is_trusted_with_the_unix_token() -> None:
    config = _config(trusted_proxies=["unix"])

    assert _status(config, None, "https") is None


def test_a_unix_socket_peer_is_not_trusted_without_the_unix_token() -> None:
    assert _status(_config(), None, "https") == 301


def test_a_non_ip_peer_with_a_cidr_proxy_is_not_trusted_and_does_not_fail() -> None:
    config = _config(trusted_proxies=["10.0.0.0/8"])

    assert _status(config, "testclient", "https") == 301


def test_an_untrusted_peer_forwarding_https_is_redirected() -> None:
    assert _status(_config(), "203.0.113.9", "https") == 301


def test_the_proxy_appended_entry_decides_at_depth_one() -> None:
    assert _status(_config(), "10.0.0.5", "https,http") == 301
    assert _status(_config(), "10.0.0.5", "http,https") is None


def test_the_entry_at_trusted_proxy_depth_decides() -> None:
    config = _config(trusted_proxy_depth=2)

    assert _status(config, "10.0.0.5", "https,http") is None
    assert _status(config, "10.0.0.5", "http,https") == 301


def test_a_chain_shorter_than_the_depth_uses_its_leftmost_entry() -> None:
    config = _config(trusted_proxy_depth=3)

    assert _status(config, "10.0.0.5", "https") is None
    assert _status(config, "10.0.0.5", "https,http") is None


@pytest.mark.parametrize("value", ["HTTPS", " https ", "Https"])
def test_the_scheme_is_case_insensitive_and_trimmed(value: str) -> None:
    assert _status(_config(), "10.0.0.5", value) is None


@pytest.mark.parametrize("value", ["wss", "javascript", "", "https;evil", "httpss"])
def test_only_http_and_https_are_accepted(value: str) -> None:
    assert _status(_config(), "10.0.0.5", value) == 301


@pytest.mark.parametrize(
    "peer, trusted, expected",
    [
        ("::ffff:10.0.0.5", ["10.0.0.5"], True),
        ("10.0.0.5", ["10.0.0.0/8"], True),
        ("testclient", ["10.0.0.0/8"], False),
        ("203.0.113.9", ["10.0.0.5"], False),
    ],
)
def test_the_validator_uses_the_shared_trusted_peer_test(
    peer: str, trusted: list[str], expected: bool
) -> None:
    validator = _validator(_config(trusted_proxies=trusted))

    assert validator.is_trusted_proxy(peer) is expected


def test_the_validator_reads_forwarded_proto_like_the_check() -> None:
    config = _config(trusted_proxy_depth=2)
    validator = _validator(config)
    request = SyncMockGuardRequest(
        scheme="http",
        client_host="10.0.0.5",
        headers={"X-Forwarded-Proto": "https,http"},
    )

    assert validator.is_request_https(request) is True
