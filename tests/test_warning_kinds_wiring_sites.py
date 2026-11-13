import logging
from dataclasses import replace
from types import SimpleNamespace
from typing import cast

import pytest

from guard_core._security_headers_override import CorsParams
from guard_core._utils import body_reader, ip_extraction
from guard_core.core.behavioral import _throttle
from guard_core.core.initialization._handler_initializer_steps import (
    _HandlerInitializerStepsMixin,
)
from guard_core.handlers.behavior_handler import BehaviorRule
from guard_core.handlers.security_headers_handler import SecurityHeadersManager
from guard_core.protocols.request_protocol import GuardRequest

_DEPTH = "trusted_proxy_depth"


def _the_one_warning(caplog: pytest.LogCaptureFixture) -> logging.LogRecord:
    [record] = [r for r in caplog.records if r.levelno >= logging.WARNING]
    return record


def _problems(record: logging.LogRecord) -> object:
    return getattr(record, "problems", None)


_BASE = CorsParams(
    enabled=True,
    origins=("https://a.example",),
    credentials=False,
    methods=("GET",),
    headers=("*",),
    max_age=3600,
    expose=(),
)


def test_cors_override_fields_refused_warns_with_its_kind(
    caplog: pytest.LogCaptureFixture,
) -> None:
    manager = SecurityHeadersManager.isolated()
    merged = replace(_BASE, origins=("https://a.example", "https://b.example"))

    with caplog.at_level(logging.WARNING):
        manager._log_cors_override(_BASE, merged, "why")

    record = _the_one_warning(caplog)
    assert record.getMessage() == "CORS override fields refused for this app: why"
    assert _problems(record) == (("cors_override.fields_refused", None),)


def test_cors_override_refused_warns_with_its_kind(
    caplog: pytest.LogCaptureFixture,
) -> None:
    manager = SecurityHeadersManager.isolated()

    with caplog.at_level(logging.WARNING):
        manager._log_cors_override(_BASE, _BASE, "why")

    record = _the_one_warning(caplog)
    assert record.getMessage() == (
        "CORS override refused for this app, it keeps its own CORS: why"
    )
    assert _problems(record) == (("cors_override.refused", None),)


def test_cors_override_that_widens_warns_with_its_kind(
    caplog: pytest.LogCaptureFixture,
) -> None:
    manager = SecurityHeadersManager.isolated()
    merged = replace(_BASE, origins=("https://a.example", "https://b.example"))

    with caplog.at_level(logging.WARNING):
        manager._log_cors_override(_BASE, merged, None)

    record = _the_one_warning(caplog)
    assert record.getMessage() == (
        "CORS override widens the CORS of this app: enabled=True, origins="
        "https://a.example, https://b.example, credentials=False"
    )
    assert _problems(record) == (("cors_override.widens", None),)


async def test_a_configured_cors_value_that_is_no_header_value_warns_with_its_kind(
    caplog: pytest.LogCaptureFixture,
) -> None:
    manager = SecurityHeadersManager.isolated()
    manager.cors_config = {
        "origins": ["https://a.example"],
        "allow_credentials": False,
        "allow_methods": ["GE\nT"],
        "allow_headers": ["*"],
        "max_age": 1,
    }

    with caplog.at_level(logging.WARNING):
        headers = await manager.get_cors_headers("https://a.example")

    record = _the_one_warning(caplog)
    assert headers == {}
    assert record.getMessage() == "CORS headers not emitted, a header value is invalid"
    assert _problems(record) == (("cors.header_value_invalid", None),)


async def test_a_request_origin_with_a_control_character_never_reaches_the_validator(
    caplog: pytest.LogCaptureFixture,
) -> None:
    manager = SecurityHeadersManager.isolated()
    manager.cors_config = {
        "origins": ["https://a.example"],
        "allow_credentials": False,
        "allow_methods": ["GET"],
        "allow_headers": ["*"],
        "max_age": 1,
    }

    with caplog.at_level(logging.WARNING):
        headers = await manager.get_cors_headers("https://a.example\r\nX: y")

    assert headers == {}
    assert [r for r in caplog.records if r.levelno >= logging.WARNING] == []


async def test_dynamic_rules_without_an_agent_warn_with_their_kind(
    caplog: pytest.LogCaptureFixture,
) -> None:
    stub = SimpleNamespace(
        config=SimpleNamespace(enable_dynamic_rules=True),
        agent_handler=None,
        logger=logging.getLogger("guard_core.kind_pin"),
    )

    with caplog.at_level(logging.WARNING):
        await _HandlerInitializerStepsMixin.initialize_dynamic_rule_manager(
            cast("_HandlerInitializerStepsMixin", stub)
        )

    record = _the_one_warning(caplog)
    assert record.getMessage() == (
        "enable_dynamic_rules is True but this app has no agent handler, so no "
        "dynamic rule can arrive and the static configuration stays in force. "
        "Start the agent (enable_agent=True with the guard-agent package "
        "installed) or set enable_dynamic_rules=False."
    )
    assert _problems(record) == (("dynamic_rules.enabled_without_agent", None),)


@pytest.fixture
def _fresh_once_flags(monkeypatch: pytest.MonkeyPatch) -> None:
    for flag in (
        "_forwarded_header_preemption_warned",
        "_forwarded_header_chain_too_short_warned",
        "_forwarded_header_selected_entry_trusted_proxy_warned",
        "_forwarded_header_depth_overcounts_hops_warned",
    ):
        monkeypatch.setattr(ip_extraction, flag, False)


@pytest.mark.usefixtures("_fresh_once_flags")
def test_a_forwarded_chain_the_server_resolved_first_warns_with_its_kind(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.WARNING):
        for _ in range(2):
            ip_extraction._warn_forwarded_header_preempted(
                "203.0.113.7", "203.0.113.7, 198.51.100.1"
            )

    record = _the_one_warning(caplog)
    assert record.getMessage().startswith(
        "The connecting IP (203.0.113.7) already appears inside its own "
        "X-Forwarded-For chain: the application server resolved the client from "
        "that header before guard-core ran, most likely because the server's own "
        "forwarded-header handling is enabled (uvicorn defaults to "
        "proxy_headers=True)."
    )
    assert record.getMessage().endswith(
        "on TLS-terminating hosts such as Render or Heroku. "
        "This warning is logged once."
    )
    assert _problems(record) == (("forwarded_header.preempted_by_server", _DEPTH),)


@pytest.mark.usefixtures("_fresh_once_flags")
def test_a_chain_shorter_than_the_depth_warns_once_with_its_kind(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.WARNING):
        for _ in range(2):
            ip_extraction._warn_forwarded_header_chain_too_short("1.2.3.4", 1)

    record = _the_one_warning(caplog)
    assert record.getMessage() == (
        "The X-Forwarded-For chain has only 1 entries, fewer than the configured "
        "trusted_proxy_depth; chain was 1.2.3.4; falling back to the connecting "
        "peer as the client. This warning is logged once."
    )
    assert _problems(record) == (("trusted_proxy_depth.chain_too_short", _DEPTH),)


@pytest.mark.usefixtures("_fresh_once_flags")
def test_a_depth_that_selects_a_trusted_proxy_warns_once_with_its_kind(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.WARNING):
        for _ in range(2):
            ip_extraction._warn_forwarded_header_selected_entry_trusted_proxy(
                "10.0.0.1"
            )

    record = _the_one_warning(caplog)
    assert record.getMessage() == (
        "trusted_proxy_depth selected 10.0.0.1 from the X-Forwarded-For chain, "
        "but that address is itself listed in trusted_proxies; the chain likely "
        "has more proxy hops than trusted_proxy_depth accounts for. This warning "
        "is logged once."
    )
    assert _problems(record) == (("trusted_proxy_depth.selects_trusted_proxy", _DEPTH),)


@pytest.mark.usefixtures("_fresh_once_flags")
def test_a_depth_that_overcounts_the_hops_warns_once_with_its_kind(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.WARNING):
        for _ in range(2):
            ip_extraction._warn_forwarded_header_depth_overcounts_hops(
                2, "1.2.3.4, 5.6.7.8"
            )

    record = _the_one_warning(caplog)
    assert record.getMessage() == (
        "trusted_proxy_depth selected an entry from the X-Forwarded-For chain "
        "with 2 entry/entries to its right that are not listed in "
        "trusted_proxies; chain was 1.2.3.4, 5.6.7.8; the declared depth "
        "over-counts the real proxy hops. Set trusted_proxy_depth to the number "
        "of proxies that append to X-Forwarded-For. This warning is logged once."
    )
    assert _problems(record) == (("trusted_proxy_depth.overcounts_hops", _DEPTH),)


class _PlainRequest:
    pass


def test_a_request_class_without_an_idle_deadline_warns_once_with_its_kind(
    caplog: pytest.LogCaptureFixture,
) -> None:
    body_reader._fallback_warned_kinds.clear()
    request = cast("GuardRequest", _PlainRequest())

    with caplog.at_level(logging.WARNING):
        for _ in range(2):
            body_reader._warn_body_reader_fallback_once_per_app(
                request, body_reader._PREFIX, None
            )

    record = _the_one_warning(caplog)
    assert record.getMessage() == (
        "_PlainRequest has no read_body_prefix_until_idle; its read_body_prefix "
        "is read in full with no idle deadline, so a client that stops sending "
        "holds the request until the server's own timeout"
    )
    assert _problems(record) == (("body_reader.prefix_without_idle_deadline", None),)


def test_a_request_class_without_a_bounded_reader_warns_once_with_its_kind(
    caplog: pytest.LogCaptureFixture,
) -> None:
    body_reader._fallback_warned_kinds.clear()
    request = cast("GuardRequest", _PlainRequest())

    with caplog.at_level(logging.WARNING):
        for _ in range(2):
            body_reader._warn_body_reader_fallback_once_per_app(
                request, body_reader._FULL_BODY, None
            )

    record = _the_one_warning(caplog)
    assert record.getMessage() == (
        "_PlainRequest has neither read_body_prefix_until_idle nor "
        "read_body_prefix; body() is read in full with no idle deadline, so a "
        "client that stops sending holds the request until the server's own "
        "timeout"
    )
    assert _problems(record) == (("body_reader.no_bounded_reader", None),)


def test_a_throttle_rule_without_a_middleware_warns_once_with_its_kind(
    caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(_throttle, "_missing_middleware_warned", False)
    rules = [BehaviorRule("usage", 5, window=60, action="throttle")]

    with caplog.at_level(logging.WARNING):
        for _ in range(2):
            _throttle.warn_throttle_needs_middleware(rules)

    record = _the_one_warning(caplog)
    assert record.getMessage() == (
        "Behavior throttle rules are only logged: this adapter does not pass its "
        "middleware to the behavioral processor, so the engine cannot answer 429. "
        "Upgrade the adapter to enforce throttle rules. Rules: usage "
        "threshold=5 window=60s. Missing capability: a middleware with "
        "create_error_response, passed to the BehavioralContext or reachable "
        "through the pipeline's checks."
    )
    assert _problems(record) == (("behavior_rules.throttle_needs_middleware", None),)
