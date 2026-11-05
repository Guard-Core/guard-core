import json
import logging
from unittest.mock import MagicMock

import pytest
from pydantic import ValidationError

from guard_core._security_headers_override import (
    CorsParams,
    OverrideRecord,
    merge_cors,
)
from guard_core.models import SyncSecurityConfig
from guard_core.sync._utils.config_registry import REDIS_HANDLERS
from guard_core.sync.handlers.security_headers_handler import SecurityHeadersManager

LOGGER = "guard_core.sync.handlers.security_headers"


def _config(**headers: object) -> SyncSecurityConfig:
    return SyncSecurityConfig(
        enable_redis=False, security_headers={"enabled": True, **headers}
    )


def test_a_csp_report_whose_body_is_not_an_object_is_refused_not_raised() -> None:
    manager = SecurityHeadersManager.isolated()

    assert manager.validate_csp_report({"csp-report": "document-uri"}) is False
    assert (
        manager.validate_csp_report(
            {"csp-report": ["document-uri", "violated-directive", "blocked-uri"]}
        )
        is False
    )


def test_a_line_number_that_is_neither_text_nor_a_number_is_dropped() -> None:
    manager = SecurityHeadersManager.isolated()
    agent = MagicMock()
    manager.agent_handler = agent

    manager._send_csp_violation_event(
        {
            "document-uri": "https://example.com",
            "violated-directive": "script-src",
            "blocked-uri": "https://evil.example",
            "line-number": [3],
        }
    )

    assert agent.send_event.call_args[0][0].metadata["line_number"] is None


def test_events_without_an_agent_send_nothing_and_log_nothing(
    caplog: pytest.LogCaptureFixture,
) -> None:
    manager = SecurityHeadersManager.isolated()
    manager.agent_handler = None

    with caplog.at_level(logging.DEBUG, logger=LOGGER):
        manager._send_headers_applied_event("/x", {"A": "b"})
        manager._send_csp_violation_event({"document-uri": "https://e.example"})

    assert caplog.records == []


def test_a_cached_custom_headers_record_that_is_not_an_object_is_logged(
    caplog: pytest.LogCaptureFixture,
) -> None:
    manager = SecurityHeadersManager.isolated()
    redis = MagicMock()
    redis.get_key = MagicMock(side_effect=[None, None, json.dumps(["X-A", "1"])])
    manager.redis_handler = redis

    with caplog.at_level(logging.WARNING, logger=LOGGER):
        manager._load_cached_config()

    assert manager.custom_headers == {}
    assert [r.getMessage() for r in caplog.records] == [
        "Failed to load cached header config: "
        "cached custom headers are not a JSON object"
    ]


@pytest.mark.parametrize(
    ("setting", "value", "message"),
    [
        ("csp", ["default-src"], "the csp setting must map each directive"),
        ("custom", ["X-A"], "the custom setting must map header names"),
        ("hsts", "on", "the hsts setting must be a mapping of its options"),
        ("frame_options", 1, "the frame_options setting must be a string"),
    ],
)
def test_a_security_headers_setting_of_the_wrong_shape_raises_a_type_error(
    setting: str, value: object, message: str
) -> None:
    manager = SecurityHeadersManager.isolated()
    unvalidated = SyncSecurityConfig.model_construct(
        enable_redis=False, security_headers={"enabled": True, setting: value}
    )

    with pytest.raises(TypeError, match=message):
        manager.resolve_headers(unvalidated)
    with pytest.raises(ValidationError, match=message):
        _config(**{setting: value})


def test_a_cors_override_with_values_of_the_wrong_type_keeps_the_apps_own() -> None:
    base = CorsParams(True, ("https://a.example",), False, ("GET",), ("X",), 600, ())

    merged, reason = merge_cors(
        base,
        {
            "cors_origins": "https://b.example",
            "cors_allow_methods": 5,
            "cors_max_age": "99\r\nSet-Cookie: x=1",
            "cors_allow_credentials": 0,
        },
    )

    assert reason is None
    assert merged == base


def test_a_cors_override_with_valid_values_replaces_the_apps_own() -> None:
    base = CorsParams(True, ("https://a.example",), False, ("GET",), ("X",), 600, ())

    merged, _ = merge_cors(
        base,
        {
            "cors_origins": ["https://b.example"],
            "cors_allow_credentials": True,
            "cors_max_age": 5,
        },
    )

    assert merged.origins == ("https://b.example",)
    assert merged.credentials is True
    assert merged.max_age == 5


def test_the_override_pull_and_save_do_nothing_without_a_redis_handler() -> None:
    manager = SecurityHeadersManager.isolated()
    manager.redis_handler = None

    manager._override = OverrideRecord(1.0, {"frame_options": "DENY"})
    manager._override_saved_at = 0.0

    manager._pull_override()
    manager._save_override_record()

    assert manager._override_in_redis is False
    assert manager._override_saved_at == 0.0


class _NotARedisHandler:
    pass


def test_a_registered_object_that_is_not_a_redis_handler_is_not_adopted() -> None:
    manager = SecurityHeadersManager.isolated()
    config = SyncSecurityConfig(enable_redis=True, redis_url="redis://127.0.0.1:1")
    registered = _NotARedisHandler()
    REDIS_HANDLERS.register(config, registered)
    try:
        manager._find_registered_redis_handler(config)
    finally:
        REDIS_HANDLERS.drop(config)

    assert manager.redis_handler is None


class _HeadersOnlyRedisHandler:
    """Has the four members the headers override path calls and nothing else."""

    def __init__(self, config: SyncSecurityConfig) -> None:
        self.config = config

    def get_key(self, namespace: str, key: str) -> str | None:
        return None

    def set_key(
        self, namespace: str, key: str, value: str, ttl: int | None = None
    ) -> bool | None:
        return True

    get_connection = MagicMock()


def test_a_registered_handler_lacking_an_unrelated_member_is_adopted() -> None:
    manager = SecurityHeadersManager.isolated()
    config = SyncSecurityConfig(enable_redis=True, redis_url="redis://127.0.0.1:1")
    registered = _HeadersOnlyRedisHandler(config)
    assert not hasattr(registered, "is_connected")
    assert not hasattr(registered, "delete_pattern")
    REDIS_HANDLERS.register(config, registered)
    try:
        manager._find_registered_redis_handler(config)
    finally:
        REDIS_HANDLERS.drop(config)

    assert manager.redis_handler is registered
