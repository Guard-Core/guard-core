import json
import logging
from unittest.mock import MagicMock

import pytest

from guard_core._security_headers_override import OverrideRecord
from guard_core.models import SyncSecurityConfig
from guard_core.sync.handlers.security_headers_handler import SecurityHeadersManager


def _raw(keys: object) -> str:
    return json.dumps({"set_at": 1.0, "keys": keys})


@pytest.mark.parametrize(
    "keys",
    [
        {"csp": "default-src 'self'"},
        {"csp": ["default-src"]},
        {"csp": {"default-src": "'self'"}},
        {"csp": {"default-src": [1]}},
        {"hsts": "max-age=1"},
        {"hsts": {"max_age": "1"}},
        {"hsts": {"preload": "yes"}},
        {"custom": ["X-A"]},
        {"custom": {"X-A": 1}},
        {"frame_options": 5},
        {"referrer_policy": ["a"]},
    ],
)
def test_a_record_the_headers_builder_cannot_read_is_refused(keys: object) -> None:
    with pytest.raises(ValueError):
        OverrideRecord.from_json(_raw(keys))


def test_a_readable_record_is_kept() -> None:
    keys = {
        "csp": {"default-src": ["'self'"]},
        "hsts": {"max_age": 60, "include_subdomains": False},
        "custom": {"X-A": "1"},
        "frame_options": "DENY",
        "permissions_policy": None,
        "enabled": True,
    }

    assert OverrideRecord.from_json(_raw(keys)).keys == keys


def test_a_non_mapping_csp_pulled_from_redis_is_ignored_with_one_warning(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    manager = SecurityHeadersManager.isolated()
    manager.redis_handler = MagicMock()
    monkeypatch.setattr(
        manager,
        "_read_override_and_clock",
        MagicMock(return_value=_raw({"csp": "oops"})),
    )
    config = SyncSecurityConfig(
        enable_redis=False, security_headers={"enabled": True, "csp": {"a": ["b"]}}
    )

    with caplog.at_level(
        logging.WARNING, logger="guard_core.sync.handlers.security_headers"
    ):
        manager._pull_override()

    assert "Ignoring an unreadable security headers override" in caplog.text
    assert manager.resolve_headers(config)["Content-Security-Policy"] == "a b"
