import logging
from unittest.mock import MagicMock

import pytest


def test_is_private_or_loopback_private_v4() -> None:
    from guard_core.sync.utils import _is_private_or_loopback

    assert _is_private_or_loopback("10.0.0.1") is True
    assert _is_private_or_loopback("172.16.0.1") is True
    assert _is_private_or_loopback("192.168.1.1") is True


def test_is_private_or_loopback_loopback() -> None:
    from guard_core.sync.utils import _is_private_or_loopback

    assert _is_private_or_loopback("127.0.0.1") is True
    assert _is_private_or_loopback("::1") is True


def test_is_private_or_loopback_link_local() -> None:
    from guard_core.sync.utils import _is_private_or_loopback

    assert _is_private_or_loopback("169.254.0.1") is True
    assert _is_private_or_loopback("fe80::1") is True


def test_is_private_or_loopback_public() -> None:
    from guard_core.sync.utils import _is_private_or_loopback

    assert _is_private_or_loopback("8.8.8.8") is False
    assert _is_private_or_loopback("1.1.1.1") is False


def test_is_private_or_loopback_invalid_ip() -> None:
    from guard_core.sync.utils import _is_private_or_loopback

    assert _is_private_or_loopback("not-an-ip") is False


def test_spoof_warning_at_debug_for_private_source(
    caplog: pytest.LogCaptureFixture,
) -> None:
    from guard_core.sync.utils import extract_client_ip

    request = MagicMock()
    request.state = MagicMock()
    request.state.client_ip = None
    request.client_host = "192.168.65.1"
    request.headers = {"X-Forwarded-For": "192.168.65.1"}

    config = MagicMock()
    config.trusted_proxies = ["10.0.0.1"]
    config.trusted_proxy_depth = 1

    caplog.set_level(logging.DEBUG, logger="guard_core")
    extract_client_ip(request, config, agent_handler=None)
    spoof_records = [r for r in caplog.records if "Potential IP spoof" in r.message]
    assert spoof_records
    assert all(r.levelno == logging.DEBUG for r in spoof_records)


def test_spoof_warning_at_warning_for_public_source(
    caplog: pytest.LogCaptureFixture,
) -> None:
    from guard_core.sync.utils import extract_client_ip

    request = MagicMock()
    request.state = MagicMock()
    request.state.client_ip = None
    request.client_host = "8.8.8.8"
    request.headers = {"X-Forwarded-For": "1.2.3.4"}

    config = MagicMock()
    config.trusted_proxies = ["10.0.0.1"]
    config.trusted_proxy_depth = 1

    caplog.set_level(logging.DEBUG, logger="guard_core")
    extract_client_ip(request, config, agent_handler=None)
    spoof_records = [r for r in caplog.records if "Potential IP spoof" in r.message]
    assert spoof_records
    assert all(r.levelno == logging.WARNING for r in spoof_records)


def test_no_geolocation_logs_at_debug(caplog: pytest.LogCaptureFixture) -> None:
    from guard_core.sync.utils import _log_country_check_result

    caplog.set_level(logging.DEBUG, logger="guard_core")
    _log_country_check_result("192.168.1.1", None, "no_geolocation", MagicMock())

    geo_records = [r for r in caplog.records if "not geolocated" in r.message]
    assert geo_records
    assert all(r.levelno == logging.DEBUG for r in geo_records)


def test_no_rules_logs_at_debug(caplog: pytest.LogCaptureFixture) -> None:
    from guard_core.sync.utils import _log_country_check_result

    caplog.set_level(logging.DEBUG, logger="guard_core")
    _log_country_check_result("192.168.1.1", None, "no_rules", MagicMock())

    no_rules = [r for r in caplog.records if "No countries blocked" in r.message]
    assert no_rules
    assert all(r.levelno == logging.DEBUG for r in no_rules)


def test_country_verdict_logs_at_info_by_default(
    caplog: pytest.LogCaptureFixture,
) -> None:
    from guard_core.models import SyncSecurityConfig
    from guard_core.sync.utils import _log_country_check_result

    caplog.set_level(logging.DEBUG, logger="guard_core")
    _log_country_check_result("1.2.3.4", "PL", "not_affected", SyncSecurityConfig())

    records = [
        r for r in caplog.records if "not from blocked or whitelisted" in r.message
    ]
    assert records
    assert all(r.levelno == logging.INFO for r in records)


def test_country_verdict_silenced_when_level_none(
    caplog: pytest.LogCaptureFixture,
) -> None:
    from guard_core.sync.utils import _log_country_check_result

    config = MagicMock()
    config.log_country_check_level = None

    caplog.set_level(logging.DEBUG, logger="guard_core")
    _log_country_check_result("1.2.3.4", "PL", "not_affected", config)
    _log_country_check_result("1.2.3.4", "US", "whitelisted", config)

    assert not [
        r
        for r in caplog.records
        if "whitelisted country" in r.message
        or "not from blocked or whitelisted" in r.message
    ]


def test_country_verdict_respects_configured_level(
    caplog: pytest.LogCaptureFixture,
) -> None:
    from guard_core.sync.utils import _log_country_check_result

    config = MagicMock()
    config.log_country_check_level = "WARNING"

    caplog.set_level(logging.DEBUG, logger="guard_core")
    _log_country_check_result("1.2.3.4", "US", "whitelisted", config)

    records = [r for r in caplog.records if "from whitelisted country" in r.message]
    assert records
    assert all(r.levelno == logging.WARNING for r in records)


def test_blocked_country_logs_at_warning_by_default(
    caplog: pytest.LogCaptureFixture,
) -> None:
    from guard_core.sync.utils import _log_country_check_result

    config = MagicMock()
    config.log_country_check_level = None
    config.log_suspicious_level = "WARNING"

    caplog.set_level(logging.DEBUG, logger="guard_core")
    _log_country_check_result("5.5.5.5", "RU", "blocked", config)

    records = [r for r in caplog.records if "from blocked country" in r.message]
    assert records
    assert all(r.levelno == logging.WARNING for r in records)


def test_blocked_country_respects_log_suspicious_level(
    caplog: pytest.LogCaptureFixture,
) -> None:
    from guard_core.sync.utils import _log_country_check_result

    config = MagicMock()
    config.log_suspicious_level = "ERROR"

    caplog.set_level(logging.DEBUG, logger="guard_core")
    _log_country_check_result("5.5.5.5", "RU", "blocked", config)

    records = [r for r in caplog.records if "from blocked country" in r.message]
    assert records
    assert all(r.levelno == logging.ERROR for r in records)


def test_blocked_country_silenced_when_log_suspicious_level_none(
    caplog: pytest.LogCaptureFixture,
) -> None:
    from guard_core.sync.utils import _log_country_check_result

    config = MagicMock()
    config.log_suspicious_level = None

    caplog.set_level(logging.DEBUG, logger="guard_core")
    _log_country_check_result("5.5.5.5", "RU", "blocked", config)

    assert not [r for r in caplog.records if "from blocked country" in r.message]


def test_attack_detected_log_respects_level(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    from guard_core.sync import utils
    from guard_core.sync._utils import detection_scan

    def fake_enhanced(
        *args: object, **kwargs: object
    ) -> tuple[bool, str, list[dict], str | None]:
        return True, "trigger", [{"type": "regex", "category": "sqli"}], None

    monkeypatch.setattr(detection_scan, "_check_value_enhanced", fake_enhanced)

    caplog.set_level(logging.DEBUG, logger="guard_core")
    utils._check_request_component(
        "x", "query_param:q", "query param 'q'", "1.2.3.4", "cid", None, "WARNING"
    )

    records = [r for r in caplog.records if "Potential attack detected" in r.message]
    assert records
    assert all(r.levelno == logging.WARNING for r in records)


def test_attack_detected_log_silenced_when_level_none(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    from guard_core.sync import utils
    from guard_core.sync._utils import detection_scan

    def fake_enhanced(
        *args: object, **kwargs: object
    ) -> tuple[bool, str, list[dict], str | None]:
        return True, "trigger", [{"type": "regex", "category": "sqli"}], None

    monkeypatch.setattr(detection_scan, "_check_value_enhanced", fake_enhanced)

    caplog.set_level(logging.DEBUG, logger="guard_core")
    utils._check_request_component(
        "x", "query_param:q", "query param 'q'", "1.2.3.4", "cid", None, None
    )

    assert not [r for r in caplog.records if "Potential attack detected" in r.message]


_REDIS_LOGGER_LEVEL_AT_IMPORT = logging.getLogger(
    "guard_core.sync.handlers.redis"
).level


def test_a_dangling_guard_core_redis_debug_level_set_here() -> None:
    logger = logging.getLogger("guard_core.sync.handlers.redis")
    logger.setLevel(logging.DEBUG)
    assert logger.level == logging.DEBUG


def test_b_isolation_fixture_reverts_the_dangling_redis_debug_level() -> None:
    logger = logging.getLogger("guard_core.sync.handlers.redis")
    assert logger.level == _REDIS_LOGGER_LEVEL_AT_IMPORT
