import logging
from itertools import count

import pytest

from guard_core._security_headers_override import (
    CorsParams,
    OverrideRecord,
    merge_cors,
)
from guard_core.models import SecurityConfig, SyncSecurityConfig
from guard_core.sync.handlers.security_headers_handler import SecurityHeadersManager

LOGGER = "guard_core.sync.handlers.security_headers"
BASE = CorsParams(
    True, ("https://a.example",), False, ("GET",), ("X-A",), 600, ("X-B",)
)
_SET_AT = count(1)


class _Collector(logging.Handler):
    def __init__(self) -> None:
        super().__init__()
        self.records: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)


def _override_keys(**keys: object) -> OverrideRecord:
    return OverrideRecord(float(next(_SET_AT)), keys)


def test_the_two_probe_overrides_keep_the_apps_own_origins_and_methods() -> None:
    merged, reason = merge_cors(
        BASE,
        {
            "cors_origins": ["https://b.example\r\nSet-Cookie: x=1"],
            "cors_allow_methods": ["GET\r\nX-Evil: 1"],
        },
    )

    assert merged == BASE
    assert reason is not None
    assert "cors_origins" in reason
    assert "cors_allow_methods" in reason
    assert "\r" not in reason and "\n" not in reason


@pytest.mark.parametrize(
    "key",
    ["cors_origins", "cors_allow_methods", "cors_allow_headers", "cors_expose_headers"],
)
@pytest.mark.parametrize("char", ["\r", "\n", "\x00", "\x1f", "\x7f"])
def test_a_control_character_in_any_cors_override_field_is_refused(
    key: str, char: str
) -> None:
    other = {"cors_max_age": 5}
    merged, reason = merge_cors(BASE, {key: [f"https://b.example{char}"], **other})

    assert reason is not None
    assert merged.max_age == 5
    assert merged.origins == BASE.origins
    assert merged.methods == BASE.methods
    assert merged.headers == BASE.headers
    assert merged.expose == BASE.expose


@pytest.mark.parametrize(
    "origin",
    ["b.example", "https://", "https://b.example/path", "https://b .example", "x"],
)
def test_an_origin_that_is_not_a_valid_origin_token_is_refused(origin: str) -> None:
    merged, reason = merge_cors(BASE, {"cors_origins": [origin]})

    assert reason is not None
    assert merged == BASE


def test_a_refused_field_does_not_stop_a_valid_one_from_applying() -> None:
    merged, reason = merge_cors(
        BASE,
        {
            "cors_origins": ["https://b.example\r\n"],
            "cors_allow_methods": ["GET", "PUT"],
        },
    )

    assert reason is not None
    assert merged.origins == BASE.origins
    assert merged.methods == ("GET", "PUT")


def test_a_valid_override_still_applies_without_a_reason() -> None:
    merged, reason = merge_cors(
        BASE,
        {
            "cors_origins": ["https://b.example", "https://c.example:8443/", "null"],
            "cors_allow_methods": ["GET", "PUT"],
            "cors_allow_headers": ["*"],
            "cors_expose_headers": ["X-C"],
        },
    )

    assert reason is None
    assert merged.origins == ("https://b.example", "https://c.example:8443/", "null")
    assert merged.methods == ("GET", "PUT")
    assert merged.headers == ("*",)
    assert merged.expose == ("X-C",)


def test_a_refused_field_is_logged_once_for_the_app() -> None:
    manager = SecurityHeadersManager.isolated()
    config = SyncSecurityConfig(enable_redis=False, enable_cors=True)
    record = _override_keys(cors_allow_methods=["GET\r\nX-Evil: 1"])

    handler = _Collector()
    records = handler.records
    logger = logging.getLogger(LOGGER)
    logger.addHandler(handler)
    try:
        first = manager.cors_params_for(config, record)
        manager.cors_params_for(config, record)
    finally:
        logger.removeHandler(handler)

    assert first.methods == tuple(config.cors_allow_methods)
    refused = [r for r in records if "refused" in r.getMessage()]
    assert len(refused) == 1
    assert "\r" not in refused[0].getMessage()


@pytest.mark.parametrize(
    "field",
    [
        "cors_allow_origins",
        "cors_allow_methods",
        "cors_allow_headers",
        "cors_expose_headers",
    ],
)
def test_the_apps_own_cors_values_with_a_control_character_fail_at_config_time(
    field: str,
) -> None:
    with pytest.raises(ValueError, match="control character"):
        SecurityConfig.model_validate(
            {"enable_redis": False, field: ["https://a.example\r\nX: 1"]}
        )


@pytest.mark.parametrize("allow_methods", [["GET\r\nX-Evil: 1"], ["GET", "PO\nST"]])
def test_the_built_cors_headers_never_hold_a_cr_or_lf(
    allow_methods: list[str],
) -> None:
    manager = SecurityHeadersManager.isolated()
    manager.cors_config = {
        "origins": ["https://a.example"],
        "allow_methods": allow_methods,
        "allow_headers": ["X-A"],
    }

    with pytest.raises(ValueError, match="newline"):
        manager._build_cors_headers(
            "https://a.example", ["https://a.example"], allow_methods, ["X-A"]
        )

    assert manager.get_cors_headers("https://a.example") == {}
