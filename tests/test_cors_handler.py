from collections.abc import Iterator
from typing import Any

import pytest

from guard_core._security_headers_override import CorsParams, merge_cors
from guard_core.handlers._security_headers_apply import apply_security_headers_settings
from guard_core.handlers.cors_handler import (
    CorsHandler,
    is_preflight,
)
from guard_core.handlers.security_headers_handler import SecurityHeadersManager
from guard_core.models import SecurityConfig


@pytest.fixture
def cfg() -> SecurityConfig:
    return SecurityConfig(
        enable_cors=True,
        cors_allow_origins=["https://app.example.com"],
        cors_allow_methods=["GET", "POST"],
        cors_allow_headers=["X-Custom"],
        cors_allow_credentials=True,
        cors_max_age=600,
        cors_expose_headers=["X-Trace"],
    )


def test_is_preflight_true_for_options_with_acrm() -> None:
    headers = {
        "origin": "https://app.example.com",
        "access-control-request-method": "POST",
    }
    assert is_preflight("OPTIONS", headers) is True


def test_is_preflight_lowercase_options_works() -> None:
    headers = {
        "origin": "https://app.example.com",
        "access-control-request-method": "POST",
    }
    assert is_preflight("options", headers) is True


def test_is_preflight_false_for_options_without_acrm() -> None:
    assert is_preflight("OPTIONS", {"origin": "x"}) is False


def test_is_preflight_false_for_get() -> None:
    assert is_preflight("GET", {"origin": "x"}) is False


def test_is_preflight_handles_mixed_case_headers() -> None:
    headers = {
        "Origin": "https://app.example.com",
        "Access-Control-Request-Method": "POST",
    }
    assert is_preflight("OPTIONS", headers) is True


class _PairIteratingHeaders:
    # Werkzeug's EnvironHeaders iterates (name, value) pairs, unlike a Mapping.
    def __init__(self, pairs: dict[str, str]) -> None:
        self._pairs = pairs

    def keys(self) -> list[str]:
        return list(self._pairs)

    def __iter__(self) -> Iterator[tuple[str, str]]:
        return iter(self._pairs.items())


def test_is_preflight_reads_header_names_from_pair_iterating_headers() -> None:
    headers: Any = _PairIteratingHeaders({"Access-Control-Request-Method": "POST"})
    assert is_preflight("OPTIONS", headers) is True


def test_preflight_response_allowed_origin(cfg: SecurityConfig) -> None:
    handler = CorsHandler(cfg)
    response = handler.build_preflight_response(
        request_headers={
            "origin": "https://app.example.com",
            "access-control-request-method": "POST",
            "access-control-request-headers": "X-Custom",
        }
    )
    assert response.status_code == 200
    assert response.headers["Access-Control-Allow-Origin"] == "https://app.example.com"
    assert response.headers["Access-Control-Allow-Credentials"] == "true"
    assert "POST" in response.headers["Access-Control-Allow-Methods"]
    assert response.headers["Access-Control-Max-Age"] == "600"
    assert response.headers["Vary"] == "Origin"


def test_preflight_response_disallowed_origin(cfg: SecurityConfig) -> None:
    handler = CorsHandler(cfg)
    response = handler.build_preflight_response(
        request_headers={
            "origin": "https://attacker.example.com",
            "access-control-request-method": "POST",
        }
    )
    assert response.status_code == 400
    assert "origin" in response.body.lower()


def test_preflight_response_disallowed_method(cfg: SecurityConfig) -> None:
    handler = CorsHandler(cfg)
    response = handler.build_preflight_response(
        request_headers={
            "origin": "https://app.example.com",
            "access-control-request-method": "DELETE",
        }
    )
    assert response.status_code == 400
    assert "method" in response.body.lower()


def test_preflight_response_disallowed_headers(cfg: SecurityConfig) -> None:
    handler = CorsHandler(cfg)
    response = handler.build_preflight_response(
        request_headers={
            "origin": "https://app.example.com",
            "access-control-request-method": "POST",
            "access-control-request-headers": "X-Forbidden",
        }
    )
    assert response.status_code == 400
    assert "headers" in response.body.lower()


def test_response_headers_for_simple_request(cfg: SecurityConfig) -> None:
    handler = CorsHandler(cfg)
    headers = handler.build_response_headers(
        request_headers={"origin": "https://app.example.com"}
    )
    assert headers["Access-Control-Allow-Origin"] == "https://app.example.com"
    assert headers["Access-Control-Allow-Credentials"] == "true"
    assert headers["Access-Control-Expose-Headers"] == "X-Trace"
    assert headers["Vary"] == "Origin"


def test_response_headers_for_disallowed_origin(cfg: SecurityConfig) -> None:
    handler = CorsHandler(cfg)
    headers = handler.build_response_headers(
        request_headers={"origin": "https://attacker.example.com"}
    )
    assert headers == {"Vary": "Origin"}


def test_response_headers_with_no_origin_return_only_vary(cfg: SecurityConfig) -> None:
    handler = CorsHandler(cfg)
    headers = handler.build_response_headers(request_headers={})
    assert headers == {"Vary": "Origin"}


def test_wildcard_origin_with_credentials_raises_at_init() -> None:
    bad = SecurityConfig.model_construct(
        enable_cors=True,
        cors_allow_origins=["*"],
        cors_allow_credentials=True,
    )
    with pytest.raises(ValueError, match="wildcard origin"):
        CorsHandler(bad)


def test_wildcard_origin_without_credentials() -> None:
    cfg = SecurityConfig(
        enable_cors=True,
        cors_allow_origins=["*"],
        cors_allow_credentials=False,
        cors_allow_methods=["GET"],
    )
    handler = CorsHandler(cfg)
    headers = handler.build_response_headers(
        request_headers={"origin": "https://random.example.com"}
    )
    assert headers["Access-Control-Allow-Origin"] == "*"


def test_allow_all_headers_mirrors_requested(cfg: SecurityConfig) -> None:
    cfg2 = SecurityConfig(
        enable_cors=True,
        cors_allow_origins=["https://app.example.com"],
        cors_allow_methods=["GET", "POST"],
        cors_allow_headers=["*"],
        cors_allow_credentials=True,
    )
    handler = CorsHandler(cfg2)
    response = handler.build_preflight_response(
        request_headers={
            "origin": "https://app.example.com",
            "access-control-request-method": "POST",
            "access-control-request-headers": "X-Anything, Y-Other",
        }
    )
    assert response.status_code == 200
    assert response.headers["Access-Control-Allow-Headers"] == "X-Anything, Y-Other"


def test_disabled_cors_handler_skips_logic() -> None:
    cfg = SecurityConfig(enable_cors=False)
    handler = CorsHandler(cfg)
    headers = handler.build_response_headers(request_headers={"origin": "https://x"})
    assert headers == {}


def test_is_origin_allowed_false_when_disabled() -> None:
    cfg = SecurityConfig(enable_cors=False)
    handler = CorsHandler(cfg)
    assert handler.is_origin_allowed("https://example.com") is False


def test_is_origin_allowed_true_for_wildcard() -> None:
    cfg = SecurityConfig(
        enable_cors=True,
        cors_allow_origins=["*"],
        cors_allow_credentials=False,
        cors_allow_methods=["GET"],
    )
    handler = CorsHandler(cfg)
    assert handler.is_origin_allowed("https://any.example.com") is True


def test_preflight_allow_all_headers_empty_requested_headers_raw() -> None:
    cfg2 = SecurityConfig(
        enable_cors=True,
        cors_allow_origins=["https://app.example.com"],
        cors_allow_methods=["GET", "POST"],
        cors_allow_headers=["*"],
        cors_allow_credentials=True,
    )
    handler = CorsHandler(cfg2)
    response = handler.build_preflight_response(
        request_headers={
            "origin": "https://app.example.com",
            "access-control-request-method": "POST",
        }
    )
    assert response.status_code == 200
    assert "Access-Control-Allow-Headers" not in response.headers


def test_preflight_no_credentials_flag() -> None:
    cfg2 = SecurityConfig(
        enable_cors=True,
        cors_allow_origins=["https://app.example.com"],
        cors_allow_methods=["GET", "POST"],
        cors_allow_credentials=False,
    )
    handler = CorsHandler(cfg2)
    response = handler.build_preflight_response(
        request_headers={
            "origin": "https://app.example.com",
            "access-control-request-method": "GET",
        }
    )
    assert response.status_code == 200
    assert "Access-Control-Allow-Credentials" not in response.headers


def test_a_handler_for_an_app_without_cors_holds_the_disabled_defaults() -> None:
    handler = CorsHandler(SecurityConfig(enable_redis=False))

    assert handler._enabled is False
    assert handler._allow_all is False
    assert handler._allow_origins == set()
    assert handler._allow_methods == []
    assert handler._allow_headers == []
    assert handler._allow_all_headers is False
    assert handler._allow_credentials is False
    assert handler._max_age == 600
    assert handler._expose_headers == []


WILDCARD_PROBLEM = (
    "CORS misconfiguration: wildcard origin '*' is incompatible "
    "with cors_allow_credentials=True"
)
TRUE_NOTE = "Set fail_on_misconfiguration=False to start with it anyway."
FALSE_NOTE = "fail_on_misconfiguration=False keeps starting with it."


def _wildcard_with_credentials_config(
    fail_on_misconfiguration: bool | None = None,
) -> SecurityConfig:
    if fail_on_misconfiguration is None:
        return SecurityConfig(
            enable_redis=False,
            enable_cors=True,
            cors_allow_origins=["*"],
            cors_allow_credentials=True,
        )
    return SecurityConfig(
        enable_redis=False,
        enable_cors=True,
        cors_allow_origins=["*"],
        cors_allow_credentials=True,
        fail_on_misconfiguration=fail_on_misconfiguration,
    )


@pytest.mark.parametrize("flag", [None, True])
def test_a_wildcard_with_credentials_config_is_refused_at_construction(
    flag: bool | None,
) -> None:
    with pytest.raises(ValueError) as error:
        _wildcard_with_credentials_config(flag)

    assert f"{WILDCARD_PROBLEM} {TRUE_NOTE}" in str(error.value)


def test_a_wildcard_with_credentials_is_no_problem_while_cors_is_off() -> None:
    SecurityConfig(
        enable_redis=False,
        cors_allow_origins=["*"],
        cors_allow_credentials=True,
        fail_on_misconfiguration=True,
    )


def test_the_wildcard_with_credentials_error_names_both_settings() -> None:
    bad = SecurityConfig.model_construct(
        enable_cors=True, cors_allow_origins=["*"], cors_allow_credentials=True
    )

    with pytest.raises(
        ValueError,
        match=r"^CORS misconfiguration: wildcard origin '\*' is incompatible "
        r"with cors_allow_credentials=True "
        r"Set fail_on_misconfiguration=False to start with it anyway\.$",
    ):
        CorsHandler(bad)


def test_a_wildcard_with_credentials_warns_once_and_drops_credentials(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level("WARNING", logger="guard_core.models"):
        config = _wildcard_with_credentials_config(False)
    assert [
        r.getMessage() for r in caplog.records if WILDCARD_PROBLEM in r.getMessage()
    ] == [f"{WILDCARD_PROBLEM} {FALSE_NOTE}"]

    manager = SecurityHeadersManager.isolated()
    apply_security_headers_settings(manager, config)
    assert manager.cors_config is not None
    assert manager.cors_config["allow_credentials"] is False


def test_a_wildcard_with_credentials_handler_serves_without_credentials() -> None:
    config = _wildcard_with_credentials_config(False)

    handler = CorsHandler(config)
    response = handler.build_preflight_response(
        {"origin": "https://a.example", "access-control-request-method": "GET"}
    )

    assert handler._allow_credentials is False
    assert response.status_code == 200
    assert "Access-Control-Allow-Credentials" not in response.headers


def test_a_runtime_override_of_wildcard_with_credentials_is_still_refused() -> None:
    base = CorsParams(
        enabled=True,
        origins=("https://a.example",),
        credentials=False,
        methods=("GET",),
        headers=(),
        max_age=600,
        expose=(),
    )

    merged, refused = merge_cors(
        base, {"cors_origins": ["*"], "cors_allow_credentials": True}
    )

    assert merged == base
    assert refused is not None
    assert "wildcard origin cannot be combined with credentials" in refused


def test_a_trailing_slash_is_stripped_from_an_origin_and_nothing_else() -> None:
    handler = CorsHandler(
        SecurityConfig(enable_cors=True, cors_allow_origins=["https://boX/"])
    )

    assert handler.is_origin_allowed("https://boX")
    assert not handler.is_origin_allowed("https://bo")


def test_an_empty_methods_list_allows_get_only() -> None:
    handler = CorsHandler(
        SecurityConfig(
            enable_cors=True,
            cors_allow_origins=["https://a.example"],
            cors_allow_methods=[],
        )
    )

    assert handler._allow_methods == ["GET"]


def test_a_wildcard_preflight_answers_a_star_origin() -> None:
    handler = CorsHandler(
        SecurityConfig(
            enable_cors=True,
            cors_allow_origins=["*"],
            cors_allow_credentials=False,
            cors_allow_methods=["GET"],
        )
    )

    response = handler.build_preflight_response(
        {"origin": "https://x.example", "access-control-request-method": "GET"}
    )

    assert response.headers["Access-Control-Allow-Origin"] == "*"


def test_the_override_is_applied_once_until_its_record_changes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    handler = CorsHandler(SecurityConfig(enable_redis=False))
    calls: list[object] = []
    original = handler._apply

    def recording_apply(params: CorsParams) -> None:
        calls.append(params)
        original(params)

    monkeypatch.setattr(handler, "_apply", recording_apply)

    handler.is_enabled()
    handler.is_enabled()
    handler.is_origin_allowed("https://a.example")

    assert len(calls) == 1
