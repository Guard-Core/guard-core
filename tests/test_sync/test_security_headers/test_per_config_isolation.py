from unittest.mock import MagicMock

from guard_core.models import SecurityConfig
from guard_core.sync.core.events.metrics import MetricsCollector
from guard_core.sync.core.responses.context import ResponseContext
from guard_core.sync.core.responses.factory import ErrorResponseFactory
from guard_core.sync.handlers.security_headers_handler import security_headers_manager
from tests.test_sync.conftest import MockGuardResponse, MockGuardResponseFactory


def _make_config(csp: dict[str, list[str]]) -> SecurityConfig:
    return SecurityConfig(
        enable_redis=False,
        security_headers={"enabled": True, "csp": csp},
    )


def _make_factory(config: SecurityConfig) -> ErrorResponseFactory:
    metrics = MagicMock(spec=MetricsCollector)
    metrics.collect_request_metrics = MagicMock()
    ctx = ResponseContext(
        config=config,
        logger=MagicMock(),
        metrics_collector=metrics,
        response_factory=MockGuardResponseFactory(),
    )
    return ErrorResponseFactory(ctx)


def test_get_headers_with_explicit_configs_stay_isolated() -> None:
    csp_a = {"default-src": ["'self'"]}
    csp_b = {"default-src": ["'none'"], "script-src": ["'none'"]}
    config_a = _make_config(csp_a)
    config_b = _make_config(csp_b)

    security_headers_manager.configure(enabled=True, csp=csp_a)
    headers_a = security_headers_manager.get_headers("/a", config=config_a)

    security_headers_manager.configure(enabled=True, csp=csp_b)
    headers_b = security_headers_manager.get_headers("/b", config=config_b)

    headers_a_again = security_headers_manager.get_headers("/a", config=config_a)

    assert headers_a["Content-Security-Policy"] == "default-src 'self'"
    assert (
        headers_b["Content-Security-Policy"] == "default-src 'none'; script-src 'none'"
    )
    assert headers_a_again["Content-Security-Policy"] == "default-src 'self'"


def test_response_factory_headers_survive_a_later_middleware_reconfiguring() -> None:
    csp_a = {"default-src": ["'self'"]}
    csp_b = {"default-src": ["'none'"], "script-src": ["'none'"]}
    config_a = _make_config(csp_a)
    config_b = _make_config(csp_b)

    security_headers_manager.configure(enabled=True, csp=csp_a)
    factory_a = _make_factory(config_a)

    response_a_before = factory_a.apply_security_headers(
        MockGuardResponse("ok", 200), "/a"
    )
    assert response_a_before.headers["Content-Security-Policy"] == "default-src 'self'"

    security_headers_manager.configure(enabled=True, csp=csp_b)
    factory_b = _make_factory(config_b)
    response_b = factory_b.apply_security_headers(MockGuardResponse("ok", 200), "/b")
    assert (
        response_b.headers["Content-Security-Policy"]
        == "default-src 'none'; script-src 'none'"
    )

    response_a_after = factory_a.apply_security_headers(
        MockGuardResponse("ok", 200), "/a"
    )
    assert (
        response_a_after.headers["Content-Security-Policy"] == "default-src 'self'"
    ), "middleware A now serves middleware B's CSP after B reconfigured the singleton"


def test_get_headers_with_config_disabled_returns_empty() -> None:
    config = SecurityConfig(enable_redis=False, security_headers={"enabled": False})

    headers = security_headers_manager.get_headers("/off", config=config)
    assert headers == {}


def test_get_headers_without_config_uses_most_recently_configured_state() -> None:
    security_headers_manager.configure(enabled=True, csp={"default-src": ["'self'"]})
    security_headers_manager.configure(enabled=True, csp={"default-src": ["'none'"]})

    headers = security_headers_manager.get_headers("/legacy")
    assert headers["Content-Security-Policy"] == "default-src 'none'"


def test_get_cors_headers_with_explicit_configs_stay_isolated() -> None:
    config_a = SecurityConfig(
        enable_redis=False,
        security_headers={"enabled": True},
        enable_cors=True,
        cors_allow_origins=["https://a.example.com"],
    )
    config_b = SecurityConfig(
        enable_redis=False,
        security_headers={"enabled": True},
        enable_cors=True,
        cors_allow_origins=["https://b.example.com"],
    )

    cors_a = security_headers_manager.get_cors_headers(
        "https://a.example.com", config=config_a
    )
    cors_b = security_headers_manager.get_cors_headers(
        "https://b.example.com", config=config_b
    )
    cors_a_rejects_b_origin = security_headers_manager.get_cors_headers(
        "https://b.example.com", config=config_a
    )

    assert cors_a["Access-Control-Allow-Origin"] == "https://a.example.com"
    assert cors_b["Access-Control-Allow-Origin"] == "https://b.example.com"
    assert cors_a_rejects_b_origin == {}
