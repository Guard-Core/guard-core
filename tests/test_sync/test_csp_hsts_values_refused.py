import pytest
from pydantic import ValidationError

from guard_core.models import SyncSecurityConfig
from guard_core.sync.handlers.security_headers_handler import SecurityHeadersManager


@pytest.mark.parametrize(
    "csp",
    [
        {"default-src": ["'self'\r\nX-Evil: 1"]},
        {"default-src": ["'self'; script-src *"]},
        {"bad\nname": ["x"]},
        {"default src": ["x"]},
        {"default-src": "'self'"},
        {"default-src": [1]},
    ],
)
def test_a_csp_that_could_add_a_directive_or_a_header_line_is_refused(
    csp: dict[str, object],
) -> None:
    with pytest.raises(ValidationError, match="CSP|csp"):
        SyncSecurityConfig(security_headers={"csp": csp})


@pytest.mark.parametrize("max_age", ["1\r\nX-Evil2: 2", "1", -1, True, 1.5])
def test_an_hsts_max_age_that_is_not_a_non_negative_integer_is_refused(
    max_age: object,
) -> None:
    with pytest.raises(ValidationError, match="max_age"):
        SyncSecurityConfig(security_headers={"hsts": {"max_age": max_age}})


def test_the_manager_refuses_the_same_values_through_configure() -> None:
    manager = SecurityHeadersManager.isolated()

    with pytest.raises(ValueError, match="CSP"):
        manager.configure(csp={"default-src": ["'self'\r\nX-Evil: 1"]})
    with pytest.raises(ValueError, match="max_age"):
        manager.configure(hsts_max_age=-5)


def test_a_clean_csp_and_hsts_are_built_unchanged() -> None:
    config = SyncSecurityConfig(
        security_headers={
            "csp": {"default-src": ["'self'", "https://cdn.example"], "img-src": []},
            "hsts": {"max_age": 31536000, "include_subdomains": True},
        }
    )
    headers = SecurityHeadersManager.isolated().get_headers("/x", config)

    assert headers["Content-Security-Policy"] == (
        "default-src 'self' https://cdn.example; img-src"
    )
    assert headers["Strict-Transport-Security"] == (
        "max-age=31536000; includeSubDomains"
    )
