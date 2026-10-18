import threading
from collections.abc import Generator

import pytest

from guard_core.sync.handlers.security_headers_handler import (
    SecurityHeadersManager,
    reset_global_state,
)


@pytest.fixture(autouse=True)
def cleanup() -> Generator[None]:
    reset_global_state()
    yield
    reset_global_state()


def test_header_value_with_newline_rejected() -> None:
    manager = SecurityHeadersManager()

    with pytest.raises(ValueError, match="Invalid header value contains newline"):
        manager.configure(custom_headers={"X-Custom": "value\r\nX-Injected: evil"})

    with pytest.raises(ValueError, match="Invalid header value contains newline"):
        manager.configure(custom_headers={"X-Custom": "value\nX-Injected: evil"})


def test_header_name_with_newline_rejected() -> None:
    manager = SecurityHeadersManager()

    with pytest.raises(ValueError, match="Invalid header name"):
        manager.configure(custom_headers={"X-Evil\r\nSet-Cookie: x=1": "1"})


def test_header_name_token_characters_accepted() -> None:
    manager = SecurityHeadersManager()

    manager.configure(
        custom_headers={
            "X-Custom-Header123": "value",
            "X!#$%&'*+.^_`|~-Y": "value",
        }
    )

    headers = manager.get_headers()
    assert headers["X-Custom-Header123"] == "value"
    assert headers["X!#$%&'*+.^_`|~-Y"] == "value"


def test_header_value_too_long_rejected() -> None:
    manager = SecurityHeadersManager()

    long_value = "x" * 8193

    with pytest.raises(ValueError, match="Header value too long"):
        manager.configure(custom_headers={"X-Custom": long_value})


def test_control_characters_sanitized() -> None:
    manager = SecurityHeadersManager()

    value_with_controls = "normal\x00\x01\x02\ttext\x1f"
    manager.configure(custom_headers={"X-Custom": value_with_controls})

    headers = manager.get_headers()
    assert headers["X-Custom"] == "normal\ttext"


def test_standard_headers_validated() -> None:
    manager = SecurityHeadersManager()

    with pytest.raises(ValueError, match="Invalid header value contains newline"):
        manager.configure(frame_options="DENY\r\nX-Evil: true")

    with pytest.raises(ValueError, match="Invalid header value contains newline"):
        manager.configure(referrer_policy="no-referrer\nX-Evil: true")


def test_singleton_thread_safety() -> None:
    instances = []
    barrier = threading.Barrier(10)

    def create_instance() -> None:
        barrier.wait()
        instance = SecurityHeadersManager()
        instances.append(instance)

    threads = []
    for _ in range(10):
        thread = threading.Thread(target=create_instance)
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    assert len(set(id(inst) for inst in instances)) == 1
    assert all(inst is instances[0] for inst in instances)


def test_singleton_initialization_once() -> None:
    reset_global_state()

    inst1 = SecurityHeadersManager()
    inst2 = SecurityHeadersManager()
    inst3 = SecurityHeadersManager()

    assert inst1 is inst2 is inst3
    assert id(inst1) == id(inst2) == id(inst3)


def test_cache_key_uses_hashing() -> None:
    manager = SecurityHeadersManager()

    test_paths = [
        "/api/users",
        "/API/USERS",
        "/api/users/",
        "api/users",
    ]

    keys = []
    for path in test_paths:
        key = manager._generate_cache_key(path)
        keys.append(key)
        assert key.startswith("path_")
        assert len(key) == 21
        assert all(c in "0123456789abcdef" for c in key[5:])

    assert keys[0] == keys[1] == keys[2] == keys[3]


def test_cache_key_collision_resistance() -> None:
    manager = SecurityHeadersManager()

    paths = [
        "/api/users/1",
        "/api/users/2",
        "/api/user/s1",
        "/api/use/rs1",
    ]

    keys = [manager._generate_cache_key(path) for path in paths]

    assert len(set(keys)) == len(keys)


def test_cache_key_default_path() -> None:
    manager = SecurityHeadersManager()

    assert manager._generate_cache_key(None) == "default"
    assert manager._generate_cache_key("") == "default"


def test_hsts_preload_requires_long_max_age(
    caplog: pytest.LogCaptureFixture,
) -> None:
    manager = SecurityHeadersManager()

    manager.configure(
        hsts_max_age=86400,
        hsts_preload=True,
        hsts_include_subdomains=True,
    )

    assert manager.hsts_config is not None
    assert manager.hsts_config["preload"] is False
    assert "HSTS preload requires max_age >= 31536000" in caplog.text


def test_hsts_preload_requires_include_subdomains(
    caplog: pytest.LogCaptureFixture,
) -> None:
    manager = SecurityHeadersManager()

    manager.configure(
        hsts_max_age=31536000,
        hsts_preload=True,
        hsts_include_subdomains=False,
    )

    assert manager.hsts_config is not None
    assert manager.hsts_config["include_subdomains"] is True
    assert "HSTS preload requires includeSubDomains" in caplog.text


def test_hsts_valid_preload_configuration(
    caplog: pytest.LogCaptureFixture,
) -> None:
    manager = SecurityHeadersManager()

    manager.configure(
        hsts_max_age=31536000,
        hsts_preload=True,
        hsts_include_subdomains=True,
    )

    assert manager.hsts_config is not None
    assert manager.hsts_config["preload"] is True
    assert manager.hsts_config["include_subdomains"] is True
    assert manager.hsts_config["max_age"] == 31536000

    assert "HSTS preload requires" not in caplog.text


def test_reconfigure_without_hsts_clears_the_stale_header() -> None:
    manager = SecurityHeadersManager()

    manager.configure(hsts_max_age=31536000)
    headers = manager.get_headers("/hsts-reconfigure")
    assert "Strict-Transport-Security" in headers

    manager.configure()
    headers = manager.get_headers("/hsts-reconfigure")

    assert manager.hsts_config is None
    assert "Strict-Transport-Security" not in headers


def test_reconfigure_with_no_overrides_clears_every_prior_group() -> None:
    manager = SecurityHeadersManager()

    manager.configure(
        csp={"default-src": ["'self'"]},
        hsts_max_age=31536000,
        frame_options="DENY",
        content_type_options="custom-value",
        xss_protection="0",
        referrer_policy="no-referrer",
        permissions_policy="geolocation=(self)",
        custom_headers={"X-Stale": "leftover"},
        cors_origins=["https://old.example.com"],
    )

    manager.configure()
    headers = manager.get_headers("/reconfigure-clean")
    cors_headers = manager.get_cors_headers("https://old.example.com")

    assert manager.csp_config is None
    assert manager.hsts_config is None
    assert manager.cors_config is None
    assert manager.custom_headers == {}
    assert "Content-Security-Policy" not in headers
    assert "Strict-Transport-Security" not in headers
    assert "X-Stale" not in headers
    assert cors_headers == {}

    assert headers["X-Frame-Options"] == "SAMEORIGIN"
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert headers["X-XSS-Protection"] == "0"
    assert headers["Referrer-Policy"] == "strict-origin-when-cross-origin"
    assert headers["Permissions-Policy"] == "geolocation=(), microphone=(), camera=()"


def test_reconfigure_invalidates_the_headers_cache() -> None:
    manager = SecurityHeadersManager()

    manager.configure(hsts_max_age=31536000)
    cached_first = manager.get_headers("/cached-path")
    assert "Strict-Transport-Security" in cached_first

    manager.configure()
    cached_second = manager.get_headers("/cached-path")

    assert "Strict-Transport-Security" not in cached_second


def test_permissions_policy_explicit_none_clears_header_but_unset_resets_it() -> None:
    manager = SecurityHeadersManager()

    manager.configure(permissions_policy="geolocation=(self)")
    headers = manager.get_headers("/pp-explicit-clear")
    assert headers["Permissions-Policy"] == "geolocation=(self)"

    manager.configure(permissions_policy=None)
    headers = manager.get_headers("/pp-explicit-clear")
    assert "Permissions-Policy" not in headers

    manager.configure(permissions_policy="geolocation=(self)")
    manager.configure()
    headers = manager.get_headers("/pp-explicit-clear")
    assert headers["Permissions-Policy"] == "geolocation=(), microphone=(), camera=()"
