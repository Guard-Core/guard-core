import logging
from unittest.mock import Mock

import pytest

from guard_core._security_headers_override import PULLED_OVERRIDES, OverrideRecord
from guard_core.models import SyncSecurityConfig
from guard_core.sync.handlers.security_headers_handler import SecurityHeadersManager

LOGGER = "guard_core.sync.handlers.security_headers"
NO_OVERRIDE = OverrideRecord(set_at=0.0, keys={})


@pytest.fixture
def manager() -> SecurityHeadersManager:
    return SecurityHeadersManager.isolated()


def _messages(caplog: pytest.LogCaptureFixture) -> list[str]:
    return [r.getMessage() for r in caplog.records]


@pytest.mark.parametrize("name", ["X-Custom", "a", "A1", "x!#$%&'*+.^_`|~-y"])
def test_a_token_header_name_is_accepted_as_is(
    manager: SecurityHeadersManager, name: str
) -> None:
    assert manager._validate_header_name(name) == name


@pytest.mark.parametrize(
    "name", ["", "X Custom", "X-Custom ", " X", "X:Y", "X\nY", "é"]
)
def test_a_non_token_header_name_is_rejected(
    manager: SecurityHeadersManager, name: str
) -> None:
    with pytest.raises(ValueError, match="^Invalid header name: "):
        manager._validate_header_name(name)


def test_a_newline_in_a_header_value_is_rejected_with_the_value(
    manager: SecurityHeadersManager,
) -> None:
    with pytest.raises(ValueError) as exc:
        manager._validate_header_value("a\nb")
    assert str(exc.value) == "Invalid header value contains newline: a\nb"
    with pytest.raises(ValueError) as exc:
        manager._validate_header_value("a\rb")
    assert str(exc.value) == "Invalid header value contains newline: a\rb"


def test_the_header_value_length_limit_is_8192(
    manager: SecurityHeadersManager,
) -> None:
    assert manager._validate_header_value("a" * 8192) == "a" * 8192
    with pytest.raises(ValueError) as exc:
        manager._validate_header_value("a" * 8193)
    assert str(exc.value) == "Header value too long: 8193 bytes"


def test_control_characters_are_stripped_but_tab_and_space_stay(
    manager: SecurityHeadersManager,
) -> None:
    assert manager._validate_header_value("a\tb c\x00d\x1fe\x7ff") == "a\tb cde\x7ff"


def test_an_empty_csp_is_no_csp(manager: SecurityHeadersManager) -> None:
    assert manager._compute_csp_config(None) is None
    assert manager._compute_csp_config({}) is None


def test_a_csp_with_unsafe_sources_warns_per_directive_and_is_kept(
    manager: SecurityHeadersManager, caplog: pytest.LogCaptureFixture
) -> None:
    csp = {
        "script-src": ["'self'", "'unsafe-inline'"],
        "style-src": ["'unsafe-eval'"],
        "img-src": ["'self'"],
    }

    with caplog.at_level(logging.WARNING, logger=LOGGER):
        result = manager._compute_csp_config(csp)

    assert result is csp
    assert _messages(caplog) == [
        "CSP directive 'script-src' contains unsafe sources",
        "CSP directive 'style-src' contains unsafe sources",
    ]


def test_configure_csp_stores_the_computed_csp(
    manager: SecurityHeadersManager,
) -> None:
    manager._configure_csp({"default-src": ["'self'"]})

    assert manager.csp_config == {"default-src": ["'self'"]}


def test_no_hsts_max_age_means_no_hsts(manager: SecurityHeadersManager) -> None:
    assert manager._compute_hsts_config(None, True, True) is None


def test_hsts_is_returned_as_given_without_preload(
    manager: SecurityHeadersManager, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.WARNING, logger=LOGGER):
        result = manager._compute_hsts_config(10, False, False)

    assert result == {"max_age": 10, "include_subdomains": False, "preload": False}
    assert _messages(caplog) == []


def test_hsts_preload_below_a_year_is_dropped_with_a_warning(
    manager: SecurityHeadersManager, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.WARNING, logger=LOGGER):
        result = manager._compute_hsts_config(31535999, True, True)

    assert result == {
        "max_age": 31535999,
        "include_subdomains": True,
        "preload": False,
    }
    assert _messages(caplog) == ["HSTS preload requires max_age >= 31536000"]


def test_hsts_preload_at_exactly_a_year_is_kept(
    manager: SecurityHeadersManager, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.WARNING, logger=LOGGER):
        result = manager._compute_hsts_config(31536000, True, True)

    assert result == {
        "max_age": 31536000,
        "include_subdomains": True,
        "preload": True,
    }
    assert _messages(caplog) == []


def test_hsts_preload_forces_include_subdomains_with_a_warning(
    manager: SecurityHeadersManager, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.WARNING, logger=LOGGER):
        result = manager._compute_hsts_config(31536000, False, True)

    assert result == {
        "max_age": 31536000,
        "include_subdomains": True,
        "preload": True,
    }
    assert _messages(caplog) == ["HSTS preload requires includeSubDomains"]


def test_configure_hsts_stores_the_computed_hsts(
    manager: SecurityHeadersManager,
) -> None:
    manager._configure_hsts(60, False, False)

    assert manager.hsts_config == {
        "max_age": 60,
        "include_subdomains": False,
        "preload": False,
    }


@pytest.mark.parametrize("origins", [None, []])
def test_no_cors_origins_means_no_cors(
    manager: SecurityHeadersManager, origins: list[str] | None
) -> None:
    assert manager._compute_cors_config(origins, True, ["GET"], ["X"], 5) is None


def test_cors_defaults_fill_in_methods_headers_and_max_age(
    manager: SecurityHeadersManager,
) -> None:
    assert manager._compute_cors_config(["https://a.example/"], False, None, None) == {
        "origins": ["https://a.example"],
        "allow_credentials": False,
        "allow_methods": ["GET", "POST"],
        "allow_headers": ["*"],
        "max_age": 3600,
    }


def test_cors_empty_methods_fall_back_but_empty_headers_stay_empty(
    manager: SecurityHeadersManager,
) -> None:
    result = manager._compute_cors_config(["https://a.example"], True, [], [], 0)

    assert result == {
        "origins": ["https://a.example"],
        "allow_credentials": True,
        "allow_methods": ["GET", "POST"],
        "allow_headers": [],
        "max_age": 0,
    }


def test_cors_explicit_values_are_kept_and_headers_are_copied(
    manager: SecurityHeadersManager,
) -> None:
    headers = ["X-One", "X-Two"]

    result = manager._compute_cors_config(
        ["https://a.example//", "https://b.example"], True, ["PUT"], headers, 99
    )

    assert result is not None
    assert result["origins"] == ["https://a.example", "https://b.example"]
    assert result["allow_methods"] == ["PUT"]
    assert result["allow_headers"] == headers
    assert result["allow_headers"] is not headers
    assert result["max_age"] == 99


def test_a_wildcard_origin_loses_credentials_and_logs_the_error(
    manager: SecurityHeadersManager, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.ERROR, logger=LOGGER):
        result = manager._compute_cors_config(["*"], True, None, None)

    assert result is not None
    assert result["allow_credentials"] is False
    assert result["origins"] == ["*"]
    assert _messages(caplog) == [
        "CORS config error: Wildcard origin disallowed with credentials"
    ]


def test_a_wildcard_origin_without_credentials_logs_nothing(
    manager: SecurityHeadersManager, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.ERROR, logger=LOGGER):
        manager._compute_cors_config(["*"], False, None, None)
        manager._compute_cors_config(["https://a.example"], True, None, None)

    assert _messages(caplog) == []


def test_configure_cors_stores_the_computed_cors_with_its_max_age(
    manager: SecurityHeadersManager,
) -> None:
    manager._configure_cors(["https://a.example"], False, ["GET"], ["X"], 17)

    assert manager.cors_config is not None
    assert manager.cors_config["max_age"] == 17


def test_default_headers_without_overrides_are_the_class_defaults(
    manager: SecurityHeadersManager,
) -> None:
    result = manager._compute_default_headers(None, None, None, None, "UNSET")

    assert result == SecurityHeadersManager.default_headers
    assert result is not SecurityHeadersManager.default_headers


def test_each_default_header_override_replaces_only_its_header(
    manager: SecurityHeadersManager,
) -> None:
    result = manager._compute_default_headers("DENY", "x1", "1", "no-referrer", "x2")

    assert result["X-Frame-Options"] == "DENY"
    assert result["X-Content-Type-Options"] == "x1"
    assert result["X-XSS-Protection"] == "1"
    assert result["Referrer-Policy"] == "no-referrer"
    assert result["Permissions-Policy"] == "x2"
    assert result["X-Download-Options"] == "noopen"
    assert result["Cross-Origin-Opener-Policy"] == "same-origin"


def test_an_empty_string_override_is_kept_not_reset(
    manager: SecurityHeadersManager,
) -> None:
    result = manager._compute_default_headers("", "", "", "", "UNSET")

    assert result["X-Frame-Options"] == ""
    assert result["Referrer-Policy"] == ""


@pytest.mark.parametrize("policy", [None, ""])
def test_a_falsy_permissions_policy_removes_the_header(
    manager: SecurityHeadersManager, policy: str | None
) -> None:
    result = manager._compute_default_headers(None, None, None, None, policy)

    assert "Permissions-Policy" not in result


def test_a_default_header_override_is_validated(
    manager: SecurityHeadersManager,
) -> None:
    with pytest.raises(ValueError, match="^Invalid header value contains newline"):
        manager._compute_default_headers("a\nb", None, None, None, "UNSET")
    with pytest.raises(ValueError, match="^Invalid header value contains newline"):
        manager._compute_default_headers(None, None, None, None, "a\nb")


def test_update_default_headers_stores_the_computed_headers(
    manager: SecurityHeadersManager,
) -> None:
    manager._update_default_headers("DENY", None, None, None, "UNSET")

    assert manager.default_headers["X-Frame-Options"] == "DENY"


def test_custom_headers_are_validated_and_empty_means_none(
    manager: SecurityHeadersManager,
) -> None:
    assert manager._compute_custom_headers(None) == {}
    assert manager._compute_custom_headers({}) == {}
    assert manager._compute_custom_headers({"X-A": "1\x00"}) == {"X-A": "1"}
    with pytest.raises(ValueError, match="^Invalid header name: "):
        manager._compute_custom_headers({"bad name": "1"})
    manager._add_custom_headers({"X-A": "1"})
    assert manager.custom_headers == {"X-A": "1"}


def test_resolving_headers_without_a_config_returns_the_current_state(
    manager: SecurityHeadersManager,
) -> None:
    manager.csp_config = {"default-src": ["'self'"]}
    manager.hsts_config = {"max_age": 1}
    manager.custom_headers = {"X-A": "1"}

    csp, hsts, defaults, custom = manager._resolve_headers_state(None)

    assert csp == {"default-src": ["'self'"]}
    assert hsts == {"max_age": 1}
    assert defaults is manager.default_headers
    assert custom == {"X-A": "1"}


def test_resolving_headers_from_a_config_builds_every_part(
    manager: SecurityHeadersManager,
) -> None:
    config = SyncSecurityConfig(
        enable_redis=False,
        security_headers={
            "csp": {"default-src": ["'self'"]},
            "hsts": {"max_age": 100, "include_subdomains": False},
            "frame_options": "DENY",
            "custom": {"X-A": "1"},
        },
    )

    csp, hsts, defaults, custom = manager._resolve_headers_state(config, NO_OVERRIDE)

    assert csp == {"default-src": ["'self'"]}
    assert hsts == {"max_age": 100, "include_subdomains": False, "preload": False}
    assert defaults["X-Frame-Options"] == "DENY"
    assert defaults["X-Content-Type-Options"] == "nosniff"
    assert custom == {"X-A": "1"}


def test_hsts_include_subdomains_defaults_on_when_the_config_omits_it(
    manager: SecurityHeadersManager,
) -> None:
    config = SyncSecurityConfig(enable_redis=False, security_headers={"enabled": True})

    _, hsts, _, _ = manager._resolve_headers_state(config, NO_OVERRIDE)

    assert hsts == {"max_age": 31536000, "include_subdomains": True, "preload": False}


def test_a_disabled_config_without_override_resolves_to_nothing(
    manager: SecurityHeadersManager,
) -> None:
    config = SyncSecurityConfig(enable_redis=False, security_headers={"enabled": False})

    csp, hsts, defaults, custom = manager._resolve_headers_state(config, NO_OVERRIDE)

    assert (csp, hsts, defaults, custom) == (None, None, {}, {})


def test_an_enabling_override_on_a_disabled_config_restores_the_defaults(
    manager: SecurityHeadersManager,
) -> None:
    config = SyncSecurityConfig(enable_redis=False, security_headers=None)
    override = OverrideRecord(set_at=0.0, keys={"enabled": True})

    _, hsts, defaults, _ = manager._resolve_headers_state(config, override)

    assert hsts == {"max_age": 31536000, "include_subdomains": True, "preload": False}
    assert defaults["X-Frame-Options"] == "SAMEORIGIN"


def test_configured_headers_skip_unset_values_and_an_empty_permissions_policy(
    manager: SecurityHeadersManager,
) -> None:
    result = manager._compute_configured_headers(
        {
            "frame_options": "DENY",
            "content_type_options": None,
            "permissions_policy": "",
            "referrer_policy": "",
            "download_options": "x\x00y",
        }
    )

    assert result == {
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "",
        "X-Download-Options": "xy",
    }


def _cors_config(enable_cors: bool = True) -> SyncSecurityConfig:
    return SyncSecurityConfig(
        enable_redis=False,
        enable_cors=enable_cors,
        cors_allow_origins=["https://a.example/"],
        cors_allow_credentials=True,
        cors_allow_methods=["PUT"],
        cors_allow_headers=["X-One"],
        cors_max_age=42,
    )


def test_resolving_cors_without_a_config_returns_the_current_cors(
    manager: SecurityHeadersManager,
) -> None:
    manager.cors_config = {"origins": ["x"]}

    assert manager._resolve_cors_state(None) == {"origins": ["x"]}


def test_resolving_cors_with_no_override_uses_the_apps_own_cors(
    manager: SecurityHeadersManager,
) -> None:
    result = manager._resolve_cors_state(_cors_config(), NO_OVERRIDE)

    assert result == {
        "origins": ["https://a.example"],
        "allow_credentials": True,
        "allow_methods": ["PUT"],
        "allow_headers": ["X-One"],
        "max_age": 42,
    }


def test_resolving_cors_with_cors_disabled_gives_none(
    manager: SecurityHeadersManager,
) -> None:
    assert (
        manager._resolve_cors_state(_cors_config(enable_cors=False), NO_OVERRIDE)
        is None
    )


def test_resolving_cors_with_an_override_merges_the_override(
    manager: SecurityHeadersManager,
) -> None:
    override = OverrideRecord(
        set_at=0.0, keys={"cors_origins": ["https://b.example"], "cors_max_age": 7}
    )

    result = manager._resolve_cors_state(_cors_config(), override)

    assert result is not None
    assert result["origins"] == ["https://b.example"]
    assert result["max_age"] == 7
    assert result["allow_methods"] == ["PUT"]


def test_configure_applies_every_part_and_clears_the_cache(
    manager: SecurityHeadersManager,
) -> None:
    manager.headers_cache["k"] = {"X": "y"}
    manager.enabled = False

    manager.configure(
        hsts_max_age=60,
        csp={"default-src": ["'self'"]},
        custom_headers={"X-A": "1"},
        cors_origins=["https://a.example"],
        frame_options="DENY",
    )

    assert manager.enabled is True
    assert len(manager.headers_cache) == 0
    assert manager.hsts_config == {
        "max_age": 60,
        "include_subdomains": True,
        "preload": False,
    }
    assert manager.csp_config == {"default-src": ["'self'"]}
    assert manager.custom_headers == {"X-A": "1"}
    assert manager.default_headers["X-Frame-Options"] == "DENY"
    assert manager.cors_config == {
        "origins": ["https://a.example"],
        "allow_credentials": False,
        "allow_methods": ["GET", "POST"],
        "allow_headers": ["*"],
        "max_age": 3600,
    }


def test_configure_can_switch_the_headers_off() -> None:
    manager = SecurityHeadersManager.isolated()

    manager.configure(enabled=False)

    assert manager.enabled is False


def test_configure_marks_own_state_dirty_only_with_redis_and_a_startup_hash() -> None:
    manager = SecurityHeadersManager.isolated()
    manager._own_state_dirty = False
    manager.redis_handler = object()
    manager._startup_hash = None
    manager.configure()
    assert manager._own_state_dirty is False

    manager._startup_hash = "h"
    manager.redis_handler = None
    manager.configure()
    assert manager._own_state_dirty is False

    manager.redis_handler = object()
    manager.configure()
    assert manager._own_state_dirty is True


def test_a_cors_origin_loses_only_trailing_slashes(
    manager: SecurityHeadersManager,
) -> None:
    result = manager._compute_cors_config(
        ["https://hostX", "https://host/"], False, None, None
    )

    assert result is not None
    assert result["origins"] == ["https://hostX", "https://host"]


def test_hsts_from_a_config_keeps_an_enabled_preload(
    manager: SecurityHeadersManager,
) -> None:
    config = SyncSecurityConfig(
        enable_redis=False,
        security_headers={"hsts": {"max_age": 31536000, "preload": True}},
    )

    _, hsts, _, _ = manager._resolve_headers_state(config, NO_OVERRIDE)

    assert hsts == {"max_age": 31536000, "include_subdomains": True, "preload": True}


def test_an_hsts_override_without_the_other_keys_leaves_their_defaults(
    manager: SecurityHeadersManager,
) -> None:
    config = SyncSecurityConfig(enable_redis=False, security_headers={"enabled": True})
    override = OverrideRecord(set_at=0.0, keys={"hsts": {"max_age": 100}})

    _, hsts, _, _ = manager._resolve_headers_state(config, override)

    assert hsts == {"max_age": 100, "include_subdomains": True, "preload": False}


def test_an_hsts_override_on_headers_that_are_off_gets_subdomains_on_and_no_preload(
    manager: SecurityHeadersManager,
) -> None:
    config = SyncSecurityConfig(enable_redis=False, security_headers=None)
    override = OverrideRecord(set_at=0.0, keys={"hsts": {"max_age": 31536000}})

    _, hsts, _, _ = manager._resolve_headers_state(config, override)

    assert hsts == {"max_age": 31536000, "include_subdomains": True, "preload": False}


def test_the_apps_own_cors_skips_the_override_merge_when_nothing_is_overridden(
    manager: SecurityHeadersManager, monkeypatch: pytest.MonkeyPatch
) -> None:
    merge = Mock(side_effect=AssertionError("the merge must not run"))
    monkeypatch.setattr(manager, "cors_params_for", merge)

    result = manager._resolve_cors_state(_cors_config(), NO_OVERRIDE)

    assert result is not None
    merge.assert_not_called()


def test_cors_goes_through_the_merge_when_the_override_has_keys(
    manager: SecurityHeadersManager, monkeypatch: pytest.MonkeyPatch
) -> None:
    merge = Mock(wraps=manager.cors_params_for)
    monkeypatch.setattr(manager, "cors_params_for", merge)

    manager._resolve_cors_state(
        _cors_config(), OverrideRecord(set_at=0.0, keys={"cors_max_age": 1})
    )

    merge.assert_called_once()


def test_cors_goes_through_the_merge_while_overrides_are_pulled(
    manager: SecurityHeadersManager, monkeypatch: pytest.MonkeyPatch
) -> None:
    merge = Mock(wraps=manager.cors_params_for)
    monkeypatch.setattr(manager, "cors_params_for", merge)
    monkeypatch.setitem(PULLED_OVERRIDES, "other", NO_OVERRIDE)

    manager._resolve_cors_state(_cors_config(), NO_OVERRIDE)

    merge.assert_called_once()


def test_cors_goes_through_the_merge_when_no_override_record_is_given(
    manager: SecurityHeadersManager, monkeypatch: pytest.MonkeyPatch
) -> None:
    merge = Mock(wraps=manager.cors_params_for)
    monkeypatch.setattr(manager, "cors_params_for", merge)

    manager._resolve_cors_state(_cors_config(), None)

    merge.assert_called_once()


def test_configure_records_nothing_for_the_app_unless_asked(
    manager: SecurityHeadersManager, monkeypatch: pytest.MonkeyPatch
) -> None:
    record = Mock()
    monkeypatch.setattr(manager, "_record_override_from_call", record)

    manager.configure(cors_max_age=-1)

    record.assert_not_called()


def test_configure_with_override_apps_records_exactly_what_was_passed(
    manager: SecurityHeadersManager, monkeypatch: pytest.MonkeyPatch
) -> None:
    record = Mock()
    monkeypatch.setattr(manager, "_record_override_from_call", record)

    manager.configure(override_apps=True, frame_options="DENY", hsts_max_age=5)

    record.assert_called_once_with({"frame_options": "DENY", "hsts": {"max_age": 5}})


def test_configure_with_override_apps_validates_the_cors_override(
    manager: SecurityHeadersManager,
) -> None:
    with pytest.raises(
        ValueError, match="^cors_max_age must be a non-negative integer$"
    ):
        manager.configure(override_apps=True, cors_max_age=-1)


def test_configure_leaves_hsts_preload_off_unless_asked(
    manager: SecurityHeadersManager,
) -> None:
    manager.configure(hsts_max_age=31536000)

    assert manager.hsts_config == {
        "max_age": 31536000,
        "include_subdomains": True,
        "preload": False,
    }
