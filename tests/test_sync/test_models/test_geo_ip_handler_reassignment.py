from pathlib import Path
from typing import cast

import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.sync.handlers.ipinfo_handler import IPInfoManager


def test_blocked_countries_assignment_without_geo_handler_raises() -> None:
    config = SyncSecurityConfig()

    with pytest.raises(ValueError, match="geo_ip_handler is required"):
        config.blocked_countries = cast(frozenset[str], ["US"])

    assert config.blocked_countries == frozenset()
    assert config.geo_ip_handler is None


def test_whitelist_countries_assignment_without_geo_handler_raises() -> None:
    config = SyncSecurityConfig()

    with pytest.raises(ValueError, match="geo_ip_handler is required"):
        config.whitelist_countries = cast(frozenset[str], ["US"])

    assert config.whitelist_countries == frozenset()
    assert config.geo_ip_handler is None


def test_blocked_countries_assignment_with_geo_handler_already_set_succeeds(
    tmp_path: Path,
) -> None:
    handler = IPInfoManager(token="dummy", db_path=tmp_path / "asn20.mmdb")
    config = SyncSecurityConfig(geo_ip_handler=handler)

    config.blocked_countries = cast(frozenset[str], ["US"])

    assert config.blocked_countries == frozenset({"US"})
    assert config.geo_ip_handler is handler


def test_blocked_countries_assignment_with_ipinfo_token_auto_constructs_handler() -> (
    None
):
    config = SyncSecurityConfig(ipinfo_token="tok")
    assert config.geo_ip_handler is None

    config.blocked_countries = cast(frozenset[str], ["US"])

    assert type(config.geo_ip_handler).__name__ == "IPInfoManager"
    assert config.blocked_countries == frozenset({"US"})


def test_geo_ip_handler_assignment_to_none_with_active_rules_and_no_token_raises(
    tmp_path: Path,
) -> None:
    handler = IPInfoManager(token="dummy", db_path=tmp_path / "asn21.mmdb")
    config = SyncSecurityConfig(geo_ip_handler=handler, blocked_countries=["US"])

    with pytest.raises(ValueError, match="geo_ip_handler is required"):
        config.geo_ip_handler = None

    assert config.geo_ip_handler is handler


def test_model_copy_update_blocked_countries_without_geo_handler_raises() -> None:
    base = SyncSecurityConfig()

    with pytest.raises(ValueError, match="geo_ip_handler is required"):
        base.model_copy(update={"blocked_countries": ["US"]})

    assert base.blocked_countries == frozenset()


def test_model_copy_update_blocked_countries_with_geo_handler_in_same_update_succeeds(
    tmp_path: Path,
) -> None:
    base = SyncSecurityConfig()
    handler = IPInfoManager(token="dummy", db_path=tmp_path / "asn22.mmdb")

    copied = base.model_copy(
        update={"blocked_countries": ["US"], "geo_ip_handler": handler}
    )

    assert copied.blocked_countries == frozenset({"US"})
    assert copied.geo_ip_handler is handler


def test_model_copy_update_blocked_countries_with_token_auto_constructs_handler() -> (
    None
):
    base = SyncSecurityConfig(ipinfo_token="tok")
    assert base.geo_ip_handler is None

    copied = base.model_copy(update={"blocked_countries": ["US"]})

    assert type(copied.geo_ip_handler).__name__ == "IPInfoManager"
    assert copied.blocked_countries == frozenset({"US"})
    assert base.geo_ip_handler is None


def test_model_copy_update_without_geo_state_fields_skips_geo_check() -> None:
    base = SyncSecurityConfig()

    copied = base.model_copy(update={"rate_limit": 42})

    assert copied.rate_limit == 42
    assert copied.geo_ip_handler is None


def test_blocked_countries_assignment_rejection_leaves_revision_unchanged() -> None:
    config = SyncSecurityConfig()
    revision_before = config.revision

    with pytest.raises(ValueError, match="geo_ip_handler is required"):
        config.blocked_countries = cast(frozenset[str], ["US"])

    assert config.revision == revision_before
