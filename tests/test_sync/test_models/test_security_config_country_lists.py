import inspect
import warnings
from pathlib import Path
from typing import cast

import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.sync.handlers.ipinfo_handler import IPInfoManager


def test_blocked_countries_default_is_empty_frozenset() -> None:
    config = SyncSecurityConfig()
    assert config.blocked_countries == frozenset()
    assert isinstance(config.blocked_countries, frozenset)


def test_whitelist_countries_default_is_empty_frozenset() -> None:
    config = SyncSecurityConfig()
    assert config.whitelist_countries == frozenset()
    assert isinstance(config.whitelist_countries, frozenset)


def test_blocked_countries_accepts_list_input(tmp_path: Path) -> None:
    config = SyncSecurityConfig(
        blocked_countries=["us", "FR"],
        geo_ip_handler=IPInfoManager(
            token="dummy", db_path=tmp_path / "country_asn.mmdb"
        ),
    )
    assert config.blocked_countries == frozenset({"US", "FR"})


def test_blocked_countries_accepts_set_input(tmp_path: Path) -> None:
    config = SyncSecurityConfig(
        blocked_countries={"us", "fr"},
        geo_ip_handler=IPInfoManager(
            token="dummy", db_path=tmp_path / "country_asn.mmdb"
        ),
    )
    assert config.blocked_countries == frozenset({"US", "FR"})


def test_blocked_countries_accepts_tuple_input(tmp_path: Path) -> None:
    config = SyncSecurityConfig(
        blocked_countries=("us", "fr"),
        geo_ip_handler=IPInfoManager(
            token="dummy", db_path=tmp_path / "country_asn.mmdb"
        ),
    )
    assert config.blocked_countries == frozenset({"US", "FR"})


def test_blocked_countries_accepts_frozenset_input(tmp_path: Path) -> None:
    config = SyncSecurityConfig(
        blocked_countries=frozenset({"us", "fr"}),
        geo_ip_handler=IPInfoManager(
            token="dummy", db_path=tmp_path / "country_asn.mmdb"
        ),
    )
    assert config.blocked_countries == frozenset({"US", "FR"})


def test_blocked_countries_invalid_type_raises() -> None:
    with pytest.raises((ValueError, TypeError)):
        SyncSecurityConfig(blocked_countries={"key": "value"})


def test_blocked_countries_none_coerces_to_empty_frozenset() -> None:
    config = SyncSecurityConfig(blocked_countries=None)
    assert config.blocked_countries == frozenset()
    assert isinstance(config.blocked_countries, frozenset)


def test_whitelist_countries_none_coerces_to_empty_frozenset() -> None:
    config = SyncSecurityConfig(whitelist_countries=None)
    assert config.whitelist_countries == frozenset()
    assert isinstance(config.whitelist_countries, frozenset)


def test_whitelist_countries_normalizes_case(tmp_path: Path) -> None:
    config = SyncSecurityConfig(
        whitelist_countries=["us", "Gb", "DE"],
        geo_ip_handler=IPInfoManager(
            token="dummy", db_path=tmp_path / "country_asn.mmdb"
        ),
    )
    assert config.whitelist_countries == frozenset({"US", "GB", "DE"})


def test_both_country_lists_emits_shadow_warning(tmp_path: Path) -> None:
    with pytest.warns(UserWarning, match="blocked_countries is ignored"):
        SyncSecurityConfig(
            whitelist_countries=["US", "CA"],
            blocked_countries=["CN", "RU"],
            geo_ip_handler=IPInfoManager(
                token="dummy", db_path=tmp_path / "country_asn.mmdb"
            ),
        )


def test_whitelist_alone_emits_no_shadow_warning(tmp_path: Path) -> None:
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        SyncSecurityConfig(
            whitelist_countries=["US", "CA"],
            geo_ip_handler=IPInfoManager(
                token="dummy", db_path=tmp_path / "country_asn.mmdb"
            ),
        )
    assert not any("blocked_countries is ignored" in str(w.message) for w in caught)


def test_blocked_alone_emits_no_shadow_warning(tmp_path: Path) -> None:
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        SyncSecurityConfig(
            blocked_countries=["CN", "RU"],
            geo_ip_handler=IPInfoManager(
                token="dummy", db_path=tmp_path / "country_asn.mmdb"
            ),
        )
    assert not any("blocked_countries is ignored" in str(w.message) for w in caught)


def _current_lineno() -> int:
    frame = inspect.currentframe()
    assert frame is not None
    caller = frame.f_back
    assert caller is not None
    return caller.f_lineno


def test_shadow_warning_points_at_constructor_call_site(tmp_path: Path) -> None:
    geo_ip_handler = IPInfoManager(token="dummy", db_path=tmp_path / "asn.mmdb")

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        line_before = _current_lineno()
        SyncSecurityConfig(
            whitelist_countries=["US", "CA"],
            blocked_countries=["CN", "RU"],
            geo_ip_handler=geo_ip_handler,
        )
        line_after = _current_lineno()

    matches = [w for w in caught if "blocked_countries is ignored" in str(w.message)]
    assert len(matches) == 1
    assert Path(matches[0].filename).name == Path(__file__).name
    assert line_before < matches[0].lineno <= line_after


def test_shadow_warning_on_runtime_assignment_points_at_assignment_site(
    tmp_path: Path,
) -> None:
    geo_ip_handler = IPInfoManager(token="dummy", db_path=tmp_path / "asn2.mmdb")
    config = SyncSecurityConfig(
        whitelist_countries=["CA"],
        geo_ip_handler=geo_ip_handler,
    )

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        expected_lineno = _current_lineno() + 1
        config.blocked_countries = frozenset({"CN"})

    matches = [w for w in caught if "blocked_countries is ignored" in str(w.message)]
    assert len(matches) == 1
    assert Path(matches[0].filename).name == Path(__file__).name
    assert matches[0].lineno == expected_lineno


def test_reassigning_identical_blocked_countries_value_does_not_rewarn(
    tmp_path: Path,
) -> None:
    geo_ip_handler = IPInfoManager(token="dummy", db_path=tmp_path / "asn3.mmdb")

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        config = SyncSecurityConfig(
            whitelist_countries=["US"],
            blocked_countries=["CN"],
            geo_ip_handler=geo_ip_handler,
        )
        for _ in range(5):
            config.blocked_countries = frozenset({"CN"})

    matches = [w for w in caught if "blocked_countries is ignored" in str(w.message)]
    assert len(matches) == 1


@pytest.mark.parametrize(
    "reassigned_value",
    [["CN"], ("CN",), {"CN"}, frozenset({"CN"})],
    ids=["list", "tuple", "set", "frozenset"],
)
def test_reassigning_identical_blocked_countries_as_list_tuple_set_does_not_rewarn(
    tmp_path: Path,
    reassigned_value: list[str] | tuple[str, ...] | set[str] | frozenset[str],
) -> None:
    geo_ip_handler = IPInfoManager(token="dummy", db_path=tmp_path / "asn8.mmdb")

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        config = SyncSecurityConfig(
            whitelist_countries=["US"],
            blocked_countries=["CN"],
            geo_ip_handler=geo_ip_handler,
        )
        config.blocked_countries = cast(frozenset[str], reassigned_value)

    matches = [w for w in caught if "blocked_countries is ignored" in str(w.message)]
    assert len(matches) == 1


def test_reassigning_changed_blocked_countries_value_still_warns(
    tmp_path: Path,
) -> None:
    geo_ip_handler = IPInfoManager(token="dummy", db_path=tmp_path / "asn4.mmdb")

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        config = SyncSecurityConfig(
            whitelist_countries=["US"],
            blocked_countries=["CN"],
            geo_ip_handler=geo_ip_handler,
        )
        config.blocked_countries = frozenset({"RU"})

    matches = [w for w in caught if "blocked_countries is ignored" in str(w.message)]
    assert len(matches) == 2


def test_raising_bool_on_shadow_check_does_not_mutate_field_or_revision(
    tmp_path: Path,
) -> None:
    class _BoomBool:
        def __bool__(self) -> bool:
            raise RuntimeError("boom")

    geo_ip_handler = IPInfoManager(token="dummy", db_path=tmp_path / "asn5.mmdb")
    config = SyncSecurityConfig(
        whitelist_countries=["US"],
        geo_ip_handler=geo_ip_handler,
    )
    original_blocked = config.blocked_countries
    original_revision = config.revision

    with pytest.raises(RuntimeError, match="boom"):
        config.blocked_countries = cast(frozenset[str], _BoomBool())

    assert config.blocked_countries == original_blocked
    assert config.revision == original_revision


def test_raising_bool_on_blocked_countries_without_geo_handler_propagates() -> None:
    class _BoomBool:
        def __bool__(self) -> bool:
            raise RuntimeError("boom")

    config = SyncSecurityConfig()
    boom = _BoomBool()
    revision_before = config.revision

    with pytest.raises(RuntimeError, match="boom"):
        config.blocked_countries = cast(frozenset[str], boom)

    assert config.blocked_countries == frozenset()
    assert config.revision == revision_before


def test_whitelist_countries_reassignment_rejects_non_collection_value(
    tmp_path: Path,
) -> None:
    geo_ip_handler = IPInfoManager(token="dummy", db_path=tmp_path / "asn7.mmdb")
    config = SyncSecurityConfig(blocked_countries=["CN"], geo_ip_handler=geo_ip_handler)
    non_collection = object()

    with pytest.raises(ValueError, match="Country list must be"):
        config.whitelist_countries = cast(frozenset[str], non_collection)

    assert config.whitelist_countries == frozenset()


def test_blocked_countries_reassignment_rejects_invalid_type(tmp_path: Path) -> None:
    geo_ip_handler = IPInfoManager(
        token="dummy", db_path=tmp_path / "asn_invalid1.mmdb"
    )
    config = SyncSecurityConfig(geo_ip_handler=geo_ip_handler)

    with pytest.raises(ValueError, match="Country list must be"):
        config.blocked_countries = cast(frozenset[str], {"key": "value"})

    assert config.blocked_countries == frozenset()


def test_whitelist_countries_reassignment_rejects_invalid_type(tmp_path: Path) -> None:
    geo_ip_handler = IPInfoManager(
        token="dummy", db_path=tmp_path / "asn_invalid2.mmdb"
    )
    config = SyncSecurityConfig(geo_ip_handler=geo_ip_handler)

    with pytest.raises(ValueError, match="Country list must be"):
        config.whitelist_countries = cast(frozenset[str], {"key": "value"})

    assert config.whitelist_countries == frozenset()


def test_blocked_countries_reassignment_accepts_valid_list(tmp_path: Path) -> None:
    geo_ip_handler = IPInfoManager(token="dummy", db_path=tmp_path / "asn_valid1.mmdb")
    config = SyncSecurityConfig(geo_ip_handler=geo_ip_handler)

    config.blocked_countries = cast(frozenset[str], ["fr", "de"])

    assert config.blocked_countries == frozenset({"FR", "DE"})


def test_whitelist_countries_reassignment_accepts_valid_list(tmp_path: Path) -> None:
    geo_ip_handler = IPInfoManager(token="dummy", db_path=tmp_path / "asn_valid2.mmdb")
    config = SyncSecurityConfig(geo_ip_handler=geo_ip_handler)

    config.whitelist_countries = cast(frozenset[str], ["fr", "de"])

    assert config.whitelist_countries == frozenset({"FR", "DE"})


def test_model_copy_update_touching_blocked_countries_warns_on_shadow(
    tmp_path: Path,
) -> None:
    geo_ip_handler = IPInfoManager(token="dummy", db_path=tmp_path / "asn6.mmdb")
    base = SyncSecurityConfig(whitelist_countries=["US"], geo_ip_handler=geo_ip_handler)

    with pytest.warns(UserWarning, match="blocked_countries is ignored"):
        shadowed = base.model_copy(update={"blocked_countries": frozenset({"CN"})})

    assert shadowed.whitelist_countries and shadowed.blocked_countries


def test_model_copy_update_touching_whitelist_countries_warns_on_shadow(
    tmp_path: Path,
) -> None:
    geo_ip_handler = IPInfoManager(token="dummy", db_path=tmp_path / "asn9.mmdb")
    base = SyncSecurityConfig(blocked_countries=["CN"], geo_ip_handler=geo_ip_handler)

    with pytest.warns(UserWarning, match="blocked_countries is ignored"):
        shadowed = base.model_copy(update={"whitelist_countries": frozenset({"US"})})

    assert shadowed.whitelist_countries and shadowed.blocked_countries


def test_model_copy_update_touching_country_field_without_shadow_emits_no_warning(
    tmp_path: Path,
) -> None:
    base = SyncSecurityConfig()
    geo_ip_handler = IPInfoManager(token="dummy", db_path=tmp_path / "asn13.mmdb")

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        shadowed = base.model_copy(
            update={
                "blocked_countries": frozenset({"CN"}),
                "geo_ip_handler": geo_ip_handler,
            }
        )

    matches = [w for w in caught if "blocked_countries is ignored" in str(w.message)]
    assert matches == []
    assert shadowed.blocked_countries and not shadowed.whitelist_countries


def test_model_copy_update_without_country_fields_skips_shadow_check(
    tmp_path: Path,
) -> None:
    geo_ip_handler = IPInfoManager(token="dummy", db_path=tmp_path / "asn11.mmdb")
    with pytest.warns(UserWarning, match="blocked_countries is ignored"):
        base = SyncSecurityConfig(
            whitelist_countries=["US"],
            blocked_countries=["CN"],
            geo_ip_handler=geo_ip_handler,
        )

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        copied = base.model_copy(update={"rate_limit": 999})

    matches = [w for w in caught if "blocked_countries is ignored" in str(w.message)]
    assert matches == []
    assert copied.rate_limit == 999


def test_model_copy_update_country_shadow_warning_points_at_call_site(
    tmp_path: Path,
) -> None:
    geo_ip_handler = IPInfoManager(token="dummy", db_path=tmp_path / "asn12.mmdb")
    base = SyncSecurityConfig(whitelist_countries=["US"], geo_ip_handler=geo_ip_handler)

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        expected_lineno = _current_lineno() + 1
        base.model_copy(update={"blocked_countries": frozenset({"CN"})})

    matches = [w for w in caught if "blocked_countries is ignored" in str(w.message)]
    assert len(matches) == 1
    assert Path(matches[0].filename).name == Path(__file__).name
    assert matches[0].lineno == expected_lineno
